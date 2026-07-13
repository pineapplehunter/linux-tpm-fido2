use std::{
    env,
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

use crate::{approval, session, store, tpm};
use ciborium::value::Value;
use sha2::{Digest, Sha256};

pub const CMD_AUTHENTICATOR_MAKE_CREDENTIAL: u8 = 0x01;
pub const CMD_AUTHENTICATOR_GET_ASSERTION: u8 = 0x02;
pub const CMD_AUTHENTICATOR_GET_NEXT_ASSERTION: u8 = 0x08;
pub const CMD_AUTHENTICATOR_GET_INFO: u8 = 0x04;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum ErrorStatus {
    InvalidCommand = 0x01,
    InvalidCbor = 0x12,
    MissingParameter = 0x14,
    CredentialExcluded = 0x19,
    UnsupportedAlgorithm = 0x26,
    OperationDenied = 0x27,
    UnsupportedOption = 0x2b,
    NoCredentials = 0x2e,
}

impl From<ErrorStatus> for u8 {
    fn from(status: ErrorStatus) -> Self {
        status as u8
    }
}

const COSE_ALG_ES256: i64 = -7;
const ASSERTION_APPROVAL_GRACE: Duration = Duration::from_secs(10);
pub const AAGUID: [u8; 16] = [
    0x6c, 0x74, 0x70, 0x6d, 0xf1, 0xd0, 0x42, 0x00, 0x80, 0x01, 0x54, 0x50, 0x4d, 0x46, 0x49, 0x44,
];

pub struct Authenticator {
    store_dir: PathBuf,
    tpm_path: Option<PathBuf>,
    tpm: Option<tpm::Tpm>,
    session: session::SessionContext,
    credentials: Vec<Credential>,
    recent_assertion_approval: Option<RecentAssertionApproval>,
    pending_assertion: Option<PendingAssertion>,
}

struct RecentAssertionApproval {
    rp_id: String,
    expires_at: Instant,
}

struct PendingAssertion {
    rp_id: String,
    client_data_hash: Vec<u8>,
    credential_indexes: Vec<usize>,
    total_credentials: usize,
}

struct Credential {
    id: Vec<u8>,
    rp_id: String,
    user_id: Option<u32>,
    user_handle: Vec<u8>,
    user_name: Option<String>,
    user_display_name: Option<String>,
    key: tpm::TpmCredential,
    policy: Option<store::StoredPcrPolicy>,
    recovery: Option<store::StoredRecoverySlot>,
    sign_count: u32,
}

impl Authenticator {
    pub fn new(store_dir: PathBuf, tpm_path: Option<PathBuf>) -> Self {
        let session = session::SessionContext::detect();
        let tpm = None;
        let credentials = match store::load_ctap2_credentials_from_dir(&store_dir, session.uid) {
            Ok(credentials) => credentials
                .into_iter()
                .map(|credential| Credential {
                    id: credential.id,
                    rp_id: credential.rp_id,
                    user_id: credential.user_id,
                    user_handle: credential.user_handle,
                    user_name: credential.user_name,
                    user_display_name: credential.user_display_name,
                    key: tpm::TpmCredential {
                        private: credential.key.private,
                        public: credential.key.public,
                        public_key_x: credential.key.public_key_x,
                        public_key_y: credential.key.public_key_y,
                    },
                    policy: credential.policy,
                    recovery: credential.recovery,
                    sign_count: credential.sign_count,
                })
                .collect(),
            Err(error) => {
                log::warn!("failed to load CTAP2 credential store: {error:?}");
                Vec::new()
            }
        };
        log::info!("loaded {} TPM-backed CTAP2 credentials", credentials.len());

        Self {
            store_dir,
            tpm_path,
            tpm,
            session,
            credentials,
            recent_assertion_approval: None,
            pending_assertion: None,
        }
    }

    pub fn handle_cbor(&mut self, payload: &[u8]) -> Vec<u8> {
        let Some((&command, body)) = payload.split_first() else {
            return error_response(ErrorStatus::InvalidCommand);
        };

        log::info!("ctap2 command: {}", command_name(command));

        match match command {
            CMD_AUTHENTICATOR_GET_INFO => Ok(get_info_response()),
            CMD_AUTHENTICATOR_MAKE_CREDENTIAL => self.make_credential(body),
            CMD_AUTHENTICATOR_GET_ASSERTION => self.get_assertion(body),
            CMD_AUTHENTICATOR_GET_NEXT_ASSERTION => self.get_next_assertion(body),
            _ => Err(ErrorStatus::InvalidCommand),
        } {
            Ok(response) => response,
            Err(status) => error_response(status),
        }
    }

    fn make_credential(&mut self, body: &[u8]) -> Result<Vec<u8>, ErrorStatus> {
        let request = decode_map(body)?;

        let client_data_hash = map_bytes(&request, 1).ok_or(ErrorStatus::MissingParameter)?;
        validate_client_data_hash(client_data_hash)?;
        let rp = map_map(&request, 2).ok_or(ErrorStatus::MissingParameter)?;
        let user = map_map(&request, 3).ok_or(ErrorStatus::MissingParameter)?;
        let params = map_array(&request, 4).ok_or(ErrorStatus::MissingParameter)?;
        let cred_props_requested = map_map(&request, 6)
            .is_some_and(|extensions| map_bool(extensions, "credProps") == Some(true));
        validate_attestation_conveyance(map_text(&request, 8))?;

        if !params.iter().any(supports_es256) {
            return Err(ErrorStatus::UnsupportedAlgorithm);
        }

        let rp_id = map_text(rp, "id").ok_or(ErrorStatus::MissingParameter)?;
        let rp_name = map_text(rp, "name");
        let user_handle = map_bytes(user, "id").ok_or(ErrorStatus::MissingParameter)?;
        let user_name = map_text(user, "name");
        let user_display_name = map_text(user, "displayName");
        validate_make_credential_options(map_map(&request, 7))?;
        validate_credential_descriptor_list(map_array(&request, 5))?;
        if excluded_credential_exists(&self.credentials, rp_id, map_array(&request, 5)) {
            log::info!("makeCredential excluded existing credential for rp_id={rp_id}");
            return Err(ErrorStatus::CredentialExcluded);
        }

        if !approval::approve(
            &format!(
                "Register a new passkey for {} as {}",
                display_rp_label(rp_name, rp_id),
                user_display_name.or(user_name).unwrap_or("unknown user")
            ),
            &self.session,
            &self.store_dir,
        ) {
            return Err(ErrorStatus::OperationDenied);
        }

        let Some(tpm) = self.ensure_tpm() else {
            log::warn!("cannot create CTAP2 credential without TPM context");
            return Err(ErrorStatus::OperationDenied);
        };
        let policy = match tpm.create_secure_boot_policy() {
            Ok(policy) => policy,
            Err(error) => {
                log::warn!(
                    "failed to create secure-boot PCR policy for CTAP2 credential: {error:?}"
                );
                return Err(ErrorStatus::OperationDenied);
            }
        };
        let key = match tpm.create_credential_key_with_policy(Some(&policy)) {
            Ok(credential) => credential,
            Err(error) => {
                log::warn!("failed to create TPM-backed CTAP2 credential key: {error:?}");
                return Err(ErrorStatus::OperationDenied);
            }
        };
        log::info!("created TPM-backed CTAP2 credential key");
        let recovery = match env::var("LINUX_TPM_FIDO2_RECOVERY_PASSPHRASE") {
            Ok(passphrase) if !passphrase.is_empty() => {
                let label = env::var("LINUX_TPM_FIDO2_RECOVERY_LABEL")
                    .ok()
                    .filter(|label| !label.is_empty());
                match tpm.create_recovery_material(label, &passphrase) {
                    Ok(material) => {
                        log::info!("created TPM recovery material for CTAP2 credential");
                        Some(store::StoredRecoverySlot {
                            label: material.label,
                            passphrase_salt: material.passphrase_salt,
                            passphrase_hash: material.passphrase_hash,
                            key: store::StoredTpmKey {
                                private: material.key.private,
                                public: material.key.public,
                                public_key_x: material.key.public_key_x,
                                public_key_y: material.key.public_key_y,
                            },
                        })
                    }
                    Err(error) => {
                        log::warn!(
                            "failed to create TPM recovery material for CTAP2 credential: {error:?}"
                        );
                        return Err(ErrorStatus::OperationDenied);
                    }
                }
            }
            _ => None,
        };
        let public_key = cose_credential_public_key(&key);
        let mut credential_id = vec![0u8; 32];
        fill_random(&mut credential_id);

        let extensions = cred_props_requested.then_some(cred_props_extension());
        let auth_data = make_auth_data(
            rp_id,
            0x41,
            0,
            Some((&credential_id, &public_key)),
            extensions.as_ref(),
        );
        self.credentials.push(Credential {
            id: credential_id,
            rp_id: rp_id.to_owned(),
            user_id: self.session.uid,
            user_handle: user_handle.to_vec(),
            user_name: user_name.map(str::to_owned),
            user_display_name: user_display_name.map(str::to_owned),
            key,
            policy: Some(store::StoredPcrPolicy {
                selection: policy.selection,
                digest: policy.digest,
            }),
            recovery,
            sign_count: 0,
        });
        self.save_credentials();

        log::info!(
            "created TPM-backed credential rp_id={} total_credentials={}",
            rp_id,
            self.credentials.len()
        );

        Ok(encode_response(Value::Map(vec![
            (Value::Integer(1.into()), Value::Text("none".to_owned())),
            (Value::Integer(2.into()), Value::Bytes(auth_data)),
            (Value::Integer(3.into()), Value::Map(Vec::new())),
        ])))
    }

    fn get_assertion(&mut self, body: &[u8]) -> Result<Vec<u8>, ErrorStatus> {
        let request = decode_map(body)?;

        let rp_id = map_text(&request, 1).ok_or(ErrorStatus::MissingParameter)?;
        let client_data_hash = map_bytes(&request, 2).ok_or(ErrorStatus::MissingParameter)?;
        validate_client_data_hash(client_data_hash)?;
        let allow_list = map_array(&request, 3);
        validate_get_assertion_options(map_map(&request, 5))?;
        validate_credential_descriptor_list(allow_list)?;

        let credential_indexes = matching_credential_indexes(&self.credentials, rp_id, allow_list);
        let Some((&credential_index, remaining_indexes)) = credential_indexes.split_first() else {
            return Err(ErrorStatus::NoCredentials);
        };

        if !self.assertion_approved(rp_id) {
            return Err(ErrorStatus::OperationDenied);
        }

        self.pending_assertion = if remaining_indexes.is_empty() {
            None
        } else {
            Some(PendingAssertion {
                rp_id: rp_id.to_owned(),
                client_data_hash: client_data_hash.to_vec(),
                credential_indexes: remaining_indexes.to_vec(),
                total_credentials: credential_indexes.len(),
            })
        };

        let (auth_data, user, credential_id, key, policy, rp_log, sign_count) = {
            let credential = &self.credentials[credential_index];
            let sign_count = credential.sign_count.saturating_add(1);
            let auth_data = make_auth_data(&credential.rp_id, 0x01, sign_count, None, None);

            let mut user = vec![(
                Value::Text("id".to_owned()),
                Value::Bytes(credential.user_handle.clone()),
            )];
            if let Some(name) = &credential.user_name {
                user.push((Value::Text("name".to_owned()), Value::Text(name.clone())));
            }
            if let Some(display_name) = &credential.user_display_name {
                user.push((
                    Value::Text("displayName".to_owned()),
                    Value::Text(display_name.clone()),
                ));
            }

            (
                auth_data,
                user,
                credential.id.clone(),
                credential.key.clone(),
                credential.policy.clone(),
                credential.rp_id.clone(),
                sign_count,
            )
        };

        let mut signed_data = auth_data.clone();
        signed_data.extend_from_slice(client_data_hash);
        let signature = match sign_credential(self, &key, policy.as_ref(), &signed_data) {
            Ok(signature) => signature,
            Err(error) => {
                log::warn!("failed to sign CTAP2 assertion: {error:?}");
                return Err(ErrorStatus::OperationDenied);
            }
        };

        if let Err(error) =
            store::update_ctap2_sign_count_in_dir(&self.store_dir, &credential_id, sign_count)
        {
            log::warn!(
                "failed to persist CTAP2 assertion sign_count for rp_id={}: {error:?}",
                rp_log
            );
            return Err(ErrorStatus::OperationDenied);
        }

        self.credentials[credential_index].sign_count = sign_count;
        log::info!(
            "asserting credential rp_id={} sign_count={}",
            rp_log,
            sign_count
        );

        Ok(encode_assertion_response(
            credential_id,
            auth_data,
            signature,
            user,
            credential_indexes.len(),
        ))
    }

    fn get_next_assertion(&mut self, body: &[u8]) -> Result<Vec<u8>, ErrorStatus> {
        if !body.is_empty() {
            return Err(ErrorStatus::InvalidCbor);
        }

        let Some(pending) = self.pending_assertion.take() else {
            return Err(ErrorStatus::NoCredentials);
        };

        let Some((&credential_index, remaining_indexes)) = pending.credential_indexes.split_first()
        else {
            return Err(ErrorStatus::NoCredentials);
        };

        self.pending_assertion = if remaining_indexes.is_empty() {
            None
        } else {
            Some(PendingAssertion {
                rp_id: pending.rp_id.clone(),
                client_data_hash: pending.client_data_hash.clone(),
                credential_indexes: remaining_indexes.to_vec(),
                total_credentials: pending.total_credentials,
            })
        };

        let credential = &self.credentials[credential_index];
        let sign_count = credential.sign_count.saturating_add(1);
        let auth_data = make_auth_data(&credential.rp_id, 0x01, sign_count, None, None);
        let credential_id = credential.id.clone();
        let rp_log = credential.rp_id.clone();
        let credential_key = credential.key.clone();
        let credential_policy = credential.policy.clone();
        let user_handle = credential.user_handle.clone();
        let user_name = credential.user_name.clone();
        let user_display_name = credential.user_display_name.clone();
        let mut user = vec![(Value::Text("id".to_owned()), Value::Bytes(user_handle))];
        if let Some(name) = &user_name {
            user.push((Value::Text("name".to_owned()), Value::Text(name.clone())));
        }
        if let Some(display_name) = &user_display_name {
            user.push((
                Value::Text("displayName".to_owned()),
                Value::Text(display_name.clone()),
            ));
        }

        let mut signed_data = auth_data.clone();
        signed_data.extend_from_slice(&pending.client_data_hash);
        let signature = match sign_credential(
            self,
            &credential_key,
            credential_policy.as_ref(),
            &signed_data,
        ) {
            Ok(signature) => signature,
            Err(error) => {
                log::warn!("failed to sign CTAP2 next assertion: {error:?}");
                return Err(ErrorStatus::OperationDenied);
            }
        };

        if let Err(error) =
            store::update_ctap2_sign_count_in_dir(&self.store_dir, &credential_id, sign_count)
        {
            log::warn!(
                "failed to persist CTAP2 next assertion sign_count for rp_id={}: {error:?}",
                rp_log
            );
            return Err(ErrorStatus::OperationDenied);
        }

        self.credentials[credential_index].sign_count = sign_count;

        Ok(encode_assertion_response(
            credential_id,
            auth_data,
            signature,
            user,
            pending.total_credentials,
        ))
    }

    fn save_credentials(&self) {
        let credentials: Vec<_> = self
            .credentials
            .iter()
            .map(|credential| store::StoredCtap2Credential {
                id: credential.id.clone(),
                rp_id: credential.rp_id.clone(),
                user_id: credential.user_id,
                user_handle: credential.user_handle.clone(),
                user_name: credential.user_name.clone(),
                user_display_name: credential.user_display_name.clone(),
                key: store::StoredTpmKey {
                    private: credential.key.private.clone(),
                    public: credential.key.public.clone(),
                    public_key_x: credential.key.public_key_x.clone(),
                    public_key_y: credential.key.public_key_y.clone(),
                },
                policy: credential.policy.clone(),
                recovery: credential.recovery.clone(),
                sign_count: credential.sign_count,
            })
            .collect();

        let path = store::credentials_database_path_in_dir(&self.store_dir);
        if let Err(error) = store::save_ctap2_credentials_to_dir(&self.store_dir, &credentials) {
            log::warn!("failed to save CTAP2 credential store: {error:?}");
        } else {
            log::info!(
                "saved {} TPM-backed CTAP2 credentials to SQLite store {}",
                credentials.len(),
                path.display()
            );
        }
    }

    fn ensure_tpm(&mut self) -> Option<&mut tpm::Tpm> {
        if self.tpm.is_none() {
            let Some(path) = self.tpm_path.clone() else {
                return None;
            };

            for attempt in 0..100 {
                match tpm::Tpm::open(&path) {
                    Ok(tpm) => {
                        self.tpm = Some(tpm);
                        break;
                    }
                    Err(error) if attempt < 99 => {
                        log::debug!(
                            "retrying TPM open for CTAP2 credentials at {}: {error:?}",
                            path.display()
                        );
                        thread::sleep(Duration::from_millis(100));
                    }
                    Err(error) => {
                        log::warn!(
                            "failed to open TPM for CTAP2 credentials at {}: {error:?}",
                            path.display()
                        );
                        return None;
                    }
                }
            }
        }

        self.tpm.as_mut()
    }

    fn assertion_approved(&mut self, rp_id: &str) -> bool {
        let now = Instant::now();
        if self
            .recent_assertion_approval
            .as_ref()
            .is_some_and(|approval| approval.rp_id == rp_id && approval.expires_at > now)
        {
            log::info!("reusing recent assertion approval for rp_id={rp_id}");
            return true;
        }

        if !approval::approve(
            &format!("Authenticate with passkey for {rp_id}"),
            &self.session,
            &self.store_dir,
        ) {
            self.recent_assertion_approval = None;
            return false;
        }

        self.recent_assertion_approval = Some(RecentAssertionApproval {
            rp_id: rp_id.to_owned(),
            expires_at: now + ASSERTION_APPROVAL_GRACE,
        });
        true
    }
}

impl Default for Authenticator {
    fn default() -> Self {
        Self::new(store::dev_store_dir(), None)
    }
}

pub fn command_name(command: u8) -> &'static str {
    match command {
        CMD_AUTHENTICATOR_MAKE_CREDENTIAL => "authenticatorMakeCredential",
        CMD_AUTHENTICATOR_GET_ASSERTION => "authenticatorGetAssertion",
        CMD_AUTHENTICATOR_GET_NEXT_ASSERTION => "authenticatorGetNextAssertion",
        CMD_AUTHENTICATOR_GET_INFO => "authenticatorGetInfo",
        _ => "unknown",
    }
}

fn get_info_response() -> Vec<u8> {
    encode_response(Value::Map(vec![
        (
            Value::Integer(1.into()),
            Value::Array(vec![
                Value::Text("FIDO_2_1".to_owned()),
                Value::Text("FIDO_2_0".to_owned()),
            ]),
        ),
        (
            Value::Integer(2.into()),
            Value::Array(vec![Value::Text("credProps".to_owned())]),
        ),
        (Value::Integer(3.into()), Value::Bytes(AAGUID.to_vec())),
        (
            Value::Integer(4.into()),
            Value::Map(vec![
                (Value::Text("plat".to_owned()), Value::Bool(false)),
                (Value::Text("rk".to_owned()), Value::Bool(true)),
                (Value::Text("up".to_owned()), Value::Bool(true)),
                (Value::Text("uv".to_owned()), Value::Bool(false)),
                (Value::Text("clientPin".to_owned()), Value::Bool(false)),
            ]),
        ),
        (Value::Integer(5.into()), Value::Integer(1200.into())),
        (
            Value::Integer(9.into()),
            Value::Array(vec![Value::Text("usb".to_owned())]),
        ),
        (
            Value::Integer(10.into()),
            Value::Array(vec![Value::Map(vec![
                (
                    Value::Text("type".to_owned()),
                    Value::Text("public-key".to_owned()),
                ),
                (
                    Value::Text("alg".to_owned()),
                    Value::Integer(COSE_ALG_ES256.into()),
                ),
            ])]),
        ),
    ]))
}

fn decode_map(body: &[u8]) -> Result<Vec<(Value, Value)>, ErrorStatus> {
    match ciborium::from_reader::<Value, _>(body) {
        Ok(Value::Map(map)) => Ok(map),
        Ok(_) | Err(_) => Err(ErrorStatus::InvalidCbor),
    }
}

trait MapKey {
    fn matches(&self, value: &Value) -> bool;
}

impl MapKey for i128 {
    fn matches(&self, value: &Value) -> bool {
        value
            .as_integer()
            .and_then(|integer| i128::try_from(integer).ok())
            == Some(*self)
    }
}

impl MapKey for &str {
    fn matches(&self, value: &Value) -> bool {
        value.as_text() == Some(*self)
    }
}

fn map_value<K: MapKey>(map: &[(Value, Value)], key: K) -> Option<&Value> {
    map.iter()
        .find_map(|(candidate, value)| key.matches(candidate).then_some(value))
}

fn map_bytes<K: MapKey>(map: &[(Value, Value)], key: K) -> Option<&[u8]> {
    map_value(map, key)
        .and_then(Value::as_bytes)
        .map(Vec::as_slice)
}

fn map_text<K: MapKey>(map: &[(Value, Value)], key: K) -> Option<&str> {
    map_value(map, key).and_then(Value::as_text)
}

fn map_bool<K: MapKey>(map: &[(Value, Value)], key: K) -> Option<bool> {
    map_value(map, key).and_then(Value::as_bool)
}

fn map_array<K: MapKey>(map: &[(Value, Value)], key: K) -> Option<&[Value]> {
    map_value(map, key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
}

fn map_map<K: MapKey>(map: &[(Value, Value)], key: K) -> Option<&[(Value, Value)]> {
    map_value(map, key)
        .and_then(Value::as_map)
        .map(Vec::as_slice)
}

fn supports_es256(value: &Value) -> bool {
    let Value::Map(map) = value else {
        return false;
    };
    map_text(map, "type") == Some("public-key")
        && map_value(map, "alg")
            .and_then(Value::as_integer)
            .and_then(|integer| i64::try_from(integer).ok())
            == Some(COSE_ALG_ES256)
}

fn validate_make_credential_options(options: Option<&[(Value, Value)]>) -> Result<(), ErrorStatus> {
    validate_common_options(options, true)?;
    // Discoverable credentials are acceptable because credentials are stored locally.
    let _rk = options.and_then(|options| map_bool(options, "rk"));
    validate_resident_key_options(options)?;
    Ok(())
}

fn validate_get_assertion_options(options: Option<&[(Value, Value)]>) -> Result<(), ErrorStatus> {
    validate_common_options(options, false)
}

fn validate_credential_descriptor_list(list: Option<&[Value]>) -> Result<(), ErrorStatus> {
    let Some(list) = list else {
        return Ok(());
    };

    for entry in list {
        let Value::Map(map) = entry else {
            return Err(ErrorStatus::InvalidCbor);
        };
        if map_text(map, "type") != Some("public-key") {
            return Err(ErrorStatus::InvalidCbor);
        }
        if map_bytes(map, "id").is_none() {
            return Err(ErrorStatus::InvalidCbor);
        }
    }

    Ok(())
}

fn validate_common_options(
    options: Option<&[(Value, Value)]>,
    reject_user_presence_false: bool,
) -> Result<(), ErrorStatus> {
    let Some(options) = options else {
        return Ok(());
    };

    if map_bool(options, "uv") == Some(true) {
        log::info!("request requires user verification; continuing with local approval flow");
    }
    if map_bool(options, "up") == Some(false) {
        log::info!("request disables user presence");
        if reject_user_presence_false {
            log::info!("request disables user presence, which is not supported");
            return Err(ErrorStatus::UnsupportedOption);
        }
    }

    Ok(())
}

fn validate_resident_key_options(options: Option<&[(Value, Value)]>) -> Result<(), ErrorStatus> {
    let Some(options) = options else {
        return Ok(());
    };

    if let Some(require_resident_key) = map_bool(options, "requireResidentKey") {
        log::info!("request sets requireResidentKey={require_resident_key}");
    }

    if let Some(resident_key) = map_text(options, "residentKey") {
        match resident_key {
            "discouraged" | "preferred" | "required" => {
                log::info!("request sets residentKey={resident_key}");
            }
            _ => return Err(ErrorStatus::InvalidCbor),
        }
    }

    Ok(())
}

fn validate_attestation_conveyance(attestation: Option<&str>) -> Result<(), ErrorStatus> {
    let Some(attestation) = attestation else {
        return Ok(());
    };

    match attestation {
        "none" | "indirect" | "direct" | "enterprise" => {
            log::info!("request sets attestation={attestation}");
            Ok(())
        }
        _ => Err(ErrorStatus::InvalidCbor),
    }
}

fn excluded_credential_exists(
    credentials: &[Credential],
    rp_id: &str,
    exclude_list: Option<&[Value]>,
) -> bool {
    let Some(exclude_list) = exclude_list else {
        return false;
    };

    credentials.iter().any(|credential| {
        credential.rp_id == rp_id
            && credential_descriptor_list_contains(exclude_list, &credential.id)
    })
}

fn allow_list_allows(allow_list: Option<&[Value]>, credential_id: &[u8]) -> bool {
    let Some(allow_list) = allow_list else {
        return true;
    };

    if allow_list.is_empty() {
        return true;
    }

    credential_descriptor_list_contains(allow_list, credential_id)
}

fn validate_client_data_hash(client_data_hash: &[u8]) -> Result<(), ErrorStatus> {
    if client_data_hash.len() != 32 {
        log::info!(
            "request provided invalid clientDataHash length {}; expected 32 bytes",
            client_data_hash.len()
        );
        return Err(ErrorStatus::InvalidCbor);
    }

    Ok(())
}

fn matching_credential_indexes(
    credentials: &[Credential],
    rp_id: &str,
    allow_list: Option<&[Value]>,
) -> Vec<usize> {
    credentials
        .iter()
        .enumerate()
        .filter_map(|(index, credential)| {
            (credential.rp_id == rp_id && allow_list_allows(allow_list, &credential.id))
                .then_some(index)
        })
        .collect()
}

fn credential_descriptor_list_contains(list: &[Value], credential_id: &[u8]) -> bool {
    list.iter().any(|entry| {
        let Value::Map(map) = entry else {
            return false;
        };
        map_text(map, "type") == Some("public-key") && map_bytes(map, "id") == Some(credential_id)
    })
}

fn make_auth_data(
    rp_id: &str,
    flags: u8,
    sign_count: u32,
    attested_credential_data: Option<(&[u8], &Value)>,
    extensions: Option<&Value>,
) -> Vec<u8> {
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
    auth_data.push(flags | if extensions.is_some() { 0x80 } else { 0x00 });
    auth_data.extend_from_slice(&sign_count.to_be_bytes());

    if let Some((credential_id, public_key)) = attested_credential_data {
        auth_data.extend_from_slice(&AAGUID);
        auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(credential_id);
        ciborium::into_writer(public_key, &mut auth_data).expect("serializing static COSE key");
    }

    if let Some(extensions) = extensions {
        ciborium::into_writer(extensions, &mut auth_data).expect("serializing CTAP2 extensions");
    }

    auth_data
}

fn cred_props_extension() -> Value {
    Value::Map(vec![(
        Value::Text("credProps".to_owned()),
        Value::Map(vec![(Value::Text("rk".to_owned()), Value::Bool(true))]),
    )])
}

fn display_rp_label(rp_name: Option<&str>, rp_id: &str) -> String {
    match rp_name {
        Some(name) if name != rp_id => format!("{name} ({rp_id})"),
        _ => rp_id.to_owned(),
    }
}

fn encode_assertion_response(
    credential_id: Vec<u8>,
    auth_data: Vec<u8>,
    signature: Vec<u8>,
    user: Vec<(Value, Value)>,
    total_credentials: usize,
) -> Vec<u8> {
    let mut response = vec![
        (
            Value::Integer(1.into()),
            Value::Map(vec![
                (
                    Value::Text("type".to_owned()),
                    Value::Text("public-key".to_owned()),
                ),
                (Value::Text("id".to_owned()), Value::Bytes(credential_id)),
            ]),
        ),
        (Value::Integer(2.into()), Value::Bytes(auth_data)),
        (Value::Integer(3.into()), Value::Bytes(signature)),
        (Value::Integer(4.into()), Value::Map(user)),
    ];

    if total_credentials > 1 {
        response.push((
            Value::Integer(5.into()),
            Value::Integer((total_credentials as u64).into()),
        ));
    }

    encode_response(Value::Map(response))
}

fn cose_credential_public_key(key: &tpm::TpmCredential) -> Value {
    cose_public_key_coordinates(key.public_key_x.clone(), key.public_key_y.clone())
}

fn cose_public_key_coordinates(x: Vec<u8>, y: Vec<u8>) -> Value {
    Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(2.into())),
        (
            Value::Integer(3.into()),
            Value::Integer(COSE_ALG_ES256.into()),
        ),
        (Value::Integer((-1).into()), Value::Integer(1.into())),
        (Value::Integer((-2).into()), Value::Bytes(x)),
        (Value::Integer((-3).into()), Value::Bytes(y)),
    ])
}

fn sign_credential(
    authenticator: &mut Authenticator,
    key: &tpm::TpmCredential,
    policy: Option<&store::StoredPcrPolicy>,
    signed_data: &[u8],
) -> color_eyre::Result<Vec<u8>> {
    let Some(tpm) = authenticator.ensure_tpm() else {
        #[cfg(test)]
        {
            return Ok(vec![0x5a; 64]);
        }
        #[cfg(not(test))]
        {
            return Err(color_eyre::eyre::eyre!(
                "TPM credential requires TPM context"
            ));
        }
    };
    let digest = Sha256::digest(signed_data);
    let policy_binding = policy.map(|policy| tpm::PcrPolicyBinding {
        selection: policy.selection.clone(),
        digest: policy.digest.clone(),
    });
    tpm.sign_digest_with_policy(key, policy_binding.as_ref(), &digest)
}

fn fill_random(bytes: &mut [u8]) {
    getrandom::fill(bytes).expect("kernel random source available");
}

fn encode_response(response: Value) -> Vec<u8> {
    let mut payload = vec![0x00];
    let response = canonicalize_value(response);
    ciborium::into_writer(&response, &mut payload).expect("serializing CTAP2 response");
    payload
}

fn canonicalize_value(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_value).collect()),
        Value::Map(entries) => {
            let mut entries: Vec<_> = entries
                .into_iter()
                .map(|(key, value)| (key, canonicalize_value(value)))
                .collect();
            entries.sort_by(|(left_key, _), (right_key, _)| {
                canonical_key_bytes(left_key).cmp(&canonical_key_bytes(right_key))
            });
            Value::Map(entries)
        }
        other => other,
    }
}

fn canonical_key_bytes(value: &Value) -> Vec<u8> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded).expect("serializing CTAP2 map key");
    encoded
}

fn error_response(status: ErrorStatus) -> Vec<u8> {
    vec![status.into()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_info_starts_with_success() {
        let response = Authenticator::default().handle_cbor(&[CMD_AUTHENTICATOR_GET_INFO]);
        assert_eq!(response[0], 0x00);
        assert!(response.len() > 1);
    }

    #[test]
    fn get_info_uses_project_aaguid_and_algorithm_metadata() {
        let response = Authenticator::default().handle_cbor(&[CMD_AUTHENTICATOR_GET_INFO]);
        let Value::Map(map) = ciborium::from_reader::<Value, _>(&response[1..]).expect("CBOR")
        else {
            panic!("expected getInfo map");
        };

        assert_eq!(map_bytes(&map, 3), Some(AAGUID.as_slice()));
        assert!(
            map_value(&map, 9).is_some(),
            "transports key should be present"
        );
        assert!(
            map_value(&map, 10).is_some(),
            "algorithms key should be present"
        );
        assert!(
            map_value(&map, 6).is_none(),
            "pinUvAuthProtocols should not contain algorithms"
        );
        assert_eq!(
            map_value(&map, 2),
            Some(&Value::Array(vec![Value::Text("credProps".to_owned())]))
        );
    }

    #[test]
    fn make_auth_data_sets_extension_flag_when_extensions_are_present() {
        let auth_data = make_auth_data(
            "example.com",
            0x41,
            0,
            Some((
                &[1, 2, 3, 4],
                &cose_public_key_coordinates(vec![5; 32], vec![6; 32]),
            )),
            Some(&cred_props_extension()),
        );

        assert_ne!(auth_data[32] & 0x80, 0);
    }

    #[test]
    fn unknown_command_is_rejected() {
        assert_eq!(
            Authenticator::default().handle_cbor(&[0xff]),
            error_response(ErrorStatus::InvalidCommand)
        );
    }

    #[test]
    fn exclude_list_detects_existing_credential_for_same_rp() {
        let authenticator = authenticator_with_credential("example.com", vec![1, 2, 3, 4]);
        let exclude_list = vec![credential_descriptor(vec![1, 2, 3, 4])];

        assert!(excluded_credential_exists(
            &authenticator.credentials,
            "example.com",
            Some(&exclude_list)
        ));
    }

    #[test]
    fn exclude_list_ignores_matching_id_for_different_rp() {
        let authenticator = authenticator_with_credential("other.example", vec![1, 2, 3, 4]);
        let exclude_list = vec![credential_descriptor(vec![1, 2, 3, 4])];

        assert!(!excluded_credential_exists(
            &authenticator.credentials,
            "example.com",
            Some(&exclude_list)
        ));
    }

    #[test]
    fn allow_list_absent_allows_any_credential() {
        assert!(allow_list_allows(None, &[1, 2, 3, 4]));
    }

    #[test]
    fn allow_list_absent_or_empty_allows_any_credential() {
        assert!(allow_list_allows(Some(&[]), &[1, 2, 3, 4]));
        assert!(allow_list_allows(None, &[1, 2, 3, 4]));
    }

    #[test]
    fn allow_list_non_matching_rejects_credential() {
        assert!(!allow_list_allows(
            Some(&[credential_descriptor(vec![9, 9, 9, 9])]),
            &[1, 2, 3, 4]
        ));
    }

    #[test]
    fn credential_descriptor_requires_public_key_type_and_matching_id() {
        let wrong_type = Value::Map(vec![
            (
                Value::Text("type".to_owned()),
                Value::Text("not-public-key".to_owned()),
            ),
            (Value::Text("id".to_owned()), Value::Bytes(vec![1, 2, 3, 4])),
        ]);
        let malformed = Value::Map(vec![(
            Value::Text("type".to_owned()),
            Value::Text("public-key".to_owned()),
        )]);

        assert!(!credential_descriptor_list_contains(
            &[wrong_type, malformed],
            &[1, 2, 3, 4]
        ));
        assert!(credential_descriptor_list_contains(
            &[credential_descriptor(vec![1, 2, 3, 4])],
            &[1, 2, 3, 4]
        ));
    }

    #[test]
    fn make_credential_options_accept_absent_up_true_and_rk() {
        assert_eq!(validate_make_credential_options(None), Ok(()));
        assert_eq!(
            validate_make_credential_options(Some(&options_map(&[
                ("up", true),
                ("rk", true),
                ("unknown", true),
            ]))),
            Ok(())
        );
        assert_eq!(
            validate_make_credential_options(Some(&options_map(&[("rk", false)]))),
            Ok(())
        );
        assert_eq!(
            validate_make_credential_options(Some(&options_map(&[("requireResidentKey", true)]))),
            Ok(())
        );
        assert_eq!(
            validate_make_credential_options(Some(&options_text_map(&[(
                "residentKey",
                "required"
            )]))),
            Ok(())
        );
        assert_eq!(
            validate_make_credential_options(Some(&options_text_map(&[(
                "residentKey",
                "preferred"
            )]))),
            Ok(())
        );
        assert_eq!(
            validate_make_credential_options(Some(&options_text_map(&[(
                "residentKey",
                "surprise"
            )]))),
            Err(ErrorStatus::InvalidCbor)
        );
    }

    #[test]
    fn attestation_conveyance_accepts_common_browser_values() {
        assert_eq!(validate_attestation_conveyance(None), Ok(()));
        assert_eq!(validate_attestation_conveyance(Some("none")), Ok(()));
        assert_eq!(validate_attestation_conveyance(Some("indirect")), Ok(()));
        assert_eq!(validate_attestation_conveyance(Some("direct")), Ok(()));
        assert_eq!(validate_attestation_conveyance(Some("enterprise")), Ok(()));
        assert_eq!(
            validate_attestation_conveyance(Some("unexpected")),
            Err(ErrorStatus::InvalidCbor)
        );
    }

    #[test]
    fn get_assertion_options_accept_absent_and_up_true() {
        assert_eq!(validate_get_assertion_options(None), Ok(()));
        assert_eq!(
            validate_get_assertion_options(Some(&options_map(&[("up", true)]))),
            Ok(())
        );
        assert_eq!(
            validate_get_assertion_options(Some(&options_map(&[("up", false)]))),
            Ok(())
        );
    }

    #[test]
    fn options_reject_required_user_verification() {
        assert_eq!(
            validate_make_credential_options(Some(&options_map(&[("uv", true)]))),
            Ok(())
        );
        assert_eq!(
            validate_get_assertion_options(Some(&options_map(&[("uv", true)]))),
            Ok(())
        );
    }

    #[test]
    fn options_reject_disabled_user_presence() {
        assert_eq!(
            validate_make_credential_options(Some(&options_map(&[("up", false)]))),
            Err(ErrorStatus::UnsupportedOption)
        );
    }

    #[test]
    fn multiple_matching_credentials_include_number_of_credentials_and_support_next_assertion() {
        let mut authenticator = authenticator_with_credentials(
            "example.com",
            vec![
                test_credential(vec![1], "example.com", 1),
                test_credential(vec![2], "example.com", 2),
            ],
        );

        let response = authenticator.handle_cbor(&ctap_request(
            CMD_AUTHENTICATOR_GET_ASSERTION,
            Value::Map(vec![
                (
                    Value::Integer(1.into()),
                    Value::Text("example.com".to_owned()),
                ),
                (Value::Integer(2.into()), Value::Bytes(vec![0xaa; 32])),
            ]),
        ));

        assert_eq!(response[0], 0x00);
        let Value::Map(map) = ciborium::from_reader::<Value, _>(&response[1..]).expect("CBOR")
        else {
            panic!("expected assertion map");
        };
        assert_eq!(map_value(&map, 5), Some(&Value::Integer(2.into())));

        let next = authenticator.handle_cbor(&[CMD_AUTHENTICATOR_GET_NEXT_ASSERTION]);
        assert_eq!(next[0], 0x00);
        let Value::Map(next_map) = ciborium::from_reader::<Value, _>(&next[1..]).expect("CBOR")
        else {
            panic!("expected next assertion map");
        };
        assert_eq!(map_value(&next_map, 5), Some(&Value::Integer(2.into())));

        let first_id = map_value(&map, 1)
            .and_then(Value::as_map)
            .and_then(|map| map_bytes(map, "id"))
            .expect("first credential id");
        let next_id = map_value(&next_map, 1)
            .and_then(Value::as_map)
            .and_then(|map| map_bytes(map, "id"))
            .expect("next credential id");
        assert_ne!(first_id, next_id);
    }

    #[test]
    fn malformed_allow_list_and_exclude_list_are_rejected() {
        let mut authenticator = Authenticator::default();

        let make_credential = ctap_request(
            CMD_AUTHENTICATOR_MAKE_CREDENTIAL,
            Value::Map(vec![
                (Value::Integer(1.into()), Value::Bytes(vec![0xaa; 32])),
                (
                    Value::Integer(2.into()),
                    Value::Map(vec![(
                        Value::Text("id".to_owned()),
                        Value::Text("example.com".to_owned()),
                    )]),
                ),
                (
                    Value::Integer(3.into()),
                    Value::Map(vec![(Value::Text("id".to_owned()), Value::Bytes(vec![1]))]),
                ),
                (
                    Value::Integer(4.into()),
                    Value::Array(vec![Value::Map(vec![
                        (
                            Value::Text("type".to_owned()),
                            Value::Text("public-key".to_owned()),
                        ),
                        (Value::Text("alg".to_owned()), Value::Integer((-7).into())),
                    ])]),
                ),
                (
                    Value::Integer(5.into()),
                    Value::Array(vec![Value::Text("not-a-descriptor".to_owned())]),
                ),
                (
                    Value::Integer(7.into()),
                    Value::Map(vec![(Value::Text("up".to_owned()), Value::Bool(true))]),
                ),
            ]),
        );
        assert_eq!(authenticator.handle_cbor(&make_credential)[0], 0x12);

        let get_assertion = ctap_request(
            CMD_AUTHENTICATOR_GET_ASSERTION,
            Value::Map(vec![
                (
                    Value::Integer(1.into()),
                    Value::Text("example.com".to_owned()),
                ),
                (Value::Integer(2.into()), Value::Bytes(vec![0xaa; 32])),
                (
                    Value::Integer(3.into()),
                    Value::Array(vec![Value::Text("bad-entry".to_owned())]),
                ),
            ]),
        );
        assert_eq!(authenticator.handle_cbor(&get_assertion)[0], 0x12);
    }

    #[test]
    fn empty_allow_list_matches_discoverable_credentials() {
        let mut authenticator = authenticator_with_credential("example.com", vec![1, 2, 3, 4]);

        let response = authenticator.handle_cbor(&ctap_request(
            CMD_AUTHENTICATOR_GET_ASSERTION,
            Value::Map(vec![
                (
                    Value::Integer(1.into()),
                    Value::Text("example.com".to_owned()),
                ),
                (Value::Integer(2.into()), Value::Bytes(vec![0xaa; 32])),
                (Value::Integer(3.into()), Value::Array(Vec::new())),
            ]),
        ));

        assert_eq!(response[0], 0x00);
    }

    #[test]
    fn client_data_hash_must_be_32_bytes() {
        let mut authenticator = Authenticator::default();

        let make_credential = ctap_request(
            CMD_AUTHENTICATOR_MAKE_CREDENTIAL,
            Value::Map(vec![
                (Value::Integer(1.into()), Value::Bytes(vec![0xaa; 31])),
                (
                    Value::Integer(2.into()),
                    Value::Map(vec![(
                        Value::Text("id".to_owned()),
                        Value::Text("example.com".to_owned()),
                    )]),
                ),
                (
                    Value::Integer(3.into()),
                    Value::Map(vec![(Value::Text("id".to_owned()), Value::Bytes(vec![1]))]),
                ),
                (
                    Value::Integer(4.into()),
                    Value::Array(vec![Value::Map(vec![
                        (
                            Value::Text("type".to_owned()),
                            Value::Text("public-key".to_owned()),
                        ),
                        (Value::Text("alg".to_owned()), Value::Integer((-7).into())),
                    ])]),
                ),
            ]),
        );
        assert_eq!(authenticator.handle_cbor(&make_credential)[0], 0x12);

        let get_assertion = ctap_request(
            CMD_AUTHENTICATOR_GET_ASSERTION,
            Value::Map(vec![
                (
                    Value::Integer(1.into()),
                    Value::Text("example.com".to_owned()),
                ),
                (Value::Integer(2.into()), Value::Bytes(vec![0xaa; 33])),
            ]),
        );
        assert_eq!(authenticator.handle_cbor(&get_assertion)[0], 0x12);
    }

    #[test]
    fn display_rp_label_prefers_human_readable_name() {
        assert_eq!(
            display_rp_label(Some("Weird Site"), "example.com"),
            "Weird Site (example.com)"
        );
        assert_eq!(
            display_rp_label(Some("example.com"), "example.com"),
            "example.com"
        );
        assert_eq!(display_rp_label(None, "example.com"), "example.com");
    }

    fn authenticator_with_credential(rp_id: &str, credential_id: Vec<u8>) -> Authenticator {
        authenticator_with_credentials(rp_id, vec![test_credential(credential_id, rp_id, 0)])
    }

    fn authenticator_with_credentials(
        rp_id: &str,
        credentials: Vec<StoredCredentialTest>,
    ) -> Authenticator {
        let store_dir = test_store_dir("authenticator");
        let stored_credentials: Vec<_> = credentials
            .iter()
            .map(|credential| store::StoredCtap2Credential {
                id: credential.id.clone(),
                rp_id: rp_id.to_owned(),
                user_id: Some(1000),
                user_handle: credential.user_handle.clone(),
                user_name: credential.user_name.clone(),
                user_display_name: credential.user_display_name.clone(),
                key: store::StoredTpmKey {
                    private: credential.key.private.clone(),
                    public: credential.key.public.clone(),
                    public_key_x: credential.key.public_key_x.clone(),
                    public_key_y: credential.key.public_key_y.clone(),
                },
                policy: None,
                recovery: None,
                sign_count: credential.sign_count,
            })
            .collect();
        store::save_ctap2_credentials_to_dir(&store_dir, &stored_credentials)
            .expect("save test credentials");

        Authenticator {
            store_dir,
            tpm_path: None,
            tpm: None,
            session: session::SessionContext {
                model: session::DaemonSessionModel::ActiveGraphicalSession,
                user: Some("test-user".to_owned()),
                uid: Some(1000),
                session_id: Some("test-session".to_owned()),
                seat: Some("seat0".to_owned()),
                display: Some(":0".to_owned()),
                wayland_display: None,
                dbus_session_bus_address: None,
            },
            credentials: credentials
                .into_iter()
                .map(|credential| Credential {
                    id: credential.id,
                    rp_id: rp_id.to_owned(),
                    user_id: Some(1000),
                    user_handle: credential.user_handle,
                    user_name: credential.user_name,
                    user_display_name: credential.user_display_name,
                    key: credential.key,
                    policy: None,
                    recovery: None,
                    sign_count: credential.sign_count,
                })
                .collect(),
            recent_assertion_approval: Some(RecentAssertionApproval {
                rp_id: rp_id.to_owned(),
                expires_at: Instant::now() + ASSERTION_APPROVAL_GRACE,
            }),
            pending_assertion: None,
        }
    }

    struct StoredCredentialTest {
        id: Vec<u8>,
        user_handle: Vec<u8>,
        user_name: Option<String>,
        user_display_name: Option<String>,
        key: tpm::TpmCredential,
        sign_count: u32,
    }

    fn test_credential(id: Vec<u8>, rp_id: &str, sign_count: u32) -> StoredCredentialTest {
        let user_suffix = id.first().copied().unwrap_or_default();
        StoredCredentialTest {
            id,
            user_handle: vec![5, 6, 7, 8],
            user_name: Some(format!("user-{user_suffix}")),
            user_display_name: Some(format!("Test User {rp_id}")),
            key: tpm::TpmCredential {
                private: vec![9],
                public: vec![10],
                public_key_x: vec![11; 32],
                public_key_y: vec![12; 32],
            },
            sign_count,
        }
    }

    fn ctap_request(command: u8, body: Value) -> Vec<u8> {
        let mut payload = vec![command];
        ciborium::into_writer(&body, &mut payload).expect("serialize CTAP request");
        payload
    }

    fn test_store_dir(name: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time after Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "linux-tpm-fido2-ctap2-test-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn credential_descriptor(id: Vec<u8>) -> Value {
        Value::Map(vec![
            (
                Value::Text("type".to_owned()),
                Value::Text("public-key".to_owned()),
            ),
            (Value::Text("id".to_owned()), Value::Bytes(id)),
        ])
    }

    fn options_map(options: &[(&str, bool)]) -> Vec<(Value, Value)> {
        options
            .iter()
            .map(|(key, value)| (Value::Text((*key).to_owned()), Value::Bool(*value)))
            .collect()
    }

    fn options_text_map(options: &[(&str, &str)]) -> Vec<(Value, Value)> {
        options
            .iter()
            .map(|(key, value)| {
                (
                    Value::Text((*key).to_owned()),
                    Value::Text((*value).to_owned()),
                )
            })
            .collect()
    }
}
