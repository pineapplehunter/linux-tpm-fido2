use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use crate::{approval, store, tpm};
use ciborium::value::Value;
use sha2::{Digest, Sha256};

pub const CMD_AUTHENTICATOR_MAKE_CREDENTIAL: u8 = 0x01;
pub const CMD_AUTHENTICATOR_GET_ASSERTION: u8 = 0x02;
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
    tpm: Option<tpm::Tpm>,
    credentials: Vec<Credential>,
    recent_assertion_approval: Option<RecentAssertionApproval>,
}

struct RecentAssertionApproval {
    rp_id: String,
    expires_at: Instant,
}

struct Credential {
    id: Vec<u8>,
    rp_id: String,
    user_handle: Vec<u8>,
    user_name: Option<String>,
    user_display_name: Option<String>,
    key: tpm::TpmCredential,
    sign_count: u32,
}

impl Authenticator {
    pub fn new(store_dir: PathBuf, tpm_path: Option<PathBuf>) -> Self {
        let tpm = tpm_path.and_then(|path| match tpm::Tpm::open(&path) {
            Ok(tpm) => Some(tpm),
            Err(error) => {
                log::warn!(
                    "failed to open TPM for CTAP2 credentials at {}: {error:?}",
                    path.display()
                );
                None
            }
        });
        let credentials = match store::load_ctap2_credentials_from_dir(&store_dir) {
            Ok(credentials) => credentials
                .into_iter()
                .map(|credential| Credential {
                    id: credential.id,
                    rp_id: credential.rp_id,
                    user_handle: credential.user_handle,
                    user_name: credential.user_name,
                    user_display_name: credential.user_display_name,
                    key: tpm::TpmCredential {
                        private: credential.key.private,
                        public: credential.key.public,
                        public_key_x: credential.key.public_key_x,
                        public_key_y: credential.key.public_key_y,
                    },
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
            tpm,
            credentials,
            recent_assertion_approval: None,
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
            _ => Err(ErrorStatus::InvalidCommand),
        } {
            Ok(response) => response,
            Err(status) => error_response(status),
        }
    }

    fn make_credential(&mut self, body: &[u8]) -> Result<Vec<u8>, ErrorStatus> {
        let request = decode_map(body)?;

        let rp = map_map(&request, 2).ok_or(ErrorStatus::MissingParameter)?;
        let user = map_map(&request, 3).ok_or(ErrorStatus::MissingParameter)?;
        let params = map_array(&request, 4).ok_or(ErrorStatus::MissingParameter)?;

        if map_bytes(&request, 1).is_none() {
            return Err(ErrorStatus::MissingParameter);
        }
        if !params.iter().any(supports_es256) {
            return Err(ErrorStatus::UnsupportedAlgorithm);
        }

        let rp_id = map_text(rp, "id").ok_or(ErrorStatus::MissingParameter)?;
        let user_handle = map_bytes(user, "id").ok_or(ErrorStatus::MissingParameter)?;
        let user_name = map_text(user, "name");
        let user_display_name = map_text(user, "displayName");
        if excluded_credential_exists(&self.credentials, rp_id, map_array(&request, 5)) {
            log::info!("makeCredential excluded existing credential for rp_id={rp_id}");
            return Err(ErrorStatus::CredentialExcluded);
        }

        if !approval::approve(&format!(
            "Register a new passkey for {} as {}",
            rp_id,
            user_display_name.or(user_name).unwrap_or("unknown user")
        )) {
            return Err(ErrorStatus::OperationDenied);
        }

        let Some(tpm) = self.tpm.as_mut() else {
            log::warn!("cannot create CTAP2 credential without TPM context");
            return Err(ErrorStatus::OperationDenied);
        };
        let key = match tpm.create_credential_key() {
            Ok(credential) => credential,
            Err(error) => {
                log::warn!("failed to create TPM-backed CTAP2 credential key: {error:?}");
                return Err(ErrorStatus::OperationDenied);
            }
        };
        log::info!("created TPM-backed CTAP2 credential key");
        let public_key = cose_credential_public_key(&key);
        let mut credential_id = vec![0u8; 32];
        fill_random(&mut credential_id);

        let auth_data = make_auth_data(rp_id, 0x41, 0, Some((&credential_id, &public_key)));
        self.credentials.push(Credential {
            id: credential_id,
            rp_id: rp_id.to_owned(),
            user_handle: user_handle.to_vec(),
            user_name: user_name.map(str::to_owned),
            user_display_name: user_display_name.map(str::to_owned),
            key,
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
        let allow_list = map_array(&request, 3);

        let Some(credential_index) = self.credentials.iter().position(|credential| {
            credential.rp_id == rp_id && allow_list_allows(allow_list, &credential.id)
        }) else {
            return Err(ErrorStatus::NoCredentials);
        };

        if !self.assertion_approved(rp_id) {
            return Err(ErrorStatus::OperationDenied);
        }

        let (auth_data, user, credential_id, key, rp_log, sign_count) = {
            let credential = &self.credentials[credential_index];
            let sign_count = credential.sign_count.saturating_add(1);
            let auth_data = make_auth_data(&credential.rp_id, 0x01, sign_count, None);

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
                credential.rp_id.clone(),
                sign_count,
            )
        };

        let mut signed_data = auth_data.clone();
        signed_data.extend_from_slice(client_data_hash);
        let signature = match sign_credential(&mut self.tpm, &key, &signed_data) {
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

        Ok(encode_response(Value::Map(vec![
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
        ])))
    }

    fn save_credentials(&self) {
        let credentials: Vec<_> = self
            .credentials
            .iter()
            .map(|credential| store::StoredCtap2Credential {
                id: credential.id.clone(),
                rp_id: credential.rp_id.clone(),
                user_handle: credential.user_handle.clone(),
                user_name: credential.user_name.clone(),
                user_display_name: credential.user_display_name.clone(),
                key: store::StoredTpmKey {
                    private: credential.key.private.clone(),
                    public: credential.key.public.clone(),
                    public_key_x: credential.key.public_key_x.clone(),
                    public_key_y: credential.key.public_key_y.clone(),
                },
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

        if !approval::approve(&format!("Authenticate with passkey for {rp_id}")) {
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

    credential_descriptor_list_contains(allow_list, credential_id)
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
) -> Vec<u8> {
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
    auth_data.push(flags);
    auth_data.extend_from_slice(&sign_count.to_be_bytes());

    if let Some((credential_id, public_key)) = attested_credential_data {
        auth_data.extend_from_slice(&AAGUID);
        auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(credential_id);
        ciborium::into_writer(public_key, &mut auth_data).expect("serializing static COSE key");
    }

    auth_data
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
    tpm: &mut Option<tpm::Tpm>,
    key: &tpm::TpmCredential,
    signed_data: &[u8],
) -> color_eyre::Result<Vec<u8>> {
    let tpm = tpm
        .as_mut()
        .ok_or_else(|| color_eyre::eyre::eyre!("TPM credential requires TPM context"))?;
    let digest = Sha256::digest(signed_data);
    tpm.sign_digest(key, &digest)
}

fn fill_random(bytes: &mut [u8]) {
    getrandom::fill(bytes).expect("kernel random source available");
}

fn encode_response(response: Value) -> Vec<u8> {
    let mut payload = vec![0x00];
    ciborium::into_writer(&response, &mut payload).expect("serializing CTAP2 response");
    payload
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
    fn allow_list_empty_or_non_matching_rejects_credential() {
        assert!(!allow_list_allows(Some(&[]), &[1, 2, 3, 4]));
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

    fn authenticator_with_credential(rp_id: &str, credential_id: Vec<u8>) -> Authenticator {
        Authenticator {
            store_dir: PathBuf::from("."),
            tpm: None,
            credentials: vec![Credential {
                id: credential_id,
                rp_id: rp_id.to_owned(),
                user_handle: vec![5, 6, 7, 8],
                user_name: Some("user".to_owned()),
                user_display_name: Some("Test User".to_owned()),
                key: tpm::TpmCredential {
                    private: vec![9],
                    public: vec![10],
                    public_key_x: vec![11; 32],
                    public_key_y: vec![12; 32],
                },
                sign_count: 0,
            }],
            recent_assertion_approval: None,
        }
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
}
