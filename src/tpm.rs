use std::{
    convert::TryFrom,
    path::{Path, PathBuf},
};

use argon2::{Algorithm, Argon2, Params, Version};
use color_eyre::{Result, eyre::WrapErr};
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest as ShaDigest, Sha256};
use tss_esapi::{
    Context,
    attributes::ObjectAttributesBuilder,
    constants::{
        CommandCode, SessionType,
        tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK},
    },
    handles::{ObjectHandle, SessionHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        key_bits::RsaKeyBits,
        resource_handles::Hierarchy,
        session_handles::{AuthSession, PolicySession},
    },
    structures::{
        Auth, Digest, DigestList, EccPoint, EccScheme, HashScheme, Name, Nonce, PcrSelectionList,
        PcrSelectionListBuilder, PcrSlot, Private, Public, PublicBuilder,
        PublicEccParametersBuilder, RsaExponent, Signature, SignatureScheme,
        SymmetricDefinitionObject, Ticket,
    },
    tcti_ldr::TctiNameConf,
    traits::{Marshall, UnMarshall},
    tss2_esys::TPMT_TK_HASHCHECK,
    utils::{self, PublicKey},
};
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcrPolicyBinding {
    pub selection: String,
    pub digest: Vec<u8>,
    pub policy_ref: Option<Vec<u8>>,
    pub authority_name: Option<Vec<u8>>,
    pub authority_signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryKdf {
    Pbkdf2Sha256 {
        iterations: u32,
    },
    Argon2id {
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
    },
}

impl RecoveryKdf {
    pub const fn argon2id_default() -> Self {
        Self::Argon2id {
            memory_kib: 65_536,
            iterations: 3,
            parallelism: 1,
        }
    }

    pub const fn legacy_pbkdf2() -> Self {
        Self::Pbkdf2Sha256 {
            iterations: RECOVERY_PBKDF2_ITERATIONS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryMaterial {
    pub label: Option<String>,
    pub passphrase_salt: Vec<u8>,
    pub passphrase_hash: Vec<u8>,
    pub kdf: RecoveryKdf,
    pub key: TpmCredential,
    pub authority_name: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmCredential {
    pub private: Vec<u8>,
    pub public: Vec<u8>,
    pub public_key_x: Vec<u8>,
    pub public_key_y: Vec<u8>,
    pub auth_value: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct TpmConfig {
    pub device: PathBuf,
}

impl Default for TpmConfig {
    fn default() -> Self {
        Self {
            device: PathBuf::from("/dev/tpmrm0"),
        }
    }
}

pub fn check_device(path: &Path) -> std::io::Result<()> {
    std::fs::metadata(path).map(|_| ())
}

pub fn public_name(public_blob: &[u8]) -> Result<Vec<u8>> {
    let public = Public::unmarshall(public_blob).wrap_err("unmarshalling TPM public area")?;
    let encoded = public.marshall().wrap_err("marshalling TPM public area")?;
    let digest = Sha256::digest(encoded);
    let mut name = Vec::with_capacity(34);
    name.extend_from_slice(&0x000b_u16.to_be_bytes());
    name.extend_from_slice(&digest);
    Ok(name)
}

pub fn credential_policy_ref(credential_id: &[u8], owner_uid: Option<u32>) -> Vec<u8> {
    let mut value = b"linux-tpm-fido2/pcr-policy/v1".to_vec();
    value.extend_from_slice(credential_id);
    value.extend_from_slice(&owner_uid.unwrap_or(0).to_be_bytes());
    Sha256::digest(value).to_vec()
}

struct PolicySessionGuard {
    context: *mut Context,
    session: PolicySession,
}

struct ObjectHandleGuard {
    context: *mut Context,
    handle: ObjectHandle,
}

impl Drop for ObjectHandleGuard {
    fn drop(&mut self) {
        // Safety: the guard is created from &mut Tpm and dropped before the
        // &mut borrow is released, so no aliasing &mut references exist.
        let ctx = unsafe { &mut *self.context };
        let _ = ctx.flush_context(self.handle);
    }
}

impl Drop for PolicySessionGuard {
    fn drop(&mut self) {
        let handle: SessionHandle = self.session.into();
        // Safety: the guard is created from &mut Tpm and dropped before the
        // &mut borrow is released, so no aliasing &mut references exist.
        let ctx = unsafe { &mut *self.context };
        let _ = ctx.flush_context(handle.into());
    }
}

pub struct Tpm {
    context: Context,
}

impl Tpm {
    pub fn open(path: &Path) -> Result<Self> {
        let tcti = format!("device:{}", path.display())
            .parse::<TctiNameConf>()
            .wrap_err_with(|| format!("creating TPM TCTI config for {}", path.display()))?;
        let context = Context::new(tcti)
            .wrap_err_with(|| format!("opening TPM ESAPI context for {}", path.display()))?;
        Ok(Self { context })
    }

    pub fn probe(&mut self) -> Result<()> {
        let random = self
            .context
            .get_random(8)
            .wrap_err("reading random bytes from TPM")?;
        log::info!(
            "TPM probe succeeded; RNG returned {} bytes",
            random.value().len()
        );
        self.probe_ecc_signing()
            .wrap_err("probing TPM ECC signing")?;
        Ok(())
    }

    pub fn create_credential_key(&mut self) -> Result<TpmCredential> {
        self.create_credential_key_with_auth(None)
    }

    pub fn create_recovery_material(
        &mut self,
        label: Option<String>,
        passphrase: &str,
    ) -> Result<RecoveryMaterial> {
        let mut passphrase_salt = vec![0u8; 32];
        getrandom::fill(&mut passphrase_salt).wrap_err("generating recovery passphrase salt")?;
        let kdf = RecoveryKdf::argon2id_default();
        let passphrase_hash = recovery_passphrase_hash(&kdf, &passphrase_salt, passphrase)?;
        let key = self.create_credential_key_with_auth(Some(&passphrase_hash))?;
        let authority_name = public_name(&key.public)?;

        Ok(RecoveryMaterial {
            label,
            passphrase_salt,
            passphrase_hash,
            kdf,
            key,
            authority_name,
        })
    }

    pub fn create_credential_key_with_policy(
        &mut self,
        policy: Option<&PcrPolicyBinding>,
    ) -> Result<TpmCredential> {
        self.create_credential_key_with_policy_and_auth(policy, None)
    }

    fn create_credential_key_with_auth(
        &mut self,
        auth_value: Option<&[u8]>,
    ) -> Result<TpmCredential> {
        self.create_credential_key_with_policy_and_auth(None, auth_value)
    }

    fn create_credential_key_with_policy_and_auth(
        &mut self,
        policy: Option<&PcrPolicyBinding>,
        auth_value: Option<&[u8]>,
    ) -> Result<TpmCredential> {
        let parent = self.create_storage_parent()?;
        let public = signing_key_public(policy, auth_value.is_some())?;
        let auth = auth_value
            .map(|value| Auth::try_from(value.to_vec()))
            .transpose()
            .wrap_err("building TPM authority auth value")?;

        let key = self.context.execute_with_nullauth_session(|context| {
            context.create(parent, public, auth, None, None, None)
        });
        self.context
            .flush_context(parent.into())
            .wrap_err("flushing transient TPM storage parent")?;
        let key = key.wrap_err("creating TPM credential signing key")?;
        let PublicKey::Ecc { x, y } = PublicKey::try_from(key.out_public.clone())
            .wrap_err("extracting TPM credential public key")?
        else {
            color_eyre::eyre::bail!("TPM credential key is not ECC");
        };

        Ok(TpmCredential {
            private: key.out_private.value().to_vec(),
            public: key
                .out_public
                .marshall()
                .wrap_err("marshalling TPM credential public blob")?,
            public_key_x: x,
            public_key_y: y,
            auth_value: auth_value.map(ToOwned::to_owned),
        })
    }

    pub fn create_secure_boot_policy(&mut self) -> Result<PcrPolicyBinding> {
        let selection_list = secure_boot_pcr_selection_list()?;
        let current_digest = self.current_pcr_digest(&selection_list)?;
        let trial_session = self
            .context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                tss_esapi::structures::SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )?
            .ok_or_else(|| color_eyre::eyre::eyre!("TPM returned no trial policy session"))?;
        let trial_session = PolicySession::try_from(trial_session)?;
        self.context.policy_pcr(
            trial_session,
            Digest::try_from(current_digest.clone())?,
            selection_list,
        )?;
        let policy_digest = self.context.policy_get_digest(trial_session)?;
        self.context
            .flush_context(SessionHandle::from(trial_session).into())?;

        Ok(PcrPolicyBinding {
            selection: secure_boot_pcr_selection_name(),
            digest: policy_digest.value().to_vec(),
            policy_ref: None,
            authority_name: None,
            authority_signature: None,
        })
    }

    pub fn policy_with_ref_hash(policy_digest: &[u8], policy_ref: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(policy_digest);
        hasher.update(policy_ref);
        hasher.finalize().to_vec()
    }

    pub fn sign_recovery_policy(
        &mut self,
        authority: &TpmCredential,
        approved_policy: &[u8],
        policy_ref: &[u8],
    ) -> Result<Vec<u8>> {
        if approved_policy.len() != 32 {
            color_eyre::eyre::bail!("approved PCR policy must be a SHA-256 digest");
        }
        let to_sign = Self::policy_with_ref_hash(approved_policy, policy_ref);
        let parent = self.create_storage_parent()?;
        let private = Private::try_from(authority.private.clone())?;
        let public = Public::unmarshall(&authority.public)?;
        let key_handle = self
            .context
            .execute_with_nullauth_session(|context| context.load(parent, private, public))?;
        if let Some(auth_value) = &authority.auth_value {
            self.context
                .tr_set_auth(key_handle.into(), Auth::try_from(auth_value.clone())?)?;
        }
        let digest = Digest::try_from(to_sign)?;
        let validation = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };
        let signature = self
            .context
            .execute_with_session(Some(AuthSession::Password), |context| {
                context.sign(
                    key_handle,
                    digest,
                    SignatureScheme::Null,
                    validation.try_into()?,
                )
            })
            .wrap_err("signing approved PCR policy")?;
        self.context.flush_context(key_handle.into())?;
        self.context.flush_context(parent.into())?;
        signature
            .marshall()
            .wrap_err("marshalling approved PCR policy signature")
    }

    pub fn create_authorized_policy(
        &mut self,
        approved: &PcrPolicyBinding,
        authority: &TpmCredential,
        policy_ref: &[u8],
    ) -> Result<PcrPolicyBinding> {
        let policy_digest = &approved.digest;
        let to_sign = Self::policy_with_ref_hash(policy_digest, policy_ref);
        let signature_bytes = self.sign_recovery_policy(authority, policy_digest, policy_ref)?;
        let signature = Signature::unmarshall(&signature_bytes)?;
        let parent = self.create_storage_parent()?;
        let key_handle = self.context.execute_with_nullauth_session(|context| {
            context.load(
                parent,
                Private::try_from(authority.private.clone())?,
                Public::unmarshall(&authority.public)?,
            )
        })?;
        let (_, authority_name, _) = self.context.read_public(key_handle)?;
        let authority_name_bytes = authority_name.value().to_vec();
        if let Some(auth_value) = &authority.auth_value {
            self.context
                .tr_set_auth(key_handle.into(), Auth::try_from(auth_value.clone())?)?;
        }
        log::debug!(
            "create_authorized_policy: policy_digest={} hex={}, to_sign={} hex={}, policy_ref={} bytes, key_name={} bytes",
            policy_digest.len(),
            hex::encode(policy_digest),
            to_sign.len(),
            hex::encode(&to_sign),
            policy_ref.len(),
            authority_name_bytes.len(),
        );
        let ticket = self.context.execute_without_session(|context| {
            context.verify_signature(key_handle, Digest::try_from(to_sign)?, signature)
        })?;
        log::debug!(
            "verify_signature produced ticket: tag={:?}, hierarchy={:?}, ticket_digest={} hex={}",
            ticket.tag(),
            ticket.hierarchy(),
            ticket.digest().len(),
            hex::encode(ticket.digest()),
        );
        self.context.flush_context(parent.into())?;

        let selection = secure_boot_pcr_selection_list()?;
        let current_digest = self.current_pcr_digest(&selection)?;
        let session = self
            .context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                tss_esapi::structures::SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )?
            .ok_or_else(|| color_eyre::eyre::eyre!("TPM returned no trial policy session"))?;
        let session = PolicySession::try_from(session)?;
        self.context
            .policy_pcr(session, Digest::try_from(current_digest)?, selection)?;
        self.context.policy_authorize(
            session,
            Digest::try_from(policy_digest.clone())?,
            Nonce::try_from(policy_ref.to_vec())?,
            &Name::try_from(authority_name_bytes.clone())?,
            ticket,
        )?;
        self.context.flush_context(key_handle.into())?;
        self.context
            .policy_command_code(session, CommandCode::Sign)?;
        let final_digest = self.context.policy_get_digest(session)?;
        self.context
            .flush_context(SessionHandle::from(session).into())?;

        Ok(PcrPolicyBinding {
            selection: approved.selection.clone(),
            digest: final_digest.value().to_vec(),
            policy_ref: Some(policy_ref.to_vec()),
            authority_name: Some(authority_name_bytes),
            authority_signature: Some(signature_bytes),
        })
    }

    pub fn update_authorized_policy(
        &mut self,
        authority: &TpmCredential,
        authority_name: &[u8],
        policy_ref: &[u8],
    ) -> Result<PcrPolicyBinding> {
        let selection = secure_boot_pcr_selection_list()?;
        let current_digest = self.current_pcr_digest(&selection)?;
        let trial_session = self
            .context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                tss_esapi::structures::SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )?
            .ok_or_else(|| color_eyre::eyre::eyre!("TPM returned no trial policy session"))?;
        let trial_session = PolicySession::try_from(trial_session)?;
        self.context.policy_pcr(
            trial_session,
            Digest::try_from(current_digest.clone())?,
            selection.clone(),
        )?;
        let pcr_policy_digest = self.context.policy_get_digest(trial_session)?;
        self.context
            .flush_context(SessionHandle::from(trial_session).into())?;

        let to_sign = Self::policy_with_ref_hash(pcr_policy_digest.value(), policy_ref);
        let parent = self.create_storage_parent()?;
        let key_handle = self
            .context
            .execute_with_nullauth_session(|context| {
                context.load(
                    parent,
                    Private::try_from(authority.private.clone())?,
                    Public::unmarshall(&authority.public)?,
                )
            })
            .wrap_err("loading authority key for PCR update")?;
        if let Some(auth_value) = &authority.auth_value {
            self.context
                .tr_set_auth(key_handle.into(), Auth::try_from(auth_value.clone())?)?;
        }
        let validation = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };
        let signature = self
            .context
            .execute_with_session(Some(AuthSession::Password), |context| {
                context.sign(
                    key_handle,
                    Digest::try_from(to_sign.clone())?,
                    SignatureScheme::Null,
                    validation.try_into()?,
                )
            })
            .wrap_err("signing updated PCR policy with authority key")?;
        let ticket = self
            .context
            .execute_without_session(|context| {
                context.verify_signature(key_handle, Digest::try_from(to_sign)?, signature.clone())
            })
            .wrap_err("verifying updated PCR policy signature")?;
        self.context.flush_context(key_handle.into())?;

        let new_session = self
            .context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                tss_esapi::structures::SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )?
            .ok_or_else(|| color_eyre::eyre::eyre!("TPM returned no trial policy session"))?;
        let new_session = PolicySession::try_from(new_session)?;
        self.context
            .policy_pcr(new_session, Digest::try_from(current_digest)?, selection)?;
        self.context.policy_authorize(
            new_session,
            pcr_policy_digest,
            Nonce::try_from(policy_ref.to_vec())?,
            &Name::try_from(authority_name.to_vec())?,
            ticket,
        )?;
        self.context
            .policy_command_code(new_session, CommandCode::Sign)?;
        let final_digest = self.context.policy_get_digest(new_session)?;
        self.context
            .flush_context(SessionHandle::from(new_session).into())?;
        self.context.flush_context(parent.into())?;

        let signature_bytes = signature
            .marshall()
            .wrap_err("marshalling updated PCR policy signature")?;

        Ok(PcrPolicyBinding {
            selection: secure_boot_pcr_selection_name(),
            digest: final_digest.value().to_vec(),
            policy_ref: Some(policy_ref.to_vec()),
            authority_name: Some(authority_name.to_vec()),
            authority_signature: Some(signature_bytes),
        })
    }

    pub fn sign_digest(&mut self, credential: &TpmCredential, digest: &[u8]) -> Result<Vec<u8>> {
        self.sign_digest_with_policy(credential, None, None, digest)
    }

    pub fn sign_digest_with_policy(
        &mut self,
        credential: &TpmCredential,
        policy: Option<&PcrPolicyBinding>,
        authority: Option<&TpmCredential>,
        digest: &[u8],
    ) -> Result<Vec<u8>> {
        if digest.len() != 32 {
            color_eyre::eyre::bail!("TPM ECDSA signing digest must be 32 bytes");
        }

        let parent = self.create_storage_parent()?;
        let _parent_guard = ObjectHandleGuard {
            context: &mut self.context as *mut Context,
            handle: parent.into(),
        };
        let private = Private::try_from(credential.private.clone())
            .wrap_err("building TPM credential private blob")?;
        let public = Public::unmarshall(&credential.public)
            .wrap_err("unmarshalling TPM credential public blob")?;
        let key_handle = self
            .context
            .execute_with_nullauth_session(|context| context.load(parent, private, public))
            .wrap_err("loading TPM credential signing key")?;
        let _key_guard = ObjectHandleGuard {
            context: &mut self.context as *mut Context,
            handle: key_handle.into(),
        };

        let digest = Digest::try_from(digest.to_vec()).wrap_err("building TPM signing digest")?;
        let validation = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };

        let signature = if let (
            Some(_policy),
            Some(authority),
            Some(policy_ref),
            Some(authority_name),
            Some(authority_signature),
        ) = (
            policy,
            authority,
            policy.and_then(|policy| policy.policy_ref.as_ref()),
            policy.and_then(|policy| policy.authority_name.as_ref()),
            policy.and_then(|policy| policy.authority_signature.as_ref()),
        ) {
            let selection_list = secure_boot_pcr_selection_list()?;
            let current_digest = self.current_pcr_digest(&selection_list)?;
            let policy_session = self
                .context
                .start_auth_session(
                    None,
                    None,
                    None,
                    SessionType::Policy,
                    tss_esapi::structures::SymmetricDefinition::AES_256_CFB,
                    HashingAlgorithm::Sha256,
                )?
                .ok_or_else(|| color_eyre::eyre::eyre!("TPM returned no policy session"))?;
            let policy_session = PolicySession::try_from(policy_session)?;
            let _policy_session_guard = PolicySessionGuard {
                context: &mut self.context as *mut Context,
                session: policy_session,
            };
            self.context.policy_pcr(
                policy_session,
                Digest::try_from(current_digest.clone())?,
                selection_list,
            )?;
            let approved_policy = self.context.policy_get_digest(policy_session)?;
            let authority_handle = self.context.execute_with_nullauth_session(|context| {
                context.load(
                    parent,
                    Private::try_from(authority.private.clone())?,
                    Public::unmarshall(&authority.public)?,
                )
            })?;
            let _authority_guard = ObjectHandleGuard {
                context: &mut self.context as *mut Context,
                handle: authority_handle.into(),
            };
            let (_, actual_name, _) = self.context.read_public(authority_handle)?;
            if actual_name.value() != authority_name.as_slice() {
                color_eyre::eyre::bail!("recovery authority name does not match the credential");
            }
            if let Some(auth_value) = &authority.auth_value {
                self.context
                    .tr_set_auth(authority_handle.into(), Auth::try_from(auth_value.clone())?)?;
            }
            log::debug!(
                "policy_authorize: approved_policy={} hex={}, policy_ref={} bytes, key_name={} bytes, key_name_hex={}",
                approved_policy.len(),
                hex::encode(approved_policy.value()),
                policy_ref.len(),
                actual_name.value().len(),
                hex::encode(actual_name.value()),
            );
            // Per TPM spec, PolicyAuthorize computes
            //   aHash = hash(nameAlg of keySign, approvedPolicy || policyRef)
            // and validates the ticket against aHash, not against approvedPolicy
            // directly.  We must therefore verify the stored signature over
            // SHA-256(approvedPolicy || policyRef), not over approvedPolicy alone.
            let to_sign = Self::policy_with_ref_hash(approved_policy.value(), policy_ref);
            let ticket = self
                .context
                .execute_without_session(|context| {
                    context.verify_signature(
                        authority_handle,
                        Digest::try_from(to_sign)?,
                        Signature::unmarshall(authority_signature)?,
                    )
                })
                .wrap_err("verifying PCR policy authority signature")?;
            log::debug!(
                "verify_signature ticket: tag={:?} hierarchy={:?} digest={} hex={}",
                ticket.tag(),
                ticket.hierarchy(),
                ticket.digest().len(),
                hex::encode(ticket.digest()),
            );
            self.context.policy_authorize(
                policy_session,
                approved_policy,
                Nonce::try_from(policy_ref.clone())?,
                &actual_name,
                ticket,
            )?;
            self.context
                .policy_command_code(policy_session, CommandCode::Sign)?;

            self.context
                .execute_with_session(Some(AuthSession::from(policy_session)), |context| {
                    context.sign(
                        key_handle,
                        digest.clone(),
                        SignatureScheme::Null,
                        validation.try_into()?,
                    )
                })
        } else if policy.is_some() {
            let selection_list = secure_boot_pcr_selection_list()?;
            let current_digest = self.current_pcr_digest(&selection_list)?;
            let policy_session = self
                .context
                .start_auth_session(
                    None,
                    None,
                    None,
                    SessionType::Policy,
                    tss_esapi::structures::SymmetricDefinition::AES_256_CFB,
                    HashingAlgorithm::Sha256,
                )?
                .ok_or_else(|| color_eyre::eyre::eyre!("TPM returned no policy session"))?;
            let policy_session = PolicySession::try_from(policy_session)?;
            let _policy_session_guard = PolicySessionGuard {
                context: &mut self.context as *mut Context,
                session: policy_session,
            };
            self.context.policy_pcr(
                policy_session,
                Digest::try_from(current_digest)?,
                selection_list,
            )?;
            self.context
                .execute_with_session(Some(AuthSession::from(policy_session)), |context| {
                    context.sign(
                        key_handle,
                        digest.clone(),
                        SignatureScheme::Null,
                        validation.try_into()?,
                    )
                })
        } else {
            self.context.execute_with_nullauth_session(|context| {
                context.sign(
                    key_handle,
                    digest,
                    SignatureScheme::Null,
                    validation.try_into()?,
                )
            })
        };

        let signature = signature.wrap_err("signing digest with TPM credential key")?;
        let Signature::EcDsa(signature) = signature else {
            color_eyre::eyre::bail!("TPM returned non-ECDSA signature");
        };

        Ok(ecdsa_der(
            signature.signature_r().value(),
            signature.signature_s().value(),
        ))
    }

    pub fn change_key_auth(
        &mut self,
        credential: &TpmCredential,
        new_auth_value: &[u8],
    ) -> Result<TpmCredential> {
        let parent = self.create_storage_parent()?;
        let private =
            Private::try_from(credential.private.clone()).wrap_err("building TPM private blob")?;
        let public =
            Public::unmarshall(&credential.public).wrap_err("unmarshalling TPM public blob")?;
        let key_handle = self
            .context
            .execute_with_nullauth_session(|context| context.load(parent, private, public))
            .wrap_err("loading TPM credential for auth change")?;

        if let Some(auth_value) = &credential.auth_value {
            self.context
                .tr_set_auth(key_handle.into(), Auth::try_from(auth_value.clone())?)?;
        }

        let new_auth_data = new_auth_value.to_vec();
        let tpm_new_auth = Auth::try_from(new_auth_data.clone())?;
        let new_private = self
            .context
            .execute_with_session(Some(AuthSession::Password), |context| {
                context.object_change_auth(key_handle.into(), parent.into(), tpm_new_auth)
            })
            .wrap_err("changing TPM credential authorization")?;

        self.context.flush_context(key_handle.into())?;
        self.context.flush_context(parent.into())?;

        Ok(TpmCredential {
            private: new_private.value().to_vec(),
            public: credential.public.clone(),
            public_key_x: credential.public_key_x.clone(),
            public_key_y: credential.public_key_y.clone(),
            auth_value: Some(new_auth_data),
        })
    }

    fn current_pcr_digest(&mut self, selection_list: &PcrSelectionList) -> Result<Vec<u8>> {
        let (_, _, digest_list): (u32, PcrSelectionList, DigestList) =
            self.context.pcr_read(selection_list.clone())?;
        let mut hasher = Sha256::new();
        for digest in digest_list.value() {
            hasher.update(digest.value());
        }
        Ok(hasher.finalize().to_vec())
    }

    fn probe_ecc_signing(&mut self) -> Result<()> {
        let public = signing_key_public(None, true)?;

        let key_handle = self
            .context
            .execute_with_nullauth_session(|context| {
                context.create_primary(Hierarchy::Owner, public, None, None, None, None)
            })
            .wrap_err("creating transient TPM ECC signing key")?
            .key_handle;
        let digest = Digest::try_from(vec![0u8; 32]).wrap_err("building TPM signing digest")?;
        let validation = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };

        let signature = self.context.execute_with_nullauth_session(|context| {
            context.sign(
                key_handle,
                digest,
                SignatureScheme::Null,
                validation.try_into()?,
            )
        });
        self.context
            .flush_context(key_handle.into())
            .wrap_err("flushing transient TPM ECC signing key")?;
        let signature = signature.wrap_err("signing digest with transient TPM ECC key")?;
        let Signature::EcDsa(signature) = signature else {
            color_eyre::eyre::bail!("TPM returned non-ECDSA signature");
        };

        log::info!(
            "TPM ECC signing probe succeeded; r={} bytes s={} bytes",
            signature.signature_r().value().len(),
            signature.signature_s().value().len()
        );
        Ok(())
    }

    fn create_storage_parent(&mut self) -> Result<tss_esapi::handles::KeyHandle> {
        let public = utils::create_restricted_decryption_rsa_public(
            SymmetricDefinitionObject::AES_128_CFB,
            RsaKeyBits::Rsa2048,
            RsaExponent::default(),
        )
        .wrap_err("building TPM storage-parent template")?;
        Ok(self
            .context
            .execute_with_nullauth_session(|context| {
                context.create_primary(Hierarchy::Owner, public, None, None, None, None)
            })
            .wrap_err("creating transient TPM storage parent")?
            .key_handle)
    }
}

fn signing_key_public(policy: Option<&PcrPolicyBinding>, user_with_auth: bool) -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(user_with_auth)
        .with_decrypt(false)
        .with_sign_encrypt(true)
        .with_restricted(false)
        .build()
        .wrap_err("building TPM object attributes")?;

    let mut builder = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new_unrestricted_signing_key(
                EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)),
                EccCurve::NistP256,
            )
            .build()?,
        )
        .with_ecc_unique_identifier(EccPoint::default());

    if let Some(policy) = policy {
        builder = builder.with_auth_policy(Digest::try_from(policy.digest.clone())?);
    }

    builder
        .build()
        .wrap_err("building TPM ECC signing-key template")
}

fn secure_boot_pcr_selection_list() -> Result<PcrSelectionList> {
    PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot7])
        .build()
        .wrap_err("building secure boot PCR selection list")
}

fn secure_boot_pcr_selection_name() -> String {
    "sha256:7".to_owned()
}

const RECOVERY_PBKDF2_ITERATIONS: u32 = 600_000;

pub fn recovery_passphrase_hash(
    kdf: &RecoveryKdf,
    passphrase_salt: &[u8],
    passphrase: &str,
) -> Result<Vec<u8>> {
    let mut output = vec![0u8; 32];
    match kdf {
        RecoveryKdf::Pbkdf2Sha256 { iterations } => {
            pbkdf2_hmac::<Sha256>(
                passphrase.as_bytes(),
                passphrase_salt,
                *iterations,
                &mut output,
            );
        }
        RecoveryKdf::Argon2id {
            memory_kib,
            iterations,
            parallelism,
        } => {
            let params = Params::new(*memory_kib, *iterations, *parallelism, Some(output.len()))
                .map_err(|error| {
                    color_eyre::eyre::eyre!("building Argon2id recovery KDF parameters: {error:?}")
                })?;
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                .hash_password_into(passphrase.as_bytes(), passphrase_salt, &mut output)
                .map_err(|error| {
                    color_eyre::eyre::eyre!(
                        "deriving Argon2id recovery authorization value: {error:?}"
                    )
                })?;
        }
    }
    Ok(output)
}

pub fn recovery_passphrase_matches(
    kdf: &RecoveryKdf,
    passphrase_salt: &[u8],
    passphrase: &str,
    expected_hash: &[u8],
) -> Result<bool> {
    Ok(recovery_passphrase_hash(kdf, passphrase_salt, passphrase)? == expected_hash)
}

fn ecdsa_der(r: &[u8], s: &[u8]) -> Vec<u8> {
    let r = der_integer(r);
    let s = der_integer(s);
    let mut der = Vec::with_capacity(2 + r.len() + s.len());
    der.push(0x30);
    der.push((r.len() + s.len()) as u8);
    der.extend_from_slice(&r);
    der.extend_from_slice(&s);
    der
}

fn der_integer(value: &[u8]) -> Vec<u8> {
    let first_nonzero = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len());
    let mut integer = if first_nonzero == value.len() {
        vec![0]
    } else {
        value[first_nonzero..].to_vec()
    };
    if integer[0] & 0x80 != 0 {
        integer.insert(0, 0);
    }

    let mut der = Vec::with_capacity(2 + integer.len());
    der.push(0x02);
    der.push(integer.len() as u8);
    der.extend_from_slice(&integer);
    der
}

#[cfg(test)]
mod tests {
    use super::{RecoveryKdf, recovery_passphrase_hash, recovery_passphrase_matches};

    #[test]
    fn recovery_passphrase_hash_uses_pbkdf2_is_deterministic() {
        let salt = b"0123456789abcdef0123456789abcdef";
        let kdf = RecoveryKdf::legacy_pbkdf2();
        let hash = recovery_passphrase_hash(&kdf, salt, "correct horse battery staple")
            .expect("derive PBKDF2 hash");

        assert_eq!(hash.len(), 32, "PBKDF2 output should be 32 bytes (SHA-256)");
        assert_eq!(
            hash,
            recovery_passphrase_hash(&kdf, salt, "correct horse battery staple")
                .expect("derive PBKDF2 hash"),
            "PBKDF2 should be deterministic with same salt and passphrase"
        );
        assert!(
            recovery_passphrase_matches(&kdf, salt, "correct horse battery staple", &hash)
                .expect("verify correct passphrase")
        );
        assert!(
            !recovery_passphrase_matches(&kdf, salt, "wrong horse battery staple", &hash)
                .expect("verify wrong passphrase")
        );
    }

    #[test]
    fn recovery_passphrase_hash_different_salt_gives_different_hash() {
        let kdf = RecoveryKdf::argon2id_default();
        let hash1 = recovery_passphrase_hash(&kdf, b"salt-one", "passphrase")
            .expect("derive Argon2id hash");
        let hash2 = recovery_passphrase_hash(&kdf, b"salt-two", "passphrase")
            .expect("derive Argon2id hash");
        assert_ne!(
            hash1, hash2,
            "different salts must produce different hashes"
        );
    }

    #[test]
    fn recovery_argon2id_rejects_wrong_passphrase() {
        let kdf = RecoveryKdf::argon2id_default();
        let salt = b"0123456789abcdef0123456789abcdef";
        let hash = recovery_passphrase_hash(&kdf, salt, "correct horse battery staple")
            .expect("derive Argon2id hash");

        assert!(
            recovery_passphrase_matches(&kdf, salt, "correct horse battery staple", &hash,)
                .expect("verify correct passphrase")
        );
        assert!(
            !recovery_passphrase_matches(&kdf, salt, "wrong passphrase", &hash)
                .expect("verify wrong passphrase")
        );
    }
}
