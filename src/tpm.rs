use std::{
    convert::TryFrom,
    path::{Path, PathBuf},
};

use color_eyre::{eyre::WrapErr, Result};
use sha2::{Digest as ShaDigest, Sha256};
use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    constants::{
        tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK},
        SessionType,
    },
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        key_bits::RsaKeyBits,
        resource_handles::Hierarchy,
        session_handles::{AuthSession, PolicySession},
    },
    structures::{
        Digest, DigestList, EccPoint, EccScheme, HashScheme, PcrSelectionList,
        PcrSelectionListBuilder, PcrSlot, Private, Public, PublicBuilder,
        PublicEccParametersBuilder, RsaExponent, Signature, SignatureScheme,
        SymmetricDefinitionObject,
    },
    tcti_ldr::TctiNameConf,
    traits::{Marshall, UnMarshall},
    tss2_esys::TPMT_TK_HASHCHECK,
    utils::{self, PublicKey},
    Context,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcrPolicyBinding {
    pub selection: String,
    pub digest: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmCredential {
    pub private: Vec<u8>,
    pub public: Vec<u8>,
    pub public_key_x: Vec<u8>,
    pub public_key_y: Vec<u8>,
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
        self.create_credential_key_with_policy(None)
    }

    pub fn create_credential_key_with_policy(
        &mut self,
        policy: Option<&PcrPolicyBinding>,
    ) -> Result<TpmCredential> {
        let parent = self.create_storage_parent()?;
        let public = signing_key_public(policy)?;
        let key = self.context.execute_with_nullauth_session(|context| {
            context.create(parent, public, None, None, None, None)
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

        Ok(PcrPolicyBinding {
            selection: secure_boot_pcr_selection_name(),
            digest: policy_digest.value().to_vec(),
        })
    }

    pub fn sign_digest(&mut self, credential: &TpmCredential, digest: &[u8]) -> Result<Vec<u8>> {
        self.sign_digest_with_policy(credential, None, digest)
    }

    pub fn sign_digest_with_policy(
        &mut self,
        credential: &TpmCredential,
        policy: Option<&PcrPolicyBinding>,
        digest: &[u8],
    ) -> Result<Vec<u8>> {
        if digest.len() != 32 {
            color_eyre::eyre::bail!("TPM ECDSA signing digest must be 32 bytes");
        }

        let parent = self.create_storage_parent()?;
        let private = Private::try_from(credential.private.clone())
            .wrap_err("building TPM credential private blob")?;
        let public = Public::unmarshall(&credential.public)
            .wrap_err("unmarshalling TPM credential public blob")?;
        let key_handle = self
            .context
            .execute_with_nullauth_session(|context| context.load(parent, private, public))
            .wrap_err("loading TPM credential signing key")?;

        let digest = Digest::try_from(digest.to_vec()).wrap_err("building TPM signing digest")?;
        let validation = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };

        let signature = if policy.is_some() {
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
            self.context.policy_pcr(
                policy_session,
                Digest::try_from(current_digest.clone())?,
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

        self.context
            .flush_context(key_handle.into())
            .wrap_err("flushing loaded TPM credential key")?;
        self.context
            .flush_context(parent.into())
            .wrap_err("flushing transient TPM storage parent")?;
        let signature = signature.wrap_err("signing digest with TPM credential key")?;
        let Signature::EcDsa(signature) = signature else {
            color_eyre::eyre::bail!("TPM returned non-ECDSA signature");
        };

        Ok(ecdsa_der(
            signature.signature_r().value(),
            signature.signature_s().value(),
        ))
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
        let public = signing_key_public(None)?;

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

fn signing_key_public(policy: Option<&PcrPolicyBinding>) -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
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
