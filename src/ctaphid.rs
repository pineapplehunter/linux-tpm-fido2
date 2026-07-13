use std::path::PathBuf;

use crate::{approval, ctap2, hid::REPORT_SIZE, store};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use rcgen::{CertifiedKey, KeyPair, SigningKey as RcgenSigningKey, generate_simple_self_signed};

pub const BROADCAST_CID: u32 = 0xffff_ffff;

const CMD_PING: u8 = 0x01;
const CMD_MSG: u8 = 0x03;
const CMD_INIT: u8 = 0x06;
const CMD_WINK: u8 = 0x08;
const CMD_CBOR: u8 = 0x10;
const CMD_CANCEL: u8 = 0x11;
const CMD_ERROR: u8 = 0x3f;

const TYPE_INIT: u8 = 0x80;

const ERR_INVALID_COMMAND: u8 = 0x01;
const ERR_INVALID_LENGTH: u8 = 0x03;
const ERR_INVALID_SEQ: u8 = 0x04;

const CAPABILITY_CBOR: u8 = 0x04;
const CAPABILITY_NMSG: u8 = 0x08;

const U2F_SW_NO_ERROR: [u8; 2] = [0x90, 0x00];
const U2F_SW_WRONG_DATA: [u8; 2] = [0x6a, 0x80];
const U2F_SW_CONDITIONS_NOT_SATISFIED: [u8; 2] = [0x69, 0x85];
const U2F_SW_INS_NOT_SUPPORTED: [u8; 2] = [0x6d, 0x00];

const MAX_PAYLOAD_SIZE: usize = (REPORT_SIZE - 7) + 128 * (REPORT_SIZE - 5);

#[derive(Default)]
pub struct PacketHandler {
    pending: Option<PendingRequest>,
    authenticator: ctap2::Authenticator,
    u2f: U2fAuthenticator,
}

struct U2fAuthenticator {
    store_dir: PathBuf,
    attestation_cert_der: Vec<u8>,
    attestation_key: KeyPair,
    credentials: Vec<U2fCredential>,
}

struct U2fCredential {
    key_handle: Vec<u8>,
    application: [u8; 32],
    signing_key: SigningKey,
    counter: u32,
}

impl Default for U2fAuthenticator {
    fn default() -> Self {
        Self::new(store::dev_store_dir())
    }
}

impl U2fAuthenticator {
    fn new(store_dir: PathBuf) -> Self {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(["linux-tpm-fido2.local".to_owned()])
                .expect("generate development U2F attestation certificate");
        let credentials = match store::load_u2f_credentials_from_dir(&store_dir) {
            Ok(credentials) => credentials
                .into_iter()
                .filter_map(
                    |credential| match SigningKey::from_slice(&credential.private_key) {
                        Ok(signing_key) => Some(U2fCredential {
                            key_handle: credential.key_handle,
                            application: credential.application,
                            signing_key,
                            counter: credential.counter,
                        }),
                        Err(error) => {
                            log::warn!("skipping stored U2F credential with invalid key: {error}");
                            None
                        }
                    },
                )
                .collect(),
            Err(error) => {
                log::warn!("failed to load U2F credential store: {error:?}");
                Vec::new()
            }
        };
        log::info!("loaded {} software U2F credentials", credentials.len());

        Self {
            store_dir,
            attestation_cert_der: cert.der().as_ref().to_vec(),
            attestation_key: signing_key,
            credentials,
        }
    }
}

#[derive(Debug)]
struct PendingRequest {
    cid: u32,
    command: u8,
    expected_len: usize,
    payload: Vec<u8>,
    next_sequence: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketOutcome {
    NeedMore,
    Response(Response),
}

impl PacketHandler {
    pub fn new(store_dir: PathBuf) -> Self {
        Self {
            pending: None,
            authenticator: ctap2::Authenticator::new(store_dir.clone()),
            u2f: U2fAuthenticator::new(store_dir),
        }
    }

    pub fn handle_packet(&mut self, report: &[u8]) -> Option<PacketOutcome> {
        if report.len() != REPORT_SIZE {
            return None;
        }

        let cid = u32::from_be_bytes(report[0..4].try_into().expect("fixed cid slice"));
        let packet_type = report[4];

        if packet_type & TYPE_INIT != 0 {
            self.handle_init_packet(cid, packet_type & !TYPE_INIT, report)
        } else {
            self.handle_continuation_packet(cid, packet_type, report)
        }
    }

    fn handle_init_packet(
        &mut self,
        cid: u32,
        command_id: u8,
        report: &[u8],
    ) -> Option<PacketOutcome> {
        let payload_len = u16::from_be_bytes([report[5], report[6]]) as usize;
        if payload_len > MAX_PAYLOAD_SIZE {
            self.pending = None;
            return Some(PacketOutcome::Response(error(cid, ERR_INVALID_LENGTH)));
        }

        let first_len = payload_len.min(REPORT_SIZE - 7);
        let mut payload = Vec::with_capacity(payload_len);
        payload.extend_from_slice(&report[7..7 + first_len]);

        if payload.len() == payload_len {
            self.pending = None;
            return Some(PacketOutcome::Response(
                self.dispatch(cid, command_id, &payload),
            ));
        }

        self.pending = Some(PendingRequest {
            cid,
            command: command_id,
            expected_len: payload_len,
            payload,
            next_sequence: 0,
        });
        Some(PacketOutcome::NeedMore)
    }

    fn handle_continuation_packet(
        &mut self,
        cid: u32,
        sequence: u8,
        report: &[u8],
    ) -> Option<PacketOutcome> {
        let Some(pending) = self.pending.as_mut() else {
            return None;
        };

        if pending.cid != cid || pending.next_sequence != sequence {
            let error_cid = pending.cid;
            self.pending = None;
            return Some(PacketOutcome::Response(error(error_cid, ERR_INVALID_SEQ)));
        }

        let remaining = pending.expected_len - pending.payload.len();
        let chunk_len = remaining.min(REPORT_SIZE - 5);
        pending.payload.extend_from_slice(&report[5..5 + chunk_len]);

        if pending.payload.len() == pending.expected_len {
            let pending = self.pending.take().expect("pending request");
            Some(PacketOutcome::Response(self.dispatch(
                pending.cid,
                pending.command,
                &pending.payload,
            )))
        } else {
            pending.next_sequence = pending.next_sequence.wrapping_add(1);
            Some(PacketOutcome::NeedMore)
        }
    }

    fn dispatch(&mut self, cid: u32, command_id: u8, payload: &[u8]) -> Response {
        match command_id {
            CMD_INIT => handle_init(cid, payload),
            CMD_PING => Response {
                cid,
                command: CMD_PING,
                payload: payload.to_vec(),
            },
            CMD_MSG => Response {
                cid,
                command: CMD_MSG,
                payload: self.u2f.handle_msg(payload),
            },
            CMD_WINK => Response {
                cid,
                command: CMD_WINK,
                payload: Vec::new(),
            },
            CMD_CBOR => Response {
                cid,
                command: CMD_CBOR,
                payload: self.authenticator.handle_cbor(payload),
            },
            CMD_CANCEL => error(cid, ERR_INVALID_COMMAND),
            _ => error(cid, ERR_INVALID_COMMAND),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub cid: u32,
    pub command: u8,
    pub payload: Vec<u8>,
}

impl Response {
    pub fn packets(&self) -> Vec<[u8; REPORT_SIZE]> {
        encode_message(self.cid, self.command, &self.payload)
    }
}

pub fn handle_packet(report: &[u8]) -> Option<Response> {
    let mut handler = PacketHandler::default();
    match handler.handle_packet(report) {
        Some(PacketOutcome::Response(response)) => Some(response),
        Some(PacketOutcome::NeedMore) | None => None,
    }
}

pub fn describe_report(report: &[u8]) -> String {
    if report.len() != REPORT_SIZE {
        return format!("invalid-size len={}", report.len());
    }

    let cid = u32::from_be_bytes(report[0..4].try_into().expect("fixed cid slice"));
    let packet_type = report[4];
    if packet_type & TYPE_INIT != 0 {
        let payload_len = u16::from_be_bytes([report[5], report[6]]) as usize;
        format!(
            "init cid={cid:#010x} cmd={}({:#04x}) payload_len={payload_len}",
            command_name(packet_type & !TYPE_INIT),
            packet_type & !TYPE_INIT
        )
    } else {
        format!("cont cid={cid:#010x} seq={packet_type}")
    }
}

pub fn command_name(command: u8) -> &'static str {
    match command {
        CMD_PING => "PING",
        CMD_MSG => "MSG",
        CMD_INIT => "INIT",
        CMD_WINK => "WINK",
        CMD_CBOR => "CBOR",
        CMD_CANCEL => "CANCEL",
        CMD_ERROR => "ERROR",
        _ => "UNKNOWN",
    }
}

impl U2fAuthenticator {
    fn handle_msg(&mut self, payload: &[u8]) -> Vec<u8> {
        log::info!(
            "u2f apdu ins={} p1={} payload_len={}",
            payload
                .get(1)
                .map(|ins| format!("{ins:#04x}"))
                .unwrap_or_else(|| "missing".to_owned()),
            payload
                .get(2)
                .map(|p1| format!("{p1:#04x}"))
                .unwrap_or_else(|| "missing".to_owned()),
            payload.len()
        );

        match payload.get(1).copied() {
            Some(0x01) => self.register(payload),
            Some(0x02) => self.authenticate(payload),
            Some(0x03) => status_response(b"U2F_V2", U2F_SW_NO_ERROR),
            _ => U2F_SW_INS_NOT_SUPPORTED.to_vec(),
        }
    }

    fn register(&mut self, payload: &[u8]) -> Vec<u8> {
        let Some(data) = apdu_data(payload) else {
            return U2F_SW_WRONG_DATA.to_vec();
        };
        if data.len() < 64 {
            return U2F_SW_WRONG_DATA.to_vec();
        }

        if !approval::approve("Register a new passkey") {
            return U2F_SW_CONDITIONS_NOT_SATISFIED.to_vec();
        }

        let challenge: [u8; 32] = data[0..32].try_into().expect("challenge length checked");
        let application: [u8; 32] = data[32..64].try_into().expect("application length checked");
        let signing_key = random_signing_key();
        let public_key = signing_key.verifying_key().to_sec1_point(false);
        let public_key = public_key.as_bytes();
        let mut key_handle = vec![0u8; 32];
        fill_random(&mut key_handle);

        let mut signature_base = Vec::new();
        signature_base.push(0);
        signature_base.extend_from_slice(&application);
        signature_base.extend_from_slice(&challenge);
        signature_base.extend_from_slice(&key_handle);
        signature_base.extend_from_slice(public_key);
        let signature = self
            .attestation_key
            .sign(&signature_base)
            .expect("sign U2F registration response");

        self.credentials.push(U2fCredential {
            key_handle: key_handle.clone(),
            application,
            signing_key,
            counter: 0,
        });
        self.save_credentials();

        log::info!(
            "created software U2F credential key_handle_len={} total_u2f_credentials={}",
            key_handle.len(),
            self.credentials.len()
        );

        let mut response = Vec::new();
        response.push(0x05);
        response.extend_from_slice(public_key);
        response.push(key_handle.len() as u8);
        response.extend_from_slice(&key_handle);
        response.extend_from_slice(&self.attestation_cert_der);
        response.extend_from_slice(&signature);
        response.extend_from_slice(&U2F_SW_NO_ERROR);
        response
    }

    fn authenticate(&mut self, payload: &[u8]) -> Vec<u8> {
        let Some(data) = apdu_data(payload) else {
            return U2F_SW_WRONG_DATA.to_vec();
        };
        if data.len() < 65 {
            return U2F_SW_WRONG_DATA.to_vec();
        }

        let challenge = &data[0..32];
        let application: [u8; 32] = data[32..64].try_into().expect("application length checked");
        let key_handle_len = data[64] as usize;
        if data.len() < 65 + key_handle_len {
            return U2F_SW_WRONG_DATA.to_vec();
        }
        let key_handle = &data[65..65 + key_handle_len];
        let check_only = payload.get(2) == Some(&0x07);

        let Some(credential) = self.credentials.iter_mut().find(|credential| {
            credential.application == application && credential.key_handle == key_handle
        }) else {
            return U2F_SW_WRONG_DATA.to_vec();
        };

        if check_only {
            return U2F_SW_CONDITIONS_NOT_SATISFIED.to_vec();
        }

        if !approval::approve("Authenticate with this passkey") {
            return U2F_SW_CONDITIONS_NOT_SATISFIED.to_vec();
        }

        credential.counter = credential.counter.saturating_add(1);
        let counter = credential.counter.to_be_bytes();
        let mut signature_base = Vec::new();
        signature_base.extend_from_slice(&application);
        signature_base.push(0x01);
        signature_base.extend_from_slice(&counter);
        signature_base.extend_from_slice(challenge);
        let signature: Signature = credential.signing_key.sign(&signature_base);

        log::info!(
            "asserting software U2F credential counter={}",
            credential.counter
        );
        self.save_credentials();

        let mut response = Vec::new();
        response.push(0x01);
        response.extend_from_slice(&counter);
        response.extend_from_slice(signature.to_der().as_bytes());
        response.extend_from_slice(&U2F_SW_NO_ERROR);
        response
    }

    fn save_credentials(&self) {
        let credentials: Vec<_> = self
            .credentials
            .iter()
            .map(|credential| store::StoredU2fCredential {
                key_handle: credential.key_handle.clone(),
                application: credential.application,
                private_key: credential.signing_key.to_bytes().to_vec(),
                counter: credential.counter,
            })
            .collect();

        let path = store::u2f_credentials_path_in_dir(&self.store_dir);
        if let Err(error) = store::save_u2f_credentials_to_dir(&self.store_dir, &credentials) {
            log::warn!("failed to save U2F credential store: {error:?}");
        } else {
            log::info!(
                "saved {} software U2F credentials to {}",
                credentials.len(),
                path.display()
            );
        }
    }
}

fn random_signing_key() -> SigningKey {
    loop {
        let mut private_key = [0u8; 32];
        fill_random(&mut private_key);
        if let Ok(signing_key) = SigningKey::from_slice(&private_key) {
            return signing_key;
        }
    }
}

fn fill_random(bytes: &mut [u8]) {
    getrandom::fill(bytes).expect("kernel random source available");
}

fn apdu_data(payload: &[u8]) -> Option<&[u8]> {
    if payload.len() < 7 || payload[4] != 0 {
        return None;
    }
    let len = u16::from_be_bytes([payload[5], payload[6]]) as usize;
    (payload.len() >= 7 + len).then_some(&payload[7..7 + len])
}

fn status_response(data: &[u8], status: [u8; 2]) -> Vec<u8> {
    let mut response = data.to_vec();
    response.extend_from_slice(&status);
    response
}

fn handle_init(cid: u32, payload: &[u8]) -> Response {
    if payload.len() != 8 {
        return error(cid, ERR_INVALID_LENGTH);
    }

    let allocated_cid = if cid == BROADCAST_CID { 1 } else { cid };
    let mut response = Vec::with_capacity(17);
    response.extend_from_slice(payload);
    response.extend_from_slice(&allocated_cid.to_be_bytes());
    response.push(2); // CTAPHID protocol version.
    response.extend_from_slice(&[0, 1, 0]);
    response.push(CAPABILITY_CBOR | CAPABILITY_NMSG);

    Response {
        cid,
        command: CMD_INIT,
        payload: response,
    }
}

fn error(cid: u32, code: u8) -> Response {
    Response {
        cid,
        command: CMD_ERROR,
        payload: vec![code],
    }
}

fn encode_message(cid: u32, command: u8, payload: &[u8]) -> Vec<[u8; REPORT_SIZE]> {
    let mut packets = Vec::new();
    let mut first = [0u8; REPORT_SIZE];
    first[0..4].copy_from_slice(&cid.to_be_bytes());
    first[4] = command | TYPE_INIT;
    first[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());

    let first_len = payload.len().min(REPORT_SIZE - 7);
    first[7..7 + first_len].copy_from_slice(&payload[..first_len]);
    packets.push(first);

    let mut offset = first_len;
    let mut sequence = 0u8;
    while offset < payload.len() {
        let mut continuation = [0u8; REPORT_SIZE];
        continuation[0..4].copy_from_slice(&cid.to_be_bytes());
        continuation[4] = sequence;
        let chunk_len = (payload.len() - offset).min(REPORT_SIZE - 5);
        continuation[5..5 + chunk_len].copy_from_slice(&payload[offset..offset + chunk_len]);
        packets.push(continuation);
        offset += chunk_len;
        sequence = sequence.wrapping_add(1);
    }

    packets
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_packet() -> [u8; REPORT_SIZE] {
        let mut packet = [0u8; REPORT_SIZE];
        packet[0..4].copy_from_slice(&BROADCAST_CID.to_be_bytes());
        packet[4] = CMD_INIT | TYPE_INIT;
        packet[5..7].copy_from_slice(&8u16.to_be_bytes());
        packet[7..15].copy_from_slice(b"12345678");
        packet
    }

    #[test]
    fn init_allocates_channel() {
        let response = handle_packet(&init_packet()).expect("response");
        assert_eq!(response.command, CMD_INIT);
        assert_eq!(&response.payload[0..8], b"12345678");
        assert_eq!(&response.payload[8..12], &1u32.to_be_bytes());
        assert_eq!(response.payload[12], 2);
        assert_eq!(response.payload[16], CAPABILITY_CBOR | CAPABILITY_NMSG);
    }

    #[test]
    fn continuation_packets_are_assembled() {
        let mut handler = PacketHandler::default();
        let payload = vec![0xaa; 100];

        let mut first = [0u8; REPORT_SIZE];
        first[0..4].copy_from_slice(&7u32.to_be_bytes());
        first[4] = CMD_PING | TYPE_INIT;
        first[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        first[7..].copy_from_slice(&payload[..REPORT_SIZE - 7]);

        let mut second = [0u8; REPORT_SIZE];
        second[0..4].copy_from_slice(&7u32.to_be_bytes());
        second[4] = 0;
        second[5..5 + payload.len() - (REPORT_SIZE - 7)]
            .copy_from_slice(&payload[REPORT_SIZE - 7..]);

        assert_eq!(handler.handle_packet(&first), Some(PacketOutcome::NeedMore));
        let Some(PacketOutcome::Response(response)) = handler.handle_packet(&second) else {
            panic!("expected response");
        };
        assert_eq!(response.command, CMD_PING);
        assert_eq!(response.payload, payload);
    }

    #[test]
    fn ping_echoes_payload() {
        let mut packet = [0u8; REPORT_SIZE];
        packet[0..4].copy_from_slice(&7u32.to_be_bytes());
        packet[4] = CMD_PING | TYPE_INIT;
        packet[5..7].copy_from_slice(&3u16.to_be_bytes());
        packet[7..10].copy_from_slice(b"abc");

        let response = handle_packet(&packet).expect("response");
        assert_eq!(response.cid, 7);
        assert_eq!(response.command, CMD_PING);
        assert_eq!(response.payload, b"abc");
    }

    #[test]
    fn msg_version_probe_gets_u2f_version() {
        let mut packet = [0u8; REPORT_SIZE];
        packet[0..4].copy_from_slice(&7u32.to_be_bytes());
        packet[4] = CMD_MSG | TYPE_INIT;
        packet[5..7].copy_from_slice(&7u16.to_be_bytes());
        packet[7..14].copy_from_slice(&[0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00]);

        let response = handle_packet(&packet).expect("response");
        assert_eq!(response.command, CMD_MSG);
        assert_eq!(response.payload, b"U2F_V2\x90\x00");
    }

    #[test]
    fn response_packets_use_init_command_byte() {
        let response = Response {
            cid: 9,
            command: CMD_PING,
            payload: b"abc".to_vec(),
        };
        let packets = response.packets();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0][4], CMD_PING | TYPE_INIT);
        assert_eq!(&packets[0][7..10], b"abc");
    }
}
