use std::{collections::HashMap, path::PathBuf};

use crate::{ctap2, hid::REPORT_SIZE, store};

pub const BROADCAST_CID: u32 = 0xffff_ffff;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CtapHidCommand {
    Ping = 0x01,
    Init = 0x06,
    Wink = 0x08,
    Cbor = 0x10,
    Cancel = 0x11,
    Error = 0x3f,
}

impl CtapHidCommand {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Ping),
            0x06 => Some(Self::Init),
            0x08 => Some(Self::Wink),
            0x10 => Some(Self::Cbor),
            0x11 => Some(Self::Cancel),
            0x3f => Some(Self::Error),
            _ => None,
        }
    }

    fn byte(self) -> u8 {
        self as u8
    }
}

const TYPE_INIT: u8 = 0x80;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum CtapHidError {
    Command = 0x01,
    Length = 0x03,
    Seq = 0x04,
}

const CAPABILITY_CBOR: u8 = 0x04;
const CAPABILITY_NMSG: u8 = 0x08;

const MAX_PAYLOAD_SIZE: usize = (REPORT_SIZE - 7) + 128 * (REPORT_SIZE - 5);

pub struct PacketHandler {
    pending: HashMap<u32, PendingRequest>,
    authenticators: HashMap<u32, ctap2::Authenticator>,
    next_cid: u32,
    store_dir: PathBuf,
    tpm_path: Option<PathBuf>,
}

impl Default for PacketHandler {
    fn default() -> Self {
        Self::new(store::dev_store_dir(), None)
    }
}

#[derive(Debug)]
struct PendingRequest {
    cid: u32,
    command: CtapHidCommand,
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
    pub fn new(store_dir: PathBuf, tpm_path: Option<PathBuf>) -> Self {
        Self {
            pending: HashMap::new(),
            authenticators: HashMap::new(),
            next_cid: 1,
            store_dir,
            tpm_path,
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
            self.pending.remove(&cid);
            return Some(PacketOutcome::Response(error(cid, CtapHidError::Length)));
        }

        let Some(command) = CtapHidCommand::from_byte(command_id) else {
            return Some(PacketOutcome::Response(error(cid, CtapHidError::Command)));
        };

        let first_len = payload_len.min(REPORT_SIZE - 7);
        let mut payload = Vec::with_capacity(payload_len);
        payload.extend_from_slice(&report[7..7 + first_len]);

        if payload.len() == payload_len {
            self.pending.remove(&cid);
            return Some(PacketOutcome::Response(
                self.dispatch(cid, command, &payload),
            ));
        }

        self.pending.insert(
            cid,
            PendingRequest {
                cid,
                command,
                expected_len: payload_len,
                payload,
                next_sequence: 0,
            },
        );
        Some(PacketOutcome::NeedMore)
    }

    fn handle_continuation_packet(
        &mut self,
        cid: u32,
        sequence: u8,
        report: &[u8],
    ) -> Option<PacketOutcome> {
        let pending = self.pending.get_mut(&cid)?;

        if pending.cid != cid || pending.next_sequence != sequence {
            let error_cid = pending.cid;
            self.pending.remove(&cid);
            return Some(PacketOutcome::Response(error(error_cid, CtapHidError::Seq)));
        }

        let remaining = pending.expected_len - pending.payload.len();
        let chunk_len = remaining.min(REPORT_SIZE - 5);
        pending.payload.extend_from_slice(&report[5..5 + chunk_len]);

        if pending.payload.len() == pending.expected_len {
            let pending = self.pending.remove(&cid).expect("pending request");
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

    fn dispatch(&mut self, cid: u32, command: CtapHidCommand, payload: &[u8]) -> Response {
        match command {
            CtapHidCommand::Init => {
                let allocated_cid = if cid == BROADCAST_CID {
                    if self.next_cid == 0 {
                        self.next_cid = 1;
                    }
                    let allocated = self.next_cid;
                    self.next_cid = self.next_cid.wrapping_add(1).max(1);
                    allocated
                } else {
                    cid
                };
                self.authenticators.entry(allocated_cid).or_insert_with(|| {
                    ctap2::Authenticator::new(self.store_dir.clone(), self.tpm_path.clone())
                });
                handle_init(cid, allocated_cid, payload)
            }
            CtapHidCommand::Ping => Response {
                cid,
                command: CtapHidCommand::Ping,
                payload: payload.to_vec(),
            },
            CtapHidCommand::Wink => Response {
                cid,
                command: CtapHidCommand::Wink,
                payload: Vec::new(),
            },
            CtapHidCommand::Cbor => {
                let authenticator = self.authenticator_for(cid);
                Response {
                    cid,
                    command: CtapHidCommand::Cbor,
                    payload: authenticator.handle_cbor(payload),
                }
            }
            CtapHidCommand::Cancel => {
                self.pending.remove(&cid);
                if let Some(authenticator) = self.authenticators.get_mut(&cid) {
                    authenticator.cancel_pending();
                }
                error(cid, CtapHidError::Command)
            }
            CtapHidCommand::Error => error(cid, CtapHidError::Command),
        }
    }

    fn authenticator_for(&mut self, cid: u32) -> &mut ctap2::Authenticator {
        let store_dir = self.store_dir.clone();
        let tpm_path = self.tpm_path.clone();
        self.authenticators
            .entry(cid)
            .or_insert_with(|| ctap2::Authenticator::new(store_dir, tpm_path))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub cid: u32,
    pub command: CtapHidCommand,
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
        let cmd_byte = packet_type & !TYPE_INIT;
        let cmd_name = CtapHidCommand::from_byte(cmd_byte)
            .map(command_name)
            .unwrap_or("UNKNOWN");
        format!("init cid={cid:#010x} cmd={cmd_name}({cmd_byte:#04x}) payload_len={payload_len}",)
    } else {
        format!("cont cid={cid:#010x} seq={packet_type}")
    }
}

pub fn command_name(command: CtapHidCommand) -> &'static str {
    match command {
        CtapHidCommand::Ping => "PING",
        CtapHidCommand::Init => "INIT",
        CtapHidCommand::Wink => "WINK",
        CtapHidCommand::Cbor => "CBOR",
        CtapHidCommand::Cancel => "CANCEL",
        CtapHidCommand::Error => "ERROR",
    }
}

fn handle_init(cid: u32, allocated_cid: u32, payload: &[u8]) -> Response {
    if payload.len() != 8 {
        return error(cid, CtapHidError::Length);
    }

    let mut response = Vec::with_capacity(17);
    response.extend_from_slice(payload);
    response.extend_from_slice(&allocated_cid.to_be_bytes());
    response.push(2); // CTAPHID protocol version.
    response.extend_from_slice(&[0, 1, 0]);
    response.push(CAPABILITY_CBOR | CAPABILITY_NMSG);

    Response {
        cid,
        command: CtapHidCommand::Init,
        payload: response,
    }
}

fn error(cid: u32, code: CtapHidError) -> Response {
    Response {
        cid,
        command: CtapHidCommand::Error,
        payload: vec![code as u8],
    }
}

fn encode_message(cid: u32, command: CtapHidCommand, payload: &[u8]) -> Vec<[u8; REPORT_SIZE]> {
    let mut packets = Vec::new();
    let mut first = [0u8; REPORT_SIZE];
    first[0..4].copy_from_slice(&cid.to_be_bytes());
    first[4] = command.byte() | TYPE_INIT;
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
        packet[4] = CtapHidCommand::Init.byte() | TYPE_INIT;
        packet[5..7].copy_from_slice(&8u16.to_be_bytes());
        packet[7..15].copy_from_slice(b"12345678");
        packet
    }

    #[test]
    fn init_allocates_channel() {
        let response = handle_packet(&init_packet()).expect("response");
        assert_eq!(response.command, CtapHidCommand::Init);
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
        first[4] = CtapHidCommand::Ping.byte() | TYPE_INIT;
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
        assert_eq!(response.command, CtapHidCommand::Ping);
        assert_eq!(response.payload, payload);
    }

    #[test]
    fn ping_echoes_payload() {
        let mut packet = [0u8; REPORT_SIZE];
        packet[0..4].copy_from_slice(&7u32.to_be_bytes());
        packet[4] = CtapHidCommand::Ping.byte() | TYPE_INIT;
        packet[5..7].copy_from_slice(&3u16.to_be_bytes());
        packet[7..10].copy_from_slice(b"abc");

        let response = handle_packet(&packet).expect("response");
        assert_eq!(response.cid, 7);
        assert_eq!(response.command, CtapHidCommand::Ping);
        assert_eq!(response.payload, b"abc");
    }

    #[test]
    fn response_packets_use_init_command_byte() {
        let response = Response {
            cid: 9,
            command: CtapHidCommand::Ping,
            payload: b"abc".to_vec(),
        };
        let packets = response.packets();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0][4], CtapHidCommand::Ping.byte() | TYPE_INIT);
        assert_eq!(&packets[0][7..10], b"abc");
    }
}
