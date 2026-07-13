use std::path::PathBuf;

use crate::{ctap2, hid::REPORT_SIZE};

pub const BROADCAST_CID: u32 = 0xffff_ffff;

const CMD_PING: u8 = 0x01;
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

const MAX_PAYLOAD_SIZE: usize = (REPORT_SIZE - 7) + 128 * (REPORT_SIZE - 5);

#[derive(Default)]
pub struct PacketHandler {
    pending: Option<PendingRequest>,
    authenticator: ctap2::Authenticator,
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
    pub fn new(store_dir: PathBuf, tpm_path: Option<PathBuf>) -> Self {
        Self {
            pending: None,
            authenticator: ctap2::Authenticator::new(store_dir.clone(), tpm_path),
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
        CMD_INIT => "INIT",
        CMD_WINK => "WINK",
        CMD_CBOR => "CBOR",
        CMD_CANCEL => "CANCEL",
        CMD_ERROR => "ERROR",
        _ => "UNKNOWN",
    }
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
