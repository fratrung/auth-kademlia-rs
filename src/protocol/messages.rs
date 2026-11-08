//! The messages nodes exchange, and which answer each request expects.
//!
//! `RpcMessage` is the wire format: bincode encodes its variants by position,
//! so a new message goes at the end, and older nodes cannot decode it.
//! `Frame` wraps a message with its id; sending and receiving are in
//! `transport.rs`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::node::Node;
use crate::storage::StorageWriteStatus;
use crate::utils::ID_LEN;

/// Explicit result of a STORE request.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
pub enum StoreStatus {
    Stored,
    AlreadyStored,
    Conflict,
    CapacityExceeded,
    InvalidRecord,
}

impl From<StorageWriteStatus> for StoreStatus {
    fn from(status: StorageWriteStatus) -> Self {
        match status {
            StorageWriteStatus::Stored => Self::Stored,
            StorageWriteStatus::AlreadyStored => Self::AlreadyStored,
            StorageWriteStatus::Conflict => Self::Conflict,
            StorageWriteStatus::CapacityExceeded => Self::CapacityExceeded,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RpcMessage {
    Ping {
        sender_id: [u8; ID_LEN],
    },
    Pong {
        sender_id: [u8; ID_LEN],
    },
    Store {
        sender_id: [u8; ID_LEN],
        key: [u8; ID_LEN],
        value: Vec<u8>,
    },
    StoreResult {
        status: StoreStatus,
    },
    Update {
        sender_id: [u8; ID_LEN],
        key: [u8; ID_LEN],
        value: Vec<u8>,
        auth_signature: Vec<u8>,
    },
    UpdateResult {
        ok: bool,
    },
    UpdateStatusList {
        sender_id: [u8; ID_LEN],
        key: [u8; ID_LEN],
        value: Vec<u8>,
    },
    UpdateStatusListResult {
        ok: bool,
    },
    FindNode {
        sender_id: [u8; ID_LEN],
        key: [u8; ID_LEN],
    },
    FindNodeResult {
        nodes: Vec<WireNode>,
    },
    FindValue {
        sender_id: [u8; ID_LEN],
        key: [u8; ID_LEN],
    },
    FindValueNodes {
        nodes: Vec<WireNode>,
    },
    FindValueHit {
        value: Vec<u8>,
    },
    Leave {
        sender_id: [u8; ID_LEN],
    },
    /// Whether the node holds a record for `key`, asked by an empty replica
    /// before a STORE. A node that holds one answers with its SHA-256
    /// (`FindHashHit`), one that does not with closer nodes (`FindValueNodes`).
    /// The answer fits in one datagram, unlike a whole record.
    FindHash {
        sender_id: [u8; ID_LEN],
        key: [u8; ID_LEN],
    },
    FindHashHit {
        hash: [u8; RECORD_HASH_LEN],
    },
    /// Sent at once for a request that carries a record (`Store`, `Update`,
    /// `UpdateStatusList`), whose answer may take a while: the request
    /// arrived and is being handled, so the sender does not send it again yet.
    /// Sent again for each copy that arrives meanwhile.
    Received,
}

/// Length of `record_hash`.
pub const RECORD_HASH_LEN: usize = 32;

/// SHA-256 of a whole record, as a node answers `FindHash`.
pub fn record_hash(record: &[u8]) -> [u8; RECORD_HASH_LEN] {
    Sha256::digest(record).into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireNode {
    pub id: [u8; ID_LEN],
    pub ip: Option<String>,
    pub port: Option<u16>,
}

impl From<&Node> for WireNode {
    fn from(n: &Node) -> Self {
        Self {
            id: n.id,
            ip: n.ip.clone(),
            port: n.port,
        }
    }
}

impl From<WireNode> for Node {
    fn from(w: WireNode) -> Self {
        Node::new(w.id, w.ip, w.port)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Frame {
    pub(super) msg_id: u32,
    pub(super) is_request: bool,
    pub(super) message: RpcMessage,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum ExpectedResponse {
    Pong,
    StoreResult,
    UpdateResult,
    UpdateStatusListResult,
    FindNodeResult,
    FindValueResult,
    FindHashResult,
    NoResponse,
}

impl ExpectedResponse {
    pub(super) fn for_request(message: &RpcMessage) -> Self {
        match message {
            RpcMessage::Ping { .. } => Self::Pong,
            RpcMessage::Store { .. } => Self::StoreResult,
            RpcMessage::Update { .. } => Self::UpdateResult,
            RpcMessage::UpdateStatusList { .. } => Self::UpdateStatusListResult,
            RpcMessage::FindNode { .. } => Self::FindNodeResult,
            RpcMessage::FindValue { .. } => Self::FindValueResult,
            RpcMessage::FindHash { .. } => Self::FindHashResult,
            RpcMessage::Leave { .. } => Self::NoResponse,
            // Answers are not requests; listed so that a new message type
            // does not compile until its expected answer is chosen here.
            RpcMessage::Pong { .. }
            | RpcMessage::StoreResult { .. }
            | RpcMessage::UpdateResult { .. }
            | RpcMessage::UpdateStatusListResult { .. }
            | RpcMessage::FindNodeResult { .. }
            | RpcMessage::FindValueNodes { .. }
            | RpcMessage::FindValueHit { .. }
            | RpcMessage::FindHashHit { .. }
            | RpcMessage::Received => Self::NoResponse,
        }
    }

    pub(super) fn accepts(self, message: &RpcMessage) -> bool {
        match self {
            Self::Pong => matches!(message, RpcMessage::Pong { .. }),
            Self::StoreResult => matches!(message, RpcMessage::StoreResult { .. }),
            Self::UpdateResult => matches!(message, RpcMessage::UpdateResult { .. }),
            Self::UpdateStatusListResult => {
                matches!(message, RpcMessage::UpdateStatusListResult { .. })
            }
            Self::FindNodeResult => matches!(message, RpcMessage::FindNodeResult { .. }),
            Self::FindValueResult => matches!(
                message,
                RpcMessage::FindValueHit { .. } | RpcMessage::FindValueNodes { .. }
            ),
            Self::FindHashResult => matches!(
                message,
                RpcMessage::FindHashHit { .. } | RpcMessage::FindValueNodes { .. }
            ),
            Self::NoResponse => false,
        }
    }

    /// Whether the request gets a receipt before its answer.
    pub(super) fn after_receipt(self) -> bool {
        matches!(
            self,
            Self::StoreResult | Self::UpdateResult | Self::UpdateStatusListResult
        )
    }

    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Pong => "Pong",
            Self::StoreResult => "StoreResult",
            Self::UpdateResult => "UpdateResult",
            Self::UpdateStatusListResult => "UpdateStatusListResult",
            Self::FindNodeResult => "FindNodeResult",
            Self::FindValueResult => "FindValueHit|FindValueNodes",
            Self::FindHashResult => "FindHashHit|FindValueNodes",
            Self::NoResponse => "no response",
        }
    }
}

pub(super) fn rpc_message_name(message: &RpcMessage) -> &'static str {
    match message {
        RpcMessage::Ping { .. } => "Ping",
        RpcMessage::Pong { .. } => "Pong",
        RpcMessage::Store { .. } => "Store",
        RpcMessage::StoreResult { .. } => "StoreResult",
        RpcMessage::Update { .. } => "Update",
        RpcMessage::UpdateResult { .. } => "UpdateResult",
        RpcMessage::UpdateStatusList { .. } => "UpdateStatusList",
        RpcMessage::UpdateStatusListResult { .. } => "UpdateStatusListResult",
        RpcMessage::FindNode { .. } => "FindNode",
        RpcMessage::FindNodeResult { .. } => "FindNodeResult",
        RpcMessage::FindValue { .. } => "FindValue",
        RpcMessage::FindValueHit { .. } => "FindValueHit",
        RpcMessage::FindValueNodes { .. } => "FindValueNodes",
        RpcMessage::Leave { .. } => "Leave",
        RpcMessage::FindHash { .. } => "FindHash",
        RpcMessage::FindHashHit { .. } => "FindHashHit",
        RpcMessage::Received => "Received",
    }
}

/// The record a request carries, if any. Its answer comes only after the
/// record is handled, so the request gets a receipt first (`Received`).
pub(super) fn carried_record(message: &RpcMessage) -> Option<&[u8]> {
    match message {
        RpcMessage::Store { value, .. }
        | RpcMessage::Update { value, .. }
        | RpcMessage::UpdateStatusList { value, .. } => Some(value),
        RpcMessage::Ping { .. }
        | RpcMessage::Pong { .. }
        | RpcMessage::StoreResult { .. }
        | RpcMessage::UpdateResult { .. }
        | RpcMessage::UpdateStatusListResult { .. }
        | RpcMessage::FindNode { .. }
        | RpcMessage::FindNodeResult { .. }
        | RpcMessage::FindValue { .. }
        | RpcMessage::FindValueNodes { .. }
        | RpcMessage::FindValueHit { .. }
        | RpcMessage::Leave { .. }
        | RpcMessage::FindHash { .. }
        | RpcMessage::FindHashHit { .. }
        | RpcMessage::Received => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::counters::MESSAGE_TYPES;

    use super::*;

    /// One message of each type, in the order of `RpcMessage`. bincode writes
    /// a message as the index of its variant followed by its fields, and zero
    /// bytes decode as the fields of any variant (zero ids, empty vectors,
    /// `None`, the first `StoreStatus`), given enough of them. So this decodes
    /// every variant, including one added later, up to the first index that
    /// is none. It fails if it stops for another reason, such as a variant
    /// whose fields need more zero bytes than given: stopping there would
    /// leave that variant and the later ones out without a sign.
    fn one_message_of_each_type() -> Vec<RpcMessage> {
        let mut messages = Vec::new();
        for index in 0u32.. {
            let mut bytes = index.to_le_bytes().to_vec();
            bytes.extend([0u8; 4096]);
            match bincode::deserialize::<RpcMessage>(&bytes) {
                Ok(message) => messages.push(message),
                Err(error) => {
                    assert!(
                        error.to_string().contains("variant index"),
                        "variant {index} did not decode from zero bytes: {error}"
                    );
                    break;
                }
            }
        }
        messages
    }

    /// The counters count a datagram under `rpc_message_name`, and only the
    /// names in `MESSAGE_TYPES`: a message type missing there is not counted.
    #[test]
    fn every_message_type_is_counted() {
        let mut names: Vec<&str> = one_message_of_each_type()
            .iter()
            .map(rpc_message_name)
            .collect();
        names.sort_unstable();
        let mut counted = MESSAGE_TYPES.to_vec();
        counted.sort_unstable();
        assert_eq!(names, counted);
    }
}
