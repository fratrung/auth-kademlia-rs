//! Helpers shared by the tests of the protocol modules: a verification handler
//! with fixed answers, protocols on loopback sockets, and raw peers that read
//! and send frames.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::auth_handler::{AuthHandlerError, SignatureVerifierHandler};
use crate::fragmentation::{encode_fragments, parse_fragment};
use crate::node::Node;
use crate::protocol::messages::{Frame, RpcMessage};
use crate::protocol::transport::RPC_TIMEOUT;
use crate::signature_cache::SignatureCache;
use crate::storage::ForgetfulStorage;
use crate::utils::ID_LEN;

use super::KademliaProtocol;

pub(super) struct TestHandler {
    pub(super) key_binding_result: bool,
    pub(super) self_signed_result: bool,
    pub(super) issuer_signed_result: bool,
    pub(super) key_binding_calls: AtomicUsize,
    pub(super) self_signed_calls: AtomicUsize,
    pub(super) issuer_signed_calls: AtomicUsize,
}

impl TestHandler {
    pub(super) fn new(self_signed_result: bool, issuer_signed_result: bool) -> Self {
        Self {
            key_binding_result: true,
            self_signed_result,
            issuer_signed_result,
            key_binding_calls: AtomicUsize::new(0),
            self_signed_calls: AtomicUsize::new(0),
            issuer_signed_calls: AtomicUsize::new(0),
        }
    }

    pub(super) fn with_key_binding_result(mut self, result: bool) -> Self {
        self.key_binding_result = result;
        self
    }
}

impl SignatureVerifierHandler for TestHandler {
    fn handle_key_binding_verification(
        &self,
        _key: &[u8; ID_LEN],
        _value: &[u8],
    ) -> Result<bool, AuthHandlerError> {
        self.key_binding_calls.fetch_add(1, Ordering::Relaxed);
        Ok(self.key_binding_result)
    }

    fn handle_signature_verification(&self, _value: &[u8]) -> Result<bool, AuthHandlerError> {
        self.self_signed_calls.fetch_add(1, Ordering::Relaxed);
        Ok(self.self_signed_result)
    }

    fn handle_update_verification(
        &self,
        _value: &[u8],
        _old_value: &[u8],
        _auth_signature: &[u8],
    ) -> Result<bool, AuthHandlerError> {
        Ok(true)
    }

    fn handle_issuer_node_signature_verification(
        &self,
        _value: &[u8],
    ) -> Result<bool, AuthHandlerError> {
        self.issuer_signed_calls.fetch_add(1, Ordering::Relaxed);
        Ok(self.issuer_signed_result)
    }
}

pub(super) async fn test_protocol(
    handler: Arc<dyn SignatureVerifierHandler>,
    use_cache: bool,
) -> Arc<KademliaProtocol> {
    test_protocol_with_storage(handler, use_cache, Arc::new(ForgetfulStorage::new(-1))).await
}

pub(super) async fn test_protocol_with_storage(
    handler: Arc<dyn SignatureVerifierHandler>,
    use_cache: bool,
    storage: Arc<ForgetfulStorage>,
) -> Arc<KademliaProtocol> {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    Arc::new(KademliaProtocol::new(
        Node::from_id([1; ID_LEN]),
        socket,
        storage,
        20,
        3,
        handler,
        use_cache.then(|| Arc::new(SignatureCache::new(32))),
    ))
}

/// Read datagrams and handle them, as a listening node does.
pub(super) fn serve(protocol: &Arc<KademliaProtocol>) {
    let protocol = Arc::clone(protocol);
    tokio::spawn(async move {
        let socket = Arc::clone(&protocol.socket);
        let mut buffer = vec![0u8; 65_536];
        while let Ok((len, from)) = socket.recv_from(&mut buffer).await {
            protocol.handle_datagram(buffer[..len].to_vec(), from).await;
        }
    });
}

/// A node that holds nothing and answers lookups, known to `protocol`, so
/// that a STORE to `protocol` can ask the network.
pub(super) async fn give_answering_contact(protocol: &Arc<KademliaProtocol>, id: [u8; ID_LEN]) {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let port = socket.local_addr().unwrap().port();
    let peer = Arc::new(KademliaProtocol::new(
        contact_at(id, port),
        socket,
        Arc::new(ForgetfulStorage::new(-1)),
        20,
        3,
        Arc::new(TestHandler::new(true, true)),
        None,
    ));
    serve(&peer);
    serve(protocol);
    protocol
        .router
        .write()
        .await
        .add_contact(contact_at(id, port));
}

pub(super) fn contact_at(id: [u8; ID_LEN], port: u16) -> Node {
    Node::new(id, Some("127.0.0.1".to_string()), Some(port))
}

/// A socket standing in for a peer, and the contact that reaches it.
pub(super) async fn raw_peer(id: [u8; ID_LEN]) -> (UdpSocket, Node) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    (socket, contact_at(id, port))
}

/// Next frame that reaches `socket` within `wait`, which must fit in one
/// datagram.
pub(super) async fn try_read_frame(
    socket: &UdpSocket,
    wait: Duration,
) -> Option<(Frame, SocketAddr)> {
    let mut buffer = vec![0u8; 65_536];
    let (len, from) = timeout(wait, socket.recv_from(&mut buffer))
        .await
        .ok()?
        .unwrap();
    let (header, chunk) = parse_fragment(&buffer[..len]).unwrap();
    assert_eq!(header.total, 1, "a test frame must fit in one datagram");
    Some((bincode::deserialize(chunk).unwrap(), from))
}

/// Next frame that reaches `socket`. A test waiting for a frame that never
/// comes fails instead of hanging.
pub(super) async fn read_frame(socket: &UdpSocket) -> (Frame, SocketAddr) {
    try_read_frame(socket, RPC_TIMEOUT + Duration::from_millis(500))
        .await
        .expect("no frame arrived")
}

/// Next frame of `kind` (`true` for a request) that reaches `socket`,
/// skipping the others.
pub(super) async fn read_frame_of_kind(socket: &UdpSocket, request: bool) -> (Frame, SocketAddr) {
    loop {
        let (frame, from) = read_frame(socket).await;
        if frame.is_request == request {
            return (frame, from);
        }
    }
}

pub(super) async fn send_raw(
    socket: &UdpSocket,
    to: SocketAddr,
    msg_id: u32,
    is_request: bool,
    message: RpcMessage,
) {
    let frame = Frame {
        msg_id,
        is_request,
        message,
    };
    for datagram in encode_fragments(msg_id, &bincode::serialize(&frame).unwrap()) {
        socket.send_to(&datagram, to).await.unwrap();
    }
}
