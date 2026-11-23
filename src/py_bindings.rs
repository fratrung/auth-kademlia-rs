//! Python bindings for the AuthKademlia DHT server.
//!
//! Exposes the high-level [`Server`] struct as a Python class named `Server`
//! inside the `authkademlia_py` module.
//!
//! # Build
//! ```bash
//! pip install maturin
//! maturin develop --features python   # editable install (development)
//! maturin build   --features python   # build wheel
//! ```
//!
//! # Usage (Python)
//! ```python
//! import asyncio
//! import authkademlia_py
//!
//! async def main():
//!     node = authkademlia_py.Server(ksize=20, alpha=3, issuer_path="issuer.bin")
//!     await node.listen(5678, "127.0.0.1")
//!
//!     # Bootstrap from a known peer
//!     peers = await node.bootstrap([("192.168.1.10", 5678)])
//!
//!     # Publish a DID record (bytes), at any position, under its DID
//!     # ("did:iiot:" + base64url of the SHA-256 of its genesis)
//!     ok = await node.set(did, signed_record_bytes)
//!
//!     # Retrieve it from any node in the network
//!     record = await node.get(did)   # bytes or None
//!
//!     await node.stop()
//!
//! asyncio.run(main())
//! ```

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Once};
use std::time::Duration;

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use tokio::sync::RwLock;

use crate::auth_handler::{DIDSignatureVerifierHandler, SignatureVerifierHandler};
use crate::crypto::key_manager::{
    KeyManager, KeyManagerError, MlDsaKeyManager, MlKemKeyManager, EPHEMERAL_KEY_MAX_AGE,
    MAX_EPHEMERAL_KEYS,
};
use crate::network::{Server, ServerStats, SetOutcome, SetRejection, SetReport};
use crate::storage::{ForgetfulStorage, DEFAULT_TTL};
use crate::utils::ID_LEN;

static PY_RUNTIME_INIT: Once = Once::new();

fn configure_runtime() {
    PY_RUNTIME_INIT.call_once(|| {
        let parallelism = std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(2);

        let mut builder = tokio::runtime::Builder::new_multi_thread();
        builder.max_blocking_threads(parallelism).enable_all();
        pyo3_async_runtimes::tokio::init(builder);
    });
}

fn rejection_name(reason: SetRejection) -> &'static str {
    match reason {
        SetRejection::ExistingRecord => "existing_record",
        SetRejection::InvalidRecord => "invalid_record",
        SetRejection::ReplicaConflict => "replica_conflict",
        SetRejection::CapacityExceeded => "capacity_exceeded",
        SetRejection::Unavailable => "unavailable",
        SetRejection::NoResponsibleNodes => "no_responsible_nodes",
        SetRejection::NewerVersion => "newer_version",
    }
}

fn set_report_to_py<'py>(py: Python<'py>, report: &SetReport) -> PyResult<Bound<'py, PyDict>> {
    let result = PyDict::new_bound(py);
    result.set_item("expected_replicas", report.expected_replicas)?;
    result.set_item("stored_replicas", report.stored_replicas)?;
    result.set_item("already_present", report.already_present)?;
    result.set_item("acknowledged_replicas", report.acknowledged_replicas())?;
    result.set_item("capacity_rejections", report.capacity_rejections)?;
    result.set_item("unavailable_nodes", report.unavailable_nodes)?;
    result.set_item("conflict_rejections", report.conflict_rejections)?;
    result.set_item("invalid_rejections", report.invalid_rejections)?;
    result.set_item("stale_rejections", report.stale_rejections)?;
    result.set_item("unproven_refusals", report.unproven_refusals)?;
    Ok(result)
}

fn set_outcome_to_py(py: Python<'_>, outcome: SetOutcome) -> PyResult<PyObject> {
    let result = PyDict::new_bound(py);
    let (status, rejection) = match &outcome {
        SetOutcome::Complete(_) => ("complete", None),
        SetOutcome::Degraded(_) => ("degraded", None),
        SetOutcome::Rejected { reason, .. } => ("rejected", Some(rejection_name(*reason))),
    };

    result.set_item("status", status)?;
    result.set_item("reason", rejection)?;
    result.set_item("report", set_report_to_py(py, outcome.report())?)?;
    Ok(result.into_py(py))
}

fn server_stats_to_py(py: Python<'_>, stats: ServerStats) -> PyResult<PyObject> {
    let result = PyDict::new_bound(py);
    result.set_item("node_id", PyBytes::new_bound(py, &stats.node_id))?;
    result.set_item("listening", stats.listening)?;
    result.set_item("routing_nodes", stats.routing_nodes)?;
    result.set_item("live_routing_nodes", stats.live_routing_nodes)?;
    result.set_item("storage_records", stats.storage_records)?;
    result.set_item("storage_bytes", stats.storage_bytes)?;
    result.set_item("max_storage_bytes", stats.max_storage_bytes)?;
    result.set_item(
        "available_storage_bytes",
        stats.max_storage_bytes.saturating_sub(stats.storage_bytes),
    )?;
    result.set_item("signature_cache_entries", stats.signature_cache_entries)?;
    Ok(result.into_py(py))
}

fn km_err(e: KeyManagerError) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

/// Async DHT server exposed to Python.
///
/// Internally wraps [`Server`] behind an `Arc<RwLock<…>>`:
/// - Methods that mutate the server state (`listen`, `stop`,
///   `save_state_regularly`) acquire an exclusive write lock.
/// - All other methods (`get`, `set`, `update_status_list`, `bootstrap`, …)
///   acquire a shared read lock, so they can run concurrently.
///
/// Every method returns a Python coroutine — use `await` in async Python code.
#[pyclass(name = "Server")]
pub struct PyServer {
    inner: Arc<RwLock<Server>>,
}

#[pymethods]
impl PyServer {
    /// Create a new DHT server (does **not** open a socket yet — call `listen`).
    ///
    /// Args:
    ///     ksize (int):        Kademlia k parameter (bucket size). Default: 20.
    ///     alpha (int):        Concurrency factor for iterative lookups. Default: 3.
    ///     issuer_path (str):  Path to the issuer node's raw ML-DSA-65 public key
    ///                         file.  Required only for status-list key
    ///                         verification; pass ``None`` to skip issuer checks
    ///                         (self-signed DID records still work).
    ///     node_id (bytes):    Fixed 32-byte node ID.  Pass ``None`` for a
    ///                         random ID (recommended for most deployments).
    ///     max_storage_bytes (int): Per-node key/value budget. Default: 512 MiB.
    ///     data_dir (str):     Directory where this replica keeps its records,
    ///                         so that it serves them again after a restart.
    ///                         ``None`` (default) keeps them in memory only.
    ///     flush_secs (int):   With ``data_dir``, how often renewed expiries
    ///                         are written to disk. Default: 3600.
    ///
    /// Raises:
    ///     RuntimeError: ``data_dir`` cannot be created or read.
    #[new]
    #[pyo3(signature = (
        ksize=20,
        alpha=3,
        issuer_path=None,
        node_id=None,
        sig_cache=false,
        max_storage_bytes=536_870_912,
        data_dir=None,
        flush_secs=3600
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        ksize: usize,
        alpha: usize,
        issuer_path: Option<String>,
        node_id: Option<Vec<u8>>,
        sig_cache: bool,
        max_storage_bytes: usize,
        data_dir: Option<String>,
        flush_secs: u64,
    ) -> PyResult<Self> {
        configure_runtime();

        // When issuer_path is None we pass an empty PathBuf.  The DID handler
        // lazy-loads the key only for status-list verification; all other
        // operations (self-signed DID records) work without it.
        let path = issuer_path
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(""));

        let handler: Arc<dyn SignatureVerifierHandler + Send + Sync> =
            Arc::new(DIDSignatureVerifierHandler::new(path));

        let fixed_id: Option<[u8; ID_LEN]> = match node_id {
            Some(ref v) if v.len() == ID_LEN => {
                let mut arr = [0u8; ID_LEN];
                arr.copy_from_slice(v);
                Some(arr)
            }
            Some(ref v) => {
                return Err(PyRuntimeError::new_err(format!(
                    "node_id must be exactly {ID_LEN} bytes, got {}",
                    v.len()
                )))
            }
            None => None,
        };

        let storage = match data_dir {
            Some(dir) => ForgetfulStorage::persistent(&dir, DEFAULT_TTL, max_storage_bytes)
                .map_err(|e| PyRuntimeError::new_err(format!("data_dir {dir}: {e}")))?,
            None => ForgetfulStorage::with_max_storage_bytes(DEFAULT_TTL, max_storage_bytes),
        }
        .with_flush_interval(Duration::from_secs(flush_secs));
        let server = Server::new(
            handler,
            ksize,
            alpha,
            fixed_id,
            Some(Arc::new(storage)),
            sig_cache,
        );
        Ok(Self {
            inner: Arc::new(RwLock::new(server)),
        })
    }

    /// Bind to ``interface:port`` and start the UDP receive loop.
    ///
    /// Must be called before any other network operation.
    /// Raises ``RuntimeError`` on bind failure (e.g. port already in use).
    fn listen<'py>(&self, py: Python<'py>, port: u16, host: String) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            inner
                .write()
                .await
                .listen(port, &host)
                .await
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            Ok(())
        })
    }

    /// Bootstrap the node by contacting a list of known peers.
    ///
    /// Args:
    ///     addrs (list[tuple[str, int]]): Seed peers as ``[(ip, port), …]``.
    ///
    /// Returns:
    ///     list[tuple[str, int]]: Addresses of nodes discovered during the
    ///     initial lookup (may be empty if no peer is reachable).
    fn bootstrap<'py>(
        &self,
        py: Python<'py>,
        addrs: Vec<(String, u16)>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let s = inner.read().await;
            let nodes = s.bootstrap(addrs).await;
            let peers: Vec<(String, u16)> = nodes.into_iter().filter_map(|n| n.address()).collect();
            Ok(peers)
        })
    }

    /// Look up ``key``, a DID, in the DHT.
    ///
    /// A record held locally is returned without asking the network;
    /// otherwise an iterative lookup returns the first record whose key is
    /// the one its DID commits to and whose signature verifies. It may be a
    /// superseded position: when it fails the caller's check, ``repair``
    /// fetches the one the credential names.
    ///
    /// Returns:
    ///     bytes | None: Raw record bytes, or ``None`` if not found / invalid.
    fn get<'py>(&self, py: Python<'py>, key: String) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let s = inner.read().await;
            let result = s.get(&key).await;
            Python::with_gil(|py| -> PyResult<Option<PyObject>> {
                Ok(result.map(|v| PyBytes::new_bound(py, &v).into_py(py)))
            })
        })
    }

    /// Repair the record of ``did`` that this node served, ``failed_record``,
    /// once it has failed the caller's check: look in the network for the
    /// record at position ``seq`` whose raw public key has SHA-256
    /// ``key_hash``, as the caller's credential names them, and store it
    /// here, where it replaces ``failed_record`` and the next ``get`` serves
    /// it without asking the network.
    ///
    /// ``seq`` must be above the position of ``failed_record``. The lookup
    /// gives up after a few seconds. A verified record above ``seq`` met on
    /// the way supersedes the expected one, which is then refused.
    ///
    /// Returns:
    ///     bytes | None: The expected record, now stored here, or ``None``
    ///     when none was found or this node holds a higher position.
    ///
    /// Raises:
    ///     ValueError: ``key_hash`` is not 32 bytes long.
    fn repair<'py>(
        &self,
        py: Python<'py>,
        did: String,
        failed_record: Vec<u8>,
        seq: u64,
        key_hash: Vec<u8>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let key_hash: [u8; ID_LEN] = key_hash
            .try_into()
            .map_err(|_| PyValueError::new_err(format!("key_hash must be {ID_LEN} bytes")))?;
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let s = inner.read().await;
            let result = s.repair(&did, &failed_record, seq, &key_hash).await;
            Python::with_gil(|py| -> PyResult<Option<PyObject>> {
                Ok(result.map(|v| PyBytes::new_bound(py, &v).into_py(py)))
            })
        })
    }

    /// Publish a DID record, ``value``, at any position, under its DID
    /// ``key``. A first publication and every rotation use this call.
    ///
    /// The record is rejected if its key and code are not those of its
    /// position in the tree the DID commits to, if its signature does not
    /// verify, or once a replica shows a higher position or another record
    /// at the same position.
    ///
    /// ``value`` must follow the AuthKademlia record format:
    ///
    /// ```text
    /// algorithm (12 bytes, null-padded) | signature | DID Document JSON
    /// ```
    ///
    /// Returns:
    ///     bool | None: ``True`` when all discovered responsible replicas
    ///     acknowledge the record, ``False`` for a degraded/unavailable
    ///     publication, or ``None`` for an invalid/conflicting record.
    fn set<'py>(
        &self,
        py: Python<'py>,
        key: String,
        value: Vec<u8>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            // Read lock: Server::set takes &self and is internally thread-safe via
            // DashMap in ForgetfulStorage. The lock here only prevents concurrent
            // listen/stop (write-lock) calls from racing with network operations.
            let s = inner.read().await;
            Ok(s.set(&key, value).await)
        })
    }

    /// Publish a record at any position, as ``set``, and return exact
    /// replica-level publication details.
    ///
    /// Returns:
    ///     dict: ``status`` is ``complete``, ``degraded``, or ``rejected``;
    ///     ``reason`` is set for rejected publications (``existing_record``
    ///     when a replica shows another valid record at the same position,
    ///     ``newer_version`` when one shows a valid higher position,
    ///     ``replica_conflict`` when nothing was stored and replicas refused
    ///     without showing why); ``report`` contains expected, acknowledged,
    ///     unavailable, conflicting, invalid, stale and capacity-rejected
    ///     replica counts, and ``unproven_refusals``, the replicas that
    ///     refused without showing a record that proves it.
    fn set_detailed<'py>(
        &self,
        py: Python<'py>,
        key: String,
        value: Vec<u8>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let s = inner.read().await;
            let outcome = s.set_detailed(&key, value).await;
            Python::with_gil(|py| set_outcome_to_py(py, outcome))
        })
    }

    /// Replace the Status List with ``value``, signed by the issuer.
    ///
    /// Returns:
    ///     bool | None: ``True`` when a majority of the replicas took it,
    ///     ``False`` otherwise, ``None`` if no list is published yet or the
    ///     signature fails.
    fn update_status_list<'py>(
        &self,
        py: Python<'py>,
        value: Vec<u8>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let s = inner.read().await;
            Ok(s.update_status_list(value).await)
        })
    }

    /// Gracefully shut down the node.
    ///
    /// Notifies the closest neighbours via Leave RPCs, cancels all background
    /// tasks, and releases the socket. ``listen`` may be called again afterwards.
    fn stop<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            inner.write().await.stop().await;
            Ok(())
        })
    }

    /// Return the addresses of bootstrappable neighbour nodes.
    ///
    /// Returns:
    ///     list[tuple[str, int]]: Known peers as ``[(ip, port), …]``.
    fn bootstrappable_neighbors<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let s = inner.read().await;
            Ok(s.bootstrappable_neighbors().await)
        })
    }

    /// Return routing, storage-capacity, and signature-cache counters.
    fn stats<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let s = inner.read().await;
            let stats = s.stats().await;
            Python::with_gil(|py| server_stats_to_py(py, stats))
        })
    }

    /// Save node state (ksize, alpha, ID, neighbours) to a JSON file.
    ///
    /// A no-op if the routing table is empty.
    fn save_state<'py>(&self, py: Python<'py>, fname: String) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let s = inner.read().await;
            s.save_state(&fname).await;
            Ok(())
        })
    }

    /// Start a background task that saves node state every ``frequency_secs`` seconds.
    ///
    /// Has no effect if ``listen`` has not been called yet.
    fn save_state_regularly<'py>(
        &self,
        py: Python<'py>,
        fname: String,
        frequency_secs: u64,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            // Exclusive lock: save_state_regularly takes &mut self internally.
            inner
                .write()
                .await
                .save_state_regularly(fname, frequency_secs);
            Ok(())
        })
    }
}

/// ML-DSA-65 key manager exposed to Python: the signature of every record.
///
/// Args:
///     keys_dir (str): Directory where ``.public`` / ``.private`` files are stored.
#[pyclass(name = "MlDsaKeyManager")]
pub struct PyMlDsaKeyManager {
    inner: MlDsaKeyManager,
}

#[pymethods]
impl PyMlDsaKeyManager {
    #[new]
    fn new(keys_dir: String) -> Self {
        Self {
            inner: MlDsaKeyManager::new(PathBuf::from(keys_dir)),
        }
    }

    /// Generate a fresh ML-DSA-65 ``(public_key, private_key)`` pair.
    fn generate_keypair<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
        py.allow_threads(|| self.inner.generate_keypair())
            .map(|(pk, sk)| (PyBytes::new_bound(py, &pk), PyBytes::new_bound(py, &sk)))
            .map_err(km_err)
    }

    /// The ML-DSA-65 ``(public_key, private_key)`` pair of a 32-byte
    /// ``seed`` (FIPS 204): the same seed always gives the same pair.
    ///
    /// The application can keep only the seed of a position's key, in a
    /// secure element where the device has one, until the rotation that
    /// reveals it.
    ///
    /// Raises:
    ///     RuntimeError: ``seed`` is not 32 bytes long.
    fn keypair_from_seed<'py>(
        &self,
        py: Python<'py>,
        seed: Vec<u8>,
    ) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
        py.allow_threads(|| self.inner.keypair_from_seed(&seed))
            .map(|(pk, sk)| (PyBytes::new_bound(py, &pk), PyBytes::new_bound(py, &sk)))
            .map_err(km_err)
    }

    fn store_public_key(
        &self,
        py: Python<'_>,
        key_name: String,
        public_key: Vec<u8>,
    ) -> PyResult<()> {
        py.allow_threads(|| self.inner.store_public_key(&key_name, &public_key))
            .map_err(km_err)
    }

    fn store_private_key(
        &self,
        py: Python<'_>,
        key_name: String,
        private_key: Vec<u8>,
    ) -> PyResult<()> {
        py.allow_threads(|| self.inner.store_private_key(&key_name, &private_key))
            .map_err(km_err)
    }

    fn get_public_key<'py>(
        &self,
        py: Python<'py>,
        key_name: String,
    ) -> PyResult<Bound<'py, PyBytes>> {
        py.allow_threads(|| self.inner.get_public_key(&key_name))
            .map(|v| PyBytes::new_bound(py, &v))
            .map_err(km_err)
    }

    fn get_private_key<'py>(
        &self,
        py: Python<'py>,
        key_name: String,
    ) -> PyResult<Bound<'py, PyBytes>> {
        py.allow_threads(|| self.inner.get_private_key(&key_name))
            .map(|v| PyBytes::new_bound(py, &v))
            .map_err(km_err)
    }

    /// Return ``public_key`` as an RFC 9964 JWK ``dict``:
    /// ``{"kty": "AKP", "alg": "ML-DSA-65", "pub": <base64url>}``.
    fn get_jose_format(&self, public_key: Vec<u8>) -> HashMap<String, String> {
        self.inner.get_jose_format(&public_key)
    }

    /// Sign ``message`` with ``private_key``. Returns raw signature bytes.
    fn sign<'py>(
        &self,
        py: Python<'py>,
        private_key: Vec<u8>,
        message: Vec<u8>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        py.allow_threads(|| self.inner.sign(&private_key, &message))
            .map(|v| PyBytes::new_bound(py, &v))
            .map_err(km_err)
    }

    /// Verify ``signature`` over ``message`` against ``public_key``.
    fn verify_signature(
        &self,
        py: Python<'_>,
        public_key: Vec<u8>,
        message: Vec<u8>,
        signature: Vec<u8>,
    ) -> PyResult<bool> {
        py.allow_threads(|| {
            self.inner
                .verify_signature(&public_key, &message, &signature)
        })
        .map_err(km_err)
    }
}

/// ML-KEM-768 with ephemeral keys, for the handshake between devices,
/// outside the DHT. One key pair per handshake, in memory only:
/// no private key is ever returned, stored or read.
///
/// Args:
///     max_age_secs (float): How long a pair given out stays usable (30).
///     max_outstanding (int): How many pairs may be given out at once (64).
#[pyclass(name = "MlKemKeyManager")]
pub struct PyMlKemKeyManager {
    inner: MlKemKeyManager,
}

#[pymethods]
impl PyMlKemKeyManager {
    #[new]
    #[pyo3(signature = (
        max_age_secs = EPHEMERAL_KEY_MAX_AGE.as_secs_f64(),
        max_outstanding = MAX_EPHEMERAL_KEYS
    ))]
    fn new(max_age_secs: f64, max_outstanding: usize) -> PyResult<Self> {
        let max_age = Duration::try_from_secs_f64(max_age_secs)
            .map_err(|_| PyValueError::new_err("max_age_secs must be a non-negative number"))?;
        Ok(Self {
            inner: MlKemKeyManager::with_limits(max_age, max_outstanding),
        })
    }

    /// ``(key_id, public_key)`` of a new key pair, for one handshake.
    fn ephemeral_public_key<'py>(&self, py: Python<'py>) -> PyResult<(u64, Bound<'py, PyBytes>)> {
        py.allow_threads(|| self.inner.ephemeral_public_key())
            .map(|(id, pk)| (id, PyBytes::new_bound(py, &pk)))
            .map_err(km_err)
    }

    /// The shared secret of ``ciphertext`` under the pair ``key_id``, which is
    /// then destroyed. A modified ciphertext gives another secret, not an
    /// error: the handshake finds out when it confirms the key.
    fn decapsulate<'py>(
        &self,
        py: Python<'py>,
        key_id: u64,
        ciphertext: Vec<u8>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        py.allow_threads(|| self.inner.decapsulate(key_id, &ciphertext))
            .map(|secret| PyBytes::new_bound(py, secret.as_bytes()))
            .map_err(km_err)
    }

    /// ``(shared_secret, ciphertext)`` for ``public_key``, the other side of
    /// the handshake.
    #[staticmethod]
    fn encapsulate<'py>(
        py: Python<'py>,
        public_key: Vec<u8>,
    ) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
        py.allow_threads(|| MlKemKeyManager::encapsulate(&public_key))
            .map(|(secret, ciphertext)| {
                (
                    PyBytes::new_bound(py, secret.as_bytes()),
                    PyBytes::new_bound(py, &ciphertext),
                )
            })
            .map_err(km_err)
    }
}

/// Ensure the Tokio runtime uses a bounded blocking thread pool.
///
/// Runtime configuration is automatic at module import and server creation.
/// This function remains as an idempotent compatibility hook for existing
/// applications that already call it explicitly.
#[pyfunction]
fn init_runtime() {
    configure_runtime();
}

/// Python module entry point.
///
/// The function name **must** match the desired module name so that Python
/// finds the ``PyInit_authkademlia_py`` symbol when importing.
/// maturin is configured with ``module-name = "authkademlia_py"`` in
/// ``pyproject.toml`` to produce the correctly-named ``.so`` file.
#[pymodule]
fn authkademlia_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    configure_runtime();
    m.add_function(wrap_pyfunction!(init_runtime, m)?)?;
    m.add_class::<PyServer>()?;
    m.add_class::<PyMlDsaKeyManager>()?;
    m.add_class::<PyMlKemKeyManager>()?;
    Ok(())
}
