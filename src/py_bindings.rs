//! Python bindings for the AuthKademlia DHT server.
//!
//! Exposes the high-level [`Server`] struct as a Python class named `Server`
//! inside the `authkademlia_rs` module.
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
//!     # Store a signed DID record (bytes)
//!     ok = await node.set("my-did-uuid", signed_record_bytes)
//!
//!     # Retrieve it from any node in the network
//!     record = await node.get("my-did-uuid")   # bytes or None
//!
//!     await node.stop()
//!
//! asyncio.run(main())
//! ```

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use tokio::sync::RwLock;

use crate::auth_handler::{DIDSignatureVerifierHandler, SignatureVerifierHandler};
use crate::crypto::key_manager::{
    DilithiumKeyManager, Ed25519KeyManager, KeyManager, KeyManagerError, KyberKeyManager,
};
use crate::network::Server;

fn km_err(e: KeyManagerError) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

/// Async DHT server exposed to Python.
///
/// Internally wraps [`Server`] behind an `Arc<RwLock<…>>`:
/// - Methods that mutate the server state (`listen`, `stop`,
///   `save_state_regularly`) acquire an exclusive write lock.
/// - All other methods (`get`, `set`, `update`, `delete`, `bootstrap`, …)
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
    ///     issuer_path (str):  Path to the issuer node's raw Dilithium public key
    ///                         file.  Required only for status-list key
    ///                         verification; pass ``None`` to skip issuer checks
    ///                         (self-signed DID records still work).
    ///     node_id (bytes):    Fixed 20-byte node ID.  Pass ``None`` for a
    ///                         random ID (recommended for most deployments).
    #[new]
    #[pyo3(signature = (ksize=20, alpha=3, issuer_path=None, node_id=None, sig_cache=false))]
    fn new(
        ksize: usize,
        alpha: usize,
        issuer_path: Option<String>,
        node_id: Option<Vec<u8>>,
        sig_cache: bool,
    ) -> PyResult<Self> {
        // When issuer_path is None we pass an empty PathBuf.  The DID handler
        // lazy-loads the key only for status-list verification; all other
        // operations (self-signed DID records) work without it.
        let path = issuer_path
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(""));

        let handler: Arc<dyn SignatureVerifierHandler + Send + Sync> =
            Arc::new(DIDSignatureVerifierHandler::new(path));

        let fixed_id: Option<[u8; 20]> = match node_id {
            Some(ref v) if v.len() == 20 => {
                let mut arr = [0u8; 20];
                arr.copy_from_slice(v);
                Some(arr)
            }
            Some(ref v) => {
                return Err(PyRuntimeError::new_err(format!(
                    "node_id must be exactly 20 bytes, got {}",
                    v.len()
                )))
            }
            None => None,
        };

        let server = Server::new(handler, ksize, alpha, fixed_id, None, sig_cache);
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

    /// Look up ``key`` in the DHT.
    ///
    /// Checks local storage first, then performs an iterative network lookup.
    /// The signature embedded in the stored record is verified before returning.
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

    /// Store ``value`` under ``key`` in the DHT.
    ///
    /// The record is rejected if the key already exists or if the signature
    /// embedded in ``value`` does not verify against its own DID Document.
    ///
    /// ``value`` must follow the AuthKademlia record format:
    ///
    /// ```text
    /// algorithm (12 bytes, null-padded) | signature | DID Document JSON
    /// ```
    ///
    /// Returns:
    ///     bool | None: ``True`` on success, ``None`` if rejected.
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

    /// Update an existing record (DID key-rotation flow).
    ///
    /// ``auth_signature`` must be a signature of the full ``value`` bytes
    /// produced with the **old** DID Document's private key.  This proves
    /// that the owner of the current record authorises the rotation.
    /// ``value`` must also carry a valid self-signature under the **new** key.
    ///
    /// For the special status-list key, pass ``auth_signature=None``; the
    /// issuer signature embedded in ``value`` is used instead.
    ///
    /// Returns:
    ///     bool | None: ``True`` on success, ``None`` if rejected.
    fn update<'py>(
        &self,
        py: Python<'py>,
        key: String,
        value: Vec<u8>,
        auth_signature: Option<Vec<u8>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            // Read lock: same rationale as set — Server::update takes &self and
            // delegates all storage mutations to the internal RwLock<ForgetfulStorage>.
            let s = inner.read().await;
            Ok(s.update(&key, value, auth_signature).await)
        })
    }

    /// Delete an existing record.
    ///
    /// ``auth_signature`` must be a signature of ``delete_msg`` produced with
    /// the private key corresponding to the stored DID Document's public key.
    ///
    /// Returns:
    ///     bool | None: ``True`` on success, ``None`` if the key was not found
    ///     or the signature was invalid.
    fn delete<'py>(
        &self,
        py: Python<'py>,
        key: String,
        auth_signature: Vec<u8>,
        delete_msg: Vec<u8>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            // Read lock: same rationale as set — Server::delete takes &self and
            // delegates all storage mutations to the internal RwLock<ForgetfulStorage>.
            let s = inner.read().await;
            Ok(s.delete(&key, auth_signature, delete_msg).await)
        })
    }

    /// Gracefully shut down the node.
    ///
    /// Notifies all known neighbours via Leave RPCs, then cancels background
    /// refresh and save tasks.
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

/// CRYSTALS-Dilithium key manager exposed to Python.
///
/// Args:
///     keys_dir (str): Directory where ``.public`` / ``.private`` files are stored.
///     security_level (int): 2, 3, or 5.
#[pyclass(name = "DilithiumKeyManager")]
pub struct PyDilithiumKeyManager {
    inner: DilithiumKeyManager,
}

#[pymethods]
impl PyDilithiumKeyManager {
    #[new]
    fn new(keys_dir: String, security_level: u8) -> Self {
        Self {
            inner: DilithiumKeyManager::new(PathBuf::from(keys_dir), security_level),
        }
    }

    /// Generate a fresh ``(public_key, private_key)`` pair.
    ///
    /// Args:
    ///     security_level (int | None): Override the instance level (2, 3, or 5).
    ///                                  If omitted, the level set at construction is used.
    #[pyo3(signature = (security_level=None))]
    fn generate_keypair<'py>(
        &self,
        py: Python<'py>,
        security_level: Option<u8>,
    ) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
        let level = security_level.unwrap_or(self.inner.security_level);
        DilithiumKeyManager::new(self.inner.keys_dir.clone(), level)
            .generate_keypair()
            .map(|(pk, sk)| (PyBytes::new_bound(py, &pk), PyBytes::new_bound(py, &sk)))
            .map_err(km_err)
    }

    fn store_public_key(&self, key_name: String, public_key: Vec<u8>) -> PyResult<()> {
        self.inner
            .store_public_key(&key_name, &public_key)
            .map_err(km_err)
    }

    fn store_private_key(&self, key_name: String, private_key: Vec<u8>) -> PyResult<()> {
        self.inner
            .store_private_key(&key_name, &private_key)
            .map_err(km_err)
    }

    fn get_public_key<'py>(&self, py: Python<'py>, key_name: String) -> PyResult<Bound<'py, PyBytes>> {
        self.inner.get_public_key(&key_name)
            .map(|v| PyBytes::new_bound(py, &v))
            .map_err(km_err)
    }

    fn get_private_key<'py>(&self, py: Python<'py>, key_name: String) -> PyResult<Bound<'py, PyBytes>> {
        self.inner.get_private_key(&key_name)
            .map(|v| PyBytes::new_bound(py, &v))
            .map_err(km_err)
    }

    /// Return a JWK-style ``dict`` for ``public_key``.
    fn get_jose_format(&self, public_key: Vec<u8>) -> HashMap<String, String> {
        self.inner.get_jose_format(&public_key)
    }

    /// Sign ``message`` with ``private_key``. Returns raw signature bytes.
    fn sign<'py>(&self, py: Python<'py>, private_key: Vec<u8>, message: Vec<u8>) -> PyResult<Bound<'py, PyBytes>> {
        self.inner.sign(&private_key, &message)
            .map(|v| PyBytes::new_bound(py, &v))
            .map_err(km_err)
    }

    /// Verify ``signature`` over ``message`` against ``public_key``.
    fn verify_signature(
        &self,
        public_key: Vec<u8>,
        message: Vec<u8>,
        signature: Vec<u8>,
    ) -> PyResult<bool> {
        self.inner
            .verify_signature(&public_key, &message, &signature)
            .map_err(km_err)
    }
}

/// CRYSTALS-Kyber key manager exposed to Python.
///
/// Kyber is a KEM (Key Encapsulation Mechanism), not a signature scheme.
///
/// Args:
///     keys_dir (str): Directory for key files.
///     security_level (int): 512, 768, or 1024.
#[pyclass(name = "KyberKeyManager")]
pub struct PyKyberKeyManager {
    inner: KyberKeyManager,
}

#[pymethods]
impl PyKyberKeyManager {
    #[new]
    fn new(keys_dir: String, security_level: u16) -> Self {
        Self {
            inner: KyberKeyManager::new(PathBuf::from(keys_dir), security_level),
        }
    }

    /// Args:
    ///     security_level (int | None): Override the instance level (512, 768, or 1024).
    #[pyo3(signature = (security_level=None))]
    fn generate_keypair<'py>(
        &self,
        py: Python<'py>,
        security_level: Option<u16>,
    ) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
        let level = security_level.unwrap_or(self.inner.security_level);
        KyberKeyManager::new(self.inner.keys_dir.clone(), level)
            .generate_keypair()
            .map(|(pk, sk)| (PyBytes::new_bound(py, &pk), PyBytes::new_bound(py, &sk)))
            .map_err(km_err)
    }

    fn store_public_key(&self, key_name: String, public_key: Vec<u8>) -> PyResult<()> {
        self.inner
            .store_public_key(&key_name, &public_key)
            .map_err(km_err)
    }

    fn store_private_key(&self, key_name: String, private_key: Vec<u8>) -> PyResult<()> {
        self.inner
            .store_private_key(&key_name, &private_key)
            .map_err(km_err)
    }

    fn get_public_key<'py>(&self, py: Python<'py>, key_name: String) -> PyResult<Bound<'py, PyBytes>> {
        self.inner.get_public_key(&key_name)
            .map(|v| PyBytes::new_bound(py, &v))
            .map_err(km_err)
    }

    fn get_private_key<'py>(&self, py: Python<'py>, key_name: String) -> PyResult<Bound<'py, PyBytes>> {
        self.inner.get_private_key(&key_name)
            .map(|v| PyBytes::new_bound(py, &v))
            .map_err(km_err)
    }

    fn get_jose_format(&self, public_key: Vec<u8>) -> HashMap<String, String> {
        self.inner.get_jose_format(&public_key)
    }
}

/// Ed25519 key manager exposed to Python.
///
/// Args:
///     keys_dir (str): Directory for key files.
#[pyclass(name = "Ed25519KeyManager")]
pub struct PyEd25519KeyManager {
    inner: Ed25519KeyManager,
}

#[pymethods]
impl PyEd25519KeyManager {
    #[new]
    fn new(keys_dir: String) -> Self {
        Self {
            inner: Ed25519KeyManager::new(PathBuf::from(keys_dir)),
        }
    }

    fn generate_keypair<'py>(&self, py: Python<'py>) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
        self.inner.generate_keypair()
            .map(|(pk, sk)| (PyBytes::new_bound(py, &pk), PyBytes::new_bound(py, &sk)))
            .map_err(km_err)
    }

    fn store_public_key(&self, key_name: String, public_key: Vec<u8>) -> PyResult<()> {
        self.inner
            .store_public_key(&key_name, &public_key)
            .map_err(km_err)
    }

    fn store_private_key(&self, key_name: String, private_key: Vec<u8>) -> PyResult<()> {
        self.inner
            .store_private_key(&key_name, &private_key)
            .map_err(km_err)
    }

    fn get_public_key<'py>(&self, py: Python<'py>, key_name: String) -> PyResult<Bound<'py, PyBytes>> {
        self.inner.get_public_key(&key_name)
            .map(|v| PyBytes::new_bound(py, &v))
            .map_err(km_err)
    }

    fn get_private_key<'py>(&self, py: Python<'py>, key_name: String) -> PyResult<Bound<'py, PyBytes>> {
        self.inner.get_private_key(&key_name)
            .map(|v| PyBytes::new_bound(py, &v))
            .map_err(km_err)
    }

    fn get_jose_format(&self, public_key: Vec<u8>) -> HashMap<String, String> {
        self.inner.get_jose_format(&public_key)
    }

    fn sign<'py>(&self, py: Python<'py>, private_key: Vec<u8>, message: Vec<u8>) -> PyResult<Bound<'py, PyBytes>> {
        self.inner.sign(&private_key, &message)
            .map(|v| PyBytes::new_bound(py, &v))
            .map_err(km_err)
    }

    fn verify_signature(
        &self,
        public_key: Vec<u8>,
        message: Vec<u8>,
        signature: Vec<u8>,
    ) -> PyResult<bool> {
        self.inner
            .verify_signature(&public_key, &message, &signature)
            .map_err(km_err)
    }
}

/// Initialise the Tokio runtime with a bounded blocking thread pool.
///
/// Must be called **once** before creating any ``Server`` instance, ideally at
/// the very start of ``main()`` or the application entry point.
///
/// Without this call, ``pyo3-async-runtimes`` creates a default runtime with
/// ``max_blocking_threads = 512``, which causes excessive context switching
/// during Dilithium verifications (CPU-bound ``spawn_blocking`` tasks) on
/// constrained hardware with few physical cores.
///
/// After calling this, ``max_blocking_threads`` equals the number of physical
/// cores reported by the OS — optimal for Dilithium parallelism on edge nodes.
#[pyfunction]
fn init_runtime() {
    let parallelism = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(2);

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.max_blocking_threads(parallelism).enable_all();
    pyo3_async_runtimes::tokio::init(builder);
}

/// Python module entry point.
///
/// The function name **must** match the desired module name so that Python
/// finds the ``PyInit_authkademlia_py`` symbol when importing.
/// maturin is configured with ``module-name = "authkademlia_py"`` in
/// ``pyproject.toml`` to produce the correctly-named ``.so`` file.
#[pymodule]
fn authkademlia_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(init_runtime, m)?)?;
    m.add_class::<PyServer>()?;
    m.add_class::<PyDilithiumKeyManager>()?;
    m.add_class::<PyKyberKeyManager>()?;
    m.add_class::<PyEd25519KeyManager>()?;
    Ok(())
}
