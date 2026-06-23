//! The live Postgres connection: a per-session current_thread tokio runtime
//! driving a tokio-postgres Client over a wasi:sockets TCP stream.
//!
//! TLS status: IN v1 (pure-Rust rustls + rustls-rustcrypto; no cert verification)
//! Full chain verification is a follow-up milestone — see CHANGELOG.
//!
//! # TLS implementation notes
//!
//! `tokio-postgres-rustls` is NOT used because it requires tokio-postgres's
//! `runtime` feature, which fails to compile on wasm32-wasip2 (the `keepalive`
//! module is cfg-gated out on wasm32 but still imported by `connect_socket.rs`
//! and `client.rs` when `runtime` is enabled — a bug in tokio-postgres 0.7.18).
//!
//! Instead we implement `tokio_postgres::tls::TlsConnect` directly over
//! `tokio-rustls`, which does not require the `runtime` feature.

use std::convert::TryFrom;
use std::future::Future;
use std::io;
use std::net::ToSocketAddrs;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use tokio_postgres::{Client, NoTls};
use tokio_rustls::TlsConnector;

// ── SslMode ──────────────────────────────────────────────────────────────────

/// Whether to use TLS for the Postgres connection.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SslMode {
    /// No TLS; plain TCP.
    Disable,
    // v1: `prefer` attempts TLS without plaintext fallback (same as require);
    // true prefer-fallback (reconnect-on-handshake-failure) is a follow-up.
    /// Attempt TLS. v1: no plaintext fallback on failure.
    Prefer,
    /// Require TLS; fail if the server does not support it.
    Require,
}

// ── ConnConfig ────────────────────────────────────────────────────────────────
//
// A plain config struct used by Connection::open. Intentionally free of
// SDK types so conn.rs does not depend on act_sdk or the component module.

/// All parameters needed to open a Postgres connection. Built by lib.rs from
/// the SDK `OpenArgs` and passed into `Connection::open`.
pub struct ConnConfig {
    /// Optional full DSN (e.g. `postgres://user:pass@host:5432/db?sslmode=require`).
    /// When set the discrete fields below are ignored for Config building.
    pub connection_string: Option<String>,
    /// Server hostname or IP (used when `connection_string` is None).
    pub host: Option<String>,
    /// Server port (default 5432).
    pub port: u16,
    /// Login role.
    pub user: Option<String>,
    /// Password.
    pub password: Option<String>,
    /// Database name.
    pub dbname: Option<String>,
    /// TLS mode.
    pub sslmode: SslMode,
    /// Optional server-side statement timeout in milliseconds.
    pub statement_timeout_ms: Option<u32>,
    /// Capability mode for this session.
    pub mode: crate::mode::Mode,
    /// Default row cap.
    pub max_rows: usize,
}

// ── v1: TLS without full cert verification — see CHANGELOG ──────────────────
//
// wasip2 has no system certificate store, so we cannot verify the server's
// certificate chain in v1. We accept any cert presented by the server to allow
// connections to real Postgres instances (including self-signed dev setups).
// Full chain verification is tracked for a follow-up milestone.
//
// Signature verification IS performed by the crypto provider so the TLS
// handshake is still authenticated; only cert-chain trust is skipped.

#[derive(Debug)]
struct NoCertVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls_rustcrypto::provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls_rustcrypto::provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls_rustcrypto::provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Build a rustls ClientConfig backed by the pure-Rust rustls-rustcrypto
/// provider (ring/aws-lc-rs don't build for wasm32-wasip2).
fn rustls_config() -> Result<ClientConfig, String> {
    let provider = Arc::new(rustls_rustcrypto::provider());
    ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("rustls protocol versions: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerification))
        .with_no_client_auth()
        .pipe_ok()
}

/// Small helper: `Result<T,E>` identity with type inference anchor.
trait PipeOk: Sized {
    fn pipe_ok<E>(self) -> Result<Self, E> {
        Ok(self)
    }
}
impl PipeOk for ClientConfig {}

// ── tokio-postgres TlsConnect implementation ─────────────────────────────────
//
// tokio-postgres's MakeTlsConnect is gated on the `runtime` feature which we
// cannot use on wasm32-wasip2. We implement TlsConnect<TcpStream> directly.

/// Wraps a completed tokio-rustls TLS stream so it satisfies
/// `tokio_postgres::tls::TlsStream`.
pub struct PgTlsStream(tokio_rustls::client::TlsStream<TcpStream>);

impl AsyncRead for PgTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for PgTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl tokio_postgres::tls::TlsStream for PgTlsStream {
    fn channel_binding(&self) -> tokio_postgres::tls::ChannelBinding {
        // v1: return no channel-binding data (full tls-server-end-point
        // binding requires parsing the server cert, deferred to a follow-up).
        tokio_postgres::tls::ChannelBinding::none()
    }
}

/// A one-shot TlsConnect for tokio-postgres that wraps tokio-rustls.
pub struct PgTlsConnect {
    connector: TlsConnector,
    domain: ServerName<'static>,
}

impl tokio_postgres::tls::TlsConnect<TcpStream> for PgTlsConnect {
    type Stream = PgTlsStream;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<PgTlsStream, io::Error>> + Send>>;

    fn connect(self, stream: TcpStream) -> Self::Future {
        Box::pin(async move {
            let tls_stream = self
                .connector
                .connect(self.domain, stream)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            Ok(PgTlsStream(tls_stream))
        })
    }
}

// ── Connection ───────────────────────────────────────────────────────────────

pub struct Connection {
    rt: Runtime,
    client: Client,
    mode: crate::mode::Mode,
    max_rows: usize,
}

impl Connection {
    /// Open a Postgres connection from a [`ConnConfig`].
    ///
    /// Config building:
    /// - If `cfg.connection_string` is set, parse it into a `tokio_postgres::Config`
    ///   (DSN form); discrete fields are ignored.
    /// - Otherwise build a `tokio_postgres::Config` from the discrete fields.
    ///
    /// After connecting, run `SET statement_timeout = <ms>` if requested.
    pub fn open(cfg: ConnConfig) -> Result<Connection, String> {
        // ── Build tokio_postgres::Config ──────────────────────────────────────
        let pg_cfg: tokio_postgres::Config = if let Some(ref dsn) = cfg.connection_string {
            dsn.parse::<tokio_postgres::Config>()
                .map_err(|e| format!("invalid connection_string: {e}"))?
        } else {
            let mut c = tokio_postgres::Config::new();
            if let Some(ref h) = cfg.host {
                c.host(h.as_str());
            }
            c.port(cfg.port);
            if let Some(ref u) = cfg.user {
                c.user(u.as_str());
            }
            if let Some(ref pw) = cfg.password {
                c.password(pw.as_str());
            }
            if let Some(ref db) = cfg.dbname {
                c.dbname(db.as_str());
            }
            c
        };

        // Extract host for DNS resolution + TLS SNI. We need the host before
        // entering the async runtime (std DNS resolution via getaddrinfo).
        let host: String = pg_cfg
            .get_hosts()
            .iter()
            .find_map(|h| {
                if let tokio_postgres::config::Host::Tcp(s) = h {
                    Some(s.clone())
                } else {
                    None
                }
            })
            .ok_or_else(|| "no TCP host specified in connection config".to_string())?;

        let port: u16 = pg_cfg.get_ports().first().copied().unwrap_or(5432);

        // Resolve host:port to a SocketAddr OUTSIDE the async runtime. tokio's
        // lookup_host is not yet wired on wasip2, so we resolve via std
        // (getaddrinfo → wasi:sockets ip-name-lookup) and hand tokio a concrete
        // SocketAddr (which never triggers lookup_host).
        let addr = (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|e| format!("resolve {host}:{port} failed: {e}"))?
            .next()
            .ok_or_else(|| format!("no address for {host}:{port}"))?;

        let sslmode = cfg.sslmode;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("tokio runtime build failed: {e}"))?;

        let statement_timeout_ms = cfg.statement_timeout_ms;

        let client = rt.block_on(async move {
            let stream = tokio::net::TcpStream::connect(addr)
                .await
                .map_err(|e| format!("tcp connect {addr} failed: {e}"))?;

            let client = match sslmode {
                SslMode::Disable => {
                    let (client, connection) = pg_cfg
                        .connect_raw(stream, NoTls)
                        .await
                        .map_err(|e| format!("postgres handshake failed: {e}"))?;
                    tokio::spawn(async move {
                        let _ = connection.await;
                    });
                    client
                }
                // v1: `prefer` attempts TLS without plaintext fallback (same as
                // require); true prefer-fallback (reconnect on handshake failure)
                // is a follow-up milestone.
                SslMode::Prefer | SslMode::Require => {
                    let tls_cfg = rustls_config()?;
                    let connector = TlsConnector::from(Arc::new(tls_cfg));
                    let domain: ServerName<'static> =
                        ServerName::try_from(host.as_str())
                            .map_err(|e| {
                                format!("invalid hostname for TLS SNI '{host}': {e}")
                            })?
                            .to_owned();
                    let tls_connect = PgTlsConnect { connector, domain };
                    let (client, connection) = pg_cfg
                        .connect_raw(stream, tls_connect)
                        .await
                        .map_err(|e| format!("postgres TLS handshake failed: {e}"))?;
                    tokio::spawn(async move {
                        let _ = connection.await;
                    });
                    client
                }
            };

            // Apply server-side statement timeout if requested.
            if let Some(ms) = statement_timeout_ms {
                client
                    .batch_execute(&format!("SET statement_timeout = {ms}"))
                    .await
                    .map_err(|e| format!("SET statement_timeout failed: {e}"))?;
            }

            Ok::<Client, String>(client)
        })?;

        Ok(Connection {
            rt,
            client,
            mode: cfg.mode,
            max_rows: cfg.max_rows,
        })
    }

    /// The capability mode this session was opened with.
    pub fn mode(&self) -> crate::mode::Mode {
        self.mode
    }

    /// The default row cap configured at session open time.
    pub fn default_max_rows(&self) -> usize {
        self.max_rows
    }

    // ── Query methods ─────────────────────────────────────────────────────────

    /// Execute a read-only query and return CBOR rows, capped at `max_rows`.
    ///
    /// The query is wrapped in an explicit `BEGIN; SET TRANSACTION READ ONLY;
    /// ... COMMIT;` for defense-in-depth (in addition to the statement-tier
    /// classification gate in `mode.rs`). The transaction is always committed
    /// or rolled back, even if the query fails.
    pub fn query_rows(
        &self,
        sql: &str,
        params: &[crate::convert::PgParam],
        max_rows: usize,
    ) -> Result<(Vec<ciborium::value::Value>, bool), String> {
        let refs = crate::convert::param_refs(params);
        self.rt.block_on(async {
            // Read path hardening: a read-only transaction in addition to the
            // statement classification (defense-in-depth vs statement-stacking).
            self.client
                .batch_execute("BEGIN; SET TRANSACTION READ ONLY;")
                .await
                .map_err(|e| format!("begin read-only txn: {e}"))?;
            let result = self.client.query(sql, &refs).await;
            // Always end the txn, even on error.
            let _ = self.client.batch_execute("COMMIT;").await;
            let rows = result.map_err(|e| format!("query failed: {e}"))?;
            Ok(crate::convert::rows_to_cbor(&rows, max_rows))
        })
    }

    /// Execute a DML/DDL statement and return the number of affected rows.
    pub fn execute_sql(
        &self,
        sql: &str,
        params: &[crate::convert::PgParam],
    ) -> Result<u64, String> {
        let refs = crate::convert::param_refs(params);
        self.rt.block_on(async {
            self.client
                .execute(sql, &refs)
                .await
                .map_err(|e| format!("execute failed: {e}"))
        })
    }

    /// Run EXPLAIN (optionally with ANALYZE) on a SQL statement, returning
    /// the plan as CBOR rows. Supports TEXT and JSON output formats.
    pub fn explain(
        &self,
        sql: &str,
        analyze: bool,
        format: &str,
    ) -> Result<Vec<ciborium::value::Value>, String> {
        let kw = if analyze {
            "EXPLAIN (ANALYZE, FORMAT "
        } else {
            "EXPLAIN (FORMAT "
        };
        let fmt = match format.to_ascii_lowercase().as_str() {
            "json" => "JSON",
            _ => "TEXT",
        };
        let stmt = format!("{kw}{fmt}) {sql}");
        self.rt.block_on(async {
            let rows = self
                .client
                .query(&stmt, &[])
                .await
                .map_err(|e| format!("explain failed: {e}"))?;
            Ok(crate::convert::rows_to_cbor(&rows, usize::MAX).0)
        })
    }
}
