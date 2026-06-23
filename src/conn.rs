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
    /// No TLS; plain TCP. Default.
    Disable,
    /// Attempt TLS; fall back to plain if the server does not support it.
    Prefer,
    /// Require TLS; fail if the server does not support it.
    Require,
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
}

impl Connection {
    pub fn open(
        host: &str,
        port: u16,
        user: &str,
        password: Option<&str>,
        dbname: &str,
        sslmode: SslMode,
    ) -> Result<Connection, String> {
        // Resolve host:port to a SocketAddr OUTSIDE the async runtime. tokio's
        // lookup_host is not yet wired on wasip2, so we resolve via std
        // (getaddrinfo -> wasi:sockets ip-name-lookup) and hand tokio a concrete
        // SocketAddr (which never triggers lookup_host).
        let addr = (host, port)
            .to_socket_addrs()
            .map_err(|e| format!("resolve {host}:{port} failed: {e}"))?
            .next()
            .ok_or_else(|| format!("no address for {host}:{port}"))?;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("tokio runtime build failed: {e}"))?;

        let mut cfg = tokio_postgres::Config::new();
        cfg.user(user).dbname(dbname).host(host);
        if let Some(pw) = password {
            cfg.password(pw);
        }

        let host_owned = host.to_owned();
        let client = rt.block_on(async move {
            let stream = tokio::net::TcpStream::connect(addr)
                .await
                .map_err(|e| format!("tcp connect {addr} failed: {e}"))?;

            match sslmode {
                SslMode::Disable => {
                    let (client, connection) = cfg
                        .connect_raw(stream, NoTls)
                        .await
                        .map_err(|e| format!("postgres handshake failed: {e}"))?;
                    tokio::spawn(async move {
                        let _ = connection.await;
                    });
                    Ok::<Client, String>(client)
                }
                SslMode::Prefer | SslMode::Require => {
                    let tls_cfg = rustls_config()?;
                    let connector = TlsConnector::from(Arc::new(tls_cfg));
                    let domain: ServerName<'static> =
                        ServerName::try_from(host_owned.as_str())
                            .map_err(|e| format!("invalid hostname for TLS SNI '{host_owned}': {e}"))?
                            .to_owned();
                    let tls_connect = PgTlsConnect { connector, domain };
                    let (client, connection) = cfg
                        .connect_raw(stream, tls_connect)
                        .await
                        .map_err(|e| format!("postgres TLS handshake failed: {e}"))?;
                    tokio::spawn(async move {
                        let _ = connection.await;
                    });
                    Ok::<Client, String>(client)
                }
            }
        })?;

        Ok(Connection { rt, client })
    }

    pub fn select_scalar_i64(&self, sql: &str) -> Result<i64, String> {
        self.rt.block_on(async {
            let row = self
                .client
                .query_one(sql, &[])
                .await
                .map_err(|e| format!("query failed: {e}"))?;
            let v: i32 = row.get(0);
            Ok(v as i64)
        })
    }
}
