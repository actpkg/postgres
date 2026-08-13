//! The connection *target* (validated at open, secret-free) and the live
//! Postgres connection built from it on the first tool call.
//!
//! Two types, because the credential arrives between them. [`ConnTarget`] is
//! everything a session knows about where to connect, validated while
//! `open-session` is running and holding no credential material.
//! [`Connection`] is the socket, and it cannot exist until the first tool call:
//! `get-secret` requires a session the host has already marked live, and the
//! host does that only after `open-session` returns (ACT-AUTH §1.1.4).
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
use tokio_postgres::config::{Host, SslNegotiation};
use tokio_postgres::error::SqlState;
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

impl SslMode {
    fn to_pg(self) -> tokio_postgres::config::SslMode {
        match self {
            SslMode::Disable => tokio_postgres::config::SslMode::Disable,
            SslMode::Prefer => tokio_postgres::config::SslMode::Prefer,
            SslMode::Require => tokio_postgres::config::SslMode::Require,
        }
    }

    fn from_pg(mode: tokio_postgres::config::SslMode) -> SslMode {
        match mode {
            tokio_postgres::config::SslMode::Disable => SslMode::Disable,
            tokio_postgres::config::SslMode::Require => SslMode::Require,
            // `SslMode` is `#[non_exhaustive]`; `prefer` is both the default
            // and the safe reading of a mode this build does not know.
            _ => SslMode::Prefer,
        }
    }
}

// ── TargetArgs ───────────────────────────────────────────────────────────────
//
// A plain config struct built by lib.rs from the SDK `OpenArgs`. Intentionally
// free of SDK types so conn.rs does not depend on act_sdk or the component
// module — which is also what lets every rule below be driven on the host
// target, where no WIT import can be called.

/// Where to connect, as the session's args asked for it. **Carries no
/// password, and there is no field one could be written into**: the password
/// is fetched from the host credential store on the first tool call.
#[derive(Default)]
pub struct TargetArgs {
    /// A password-free DSN, URL form (`postgres://host:5432/db?...`) or
    /// keyword/value form (`host=db.internal dbname=app`). Mutually exclusive
    /// with `host`/`port`.
    pub connection_string: Option<String>,
    /// Server hostname or IP. Mutually exclusive with `connection_string`.
    pub host: Option<String>,
    /// Server port. `None` means 5432 in the discrete form; with a DSN the
    /// port is the DSN's and this MUST be `None`.
    pub port: Option<u16>,
    /// Login role, overriding both the DSN's `user=` and the credential's
    /// `postgres:user`. Not a credential: a role name authenticates nothing.
    pub user: Option<String>,
    /// Database name, overriding the DSN's `dbname=`.
    pub dbname: Option<String>,
    /// TLS mode, overriding the DSN's `sslmode=`. `None` falls back to the
    /// DSN's, and to `prefer` when the DSN says nothing.
    pub sslmode: Option<SslMode>,
    /// Optional server-side statement timeout in milliseconds.
    pub statement_timeout_ms: Option<u32>,
}

/// A validated, password-free connection target. Built once at open and kept
/// for the session; [`ConnTarget::connect`] pairs it with a credential.
#[derive(Clone)]
pub struct ConnTarget {
    /// Never carries a password — [`ConnTarget::prepare`] refuses one and
    /// [`ConnTarget::connect`] sets it on a clone, which is dropped with the
    /// connection attempt.
    pg: tokio_postgres::Config,
    host: String,
    port: u16,
    sslmode: SslMode,
    statement_timeout_ms: Option<u32>,
}

/// Prints where the target points and nothing else. Not derived: the inner
/// `tokio_postgres::Config` has a `password` field, and while `prepare`
/// guarantees it is empty, a `Debug` that would print it if it were not is a
/// leak waiting for the one code path that sets it.
impl std::fmt::Debug for ConnTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnTarget")
            .field("resource", &self.resource())
            .field("user", &self.user())
            .field("sslmode", &self.sslmode)
            .finish_non_exhaustive()
    }
}

/// Why a connection attempt failed, split by whether re-fetching the
/// credential could ever produce a different answer.
pub enum ConnectError {
    /// The server rejected the credential (SQLSTATE 28xxx). No retry inside
    /// this session can change the answer — the key is fixed at open — so the
    /// caller poisons the session rather than asking the store again on every
    /// call, which would put a consent prompt in front of a human each time.
    Authentication(String),
    /// Anything else: DNS, TCP, TLS, a missing database, a server that is
    /// still starting. These do change on their own, so they are retried.
    Other(String),
}

impl ConnTarget {
    /// Validate and resolve session args into a connection target.
    ///
    /// Pure: no DNS, no socket, no credential. Every refusal below is a
    /// refusal about *args*, so it belongs at open, where the caller can see
    /// which argument it made.
    ///
    /// # Why a DSN may not carry a password
    ///
    /// A DSN mixes secret and non-secret in one opaque string, which is the
    /// nastier of the two leaks this component used to have: `password` at
    /// least looked like a credential, while `postgres://user:pass@host/db`
    /// reads as an address. Anything an agent puts in session args is
    /// plaintext in its context, in the transcript, and in the host's session
    /// record, so the password is refused here in every spelling and comes
    /// from the credential store instead.
    ///
    /// The DSN itself is kept, because it is how connection details are
    /// actually recorded — a `DATABASE_URL`, a Helm value, a psql invocation —
    /// and because it carries non-secret parameters the discrete args do not
    /// (`options`, `application_name`). Password-free is the whole rule.
    ///
    /// # What survives from a DSN
    ///
    /// | Parameter | Fate |
    /// |---|---|
    /// | `host`, `port` | honoured; exactly one host, TCP only |
    /// | `dbname`, `user` | honoured, and overridden by the `dbname` / `user` session args |
    /// | `sslmode` | honoured, and overridden by the `sslmode` session arg |
    /// | `options`, `application_name`, `channel_binding` | honoured, sent at startup |
    /// | `password` (userinfo, `password=`, `?password=`) | **refused** |
    /// | userinfo of any kind (`user@host`) | **refused** — name the role in `user` |
    /// | more than one host | **refused**; failover is not implemented, and picking the first silently is worse |
    /// | `sslnegotiation=direct` | **refused**; it needs an ALPN this build does not set |
    /// | `connect_timeout`, `keepalives*`, `tcp_user_timeout`, `target_session_attrs`, `load_balance_hosts`, `hostaddr` | **ignored** — they belong to tokio-postgres's `runtime` connector, which does not build for wasm32-wasip2; this component connects the socket itself |
    ///
    /// An unknown or malformed parameter is a parse error, not a silent drop:
    /// `sslmode=verify-full` is rejected by tokio-postgres, which knows only
    /// `disable`/`prefer`/`require` (see the TLS caveat in this file's header —
    /// there is no certificate verification to ask for yet).
    pub fn prepare(args: TargetArgs) -> Result<ConnTarget, String> {
        let mut pg = match (&args.connection_string, &args.host) {
            (Some(_), Some(_)) => {
                return Err(
                    "connection_string and host are alternatives — pass one, not \
                            both. A DSN already names the host it connects to."
                        .into(),
                );
            }
            (None, None) => {
                return Err("no server to connect to: pass either `host` (with `port`, \
                            `dbname` and `user`) or a password-free `connection_string`."
                    .into());
            }
            (Some(dsn), None) => {
                if args.port.is_some() {
                    return Err("port belongs to the connection_string when one is given \
                                — put it there (postgres://host:5433/db) rather than \
                                passing both."
                        .into());
                }
                parse_dsn(dsn)?
            }
            (None, Some(host)) => {
                let mut c = tokio_postgres::Config::new();
                c.host(check_host(host)?);
                c.port(args.port.unwrap_or(5432));
                c
            }
        };

        // Session args override the DSN. `user` is the one non-secret half of
        // the credential, so it has a home in both places on purpose; see
        // `resolve_user` in lib.rs for the full precedence.
        if let Some(user) = &args.user {
            if user.trim().is_empty() {
                return Err("user must be a role name, not an empty string.".into());
            }
            pg.user(user.as_str());
        }
        if let Some(dbname) = &args.dbname {
            if dbname.trim().is_empty() {
                return Err("dbname must be a database name, not an empty string.".into());
            }
            pg.dbname(dbname.as_str());
        }

        // Resolve TLS *before* connecting, and write it back onto the config.
        // `Config::connect_raw` consults `ssl_mode` itself: with `disable` it
        // returns a plaintext stream whatever connector it is handed, so a
        // session arg of `require` against a DSN saying `sslmode=disable`
        // would otherwise have connected in the clear while reporting nothing.
        let sslmode = args
            .sslmode
            .unwrap_or_else(|| SslMode::from_pg(pg.get_ssl_mode()));
        pg.ssl_mode(sslmode.to_pg());
        if pg.get_ssl_negotiation() == SslNegotiation::Direct {
            return Err(
                "sslnegotiation=direct is not supported: it requires an ALPN \
                        protocol this build does not set, and the handshake fails \
                        without a diagnosis from the server."
                    .into(),
            );
        }

        // Exactly one TCP host. `get_hosts` can hold several (a comma-separated
        // DSN), and this component connects one socket: taking the first would
        // silently drop the failover the caller asked for.
        let hosts = pg.get_hosts();
        let host = match hosts {
            [Host::Tcp(h)] => h.clone(),
            [] => return Err("no host specified in the connection config.".into()),
            #[allow(unreachable_patterns)]
            [_] => {
                return Err(
                    "only TCP hosts are supported — a Unix socket path cannot be \
                            reached from a wasm component."
                        .into(),
                );
            }
            _ => {
                return Err(
                    "only one host is supported. A comma-separated host list asks \
                            for failover, which this component does not implement, and \
                            connecting to the first one silently is worse than saying so."
                        .into(),
                );
            }
        };
        let port = pg.get_ports().first().copied().unwrap_or(5432);

        Ok(ConnTarget {
            pg,
            host,
            port,
            sslmode,
            statement_timeout_ms: args.statement_timeout_ms,
        })
    }

    /// The login role the *session args* named — the `user` argument, or the
    /// DSN's `user=`. `None` when neither did, and then the credential's
    /// `postgres:user` supplies it.
    pub fn user(&self) -> Option<&str> {
        self.pg.get_user()
    }

    /// A safe description of where this session connects, for
    /// `secret-request.resource` — which leaves the component for the host and
    /// is host-visible by contract (a host MAY show it to the human it prompts,
    /// or record it).
    ///
    /// Safe because it is rebuilt from validated parts rather than echoed:
    /// [`ConnTarget::prepare`] has already refused userinfo and a password, so
    /// there is nothing here to leak, and the role is deliberately left out —
    /// the host is prompting *for* the credential, not describing it.
    pub fn resource(&self) -> String {
        match self.pg.get_dbname() {
            Some(db) => format!("postgres://{}:{}/{}", self.host, self.port, db),
            None => format!("postgres://{}:{}", self.host, self.port),
        }
    }

    /// Open the connection, authenticating as `user` with `password`.
    ///
    /// `password` is used and dropped here: it is set on a clone of the
    /// config, which lives no longer than the attempt, and it is never stored
    /// on [`Connection`], never logged, and never quoted in the errors below.
    pub fn connect(&self, user: &str, password: &str) -> Result<Connection, ConnectError> {
        let mut pg_cfg = self.pg.clone();
        pg_cfg.user(user);
        pg_cfg.password(password);

        // Resolve host:port to a SocketAddr OUTSIDE the async runtime. tokio's
        // lookup_host is not yet wired on wasip2, so we resolve via std
        // (getaddrinfo → wasi:sockets ip-name-lookup) and hand tokio a concrete
        // SocketAddr (which never triggers lookup_host).
        let host = self.host.clone();
        let port = self.port;
        let addr = (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|e| ConnectError::Other(format!("resolve {host}:{port} failed: {e}")))?
            .next()
            .ok_or_else(|| ConnectError::Other(format!("no address for {host}:{port}")))?;

        let sslmode = self.sslmode;
        let statement_timeout_ms = self.statement_timeout_ms;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| ConnectError::Other(format!("tokio runtime build failed: {e}")))?;

        let client = rt.block_on(async move {
            let stream = tokio::net::TcpStream::connect(addr)
                .await
                .map_err(|e| ConnectError::Other(format!("tcp connect {addr} failed: {e}")))?;

            let client = match sslmode {
                SslMode::Disable => {
                    let (client, connection) =
                        pg_cfg.connect_raw(stream, NoTls).await.map_err(handshake)?;
                    tokio::spawn(async move {
                        let _ = connection.await;
                    });
                    client
                }
                // v1: `prefer` attempts TLS without plaintext fallback (same as
                // require); true prefer-fallback (reconnect on handshake failure)
                // is a follow-up milestone.
                SslMode::Prefer | SslMode::Require => {
                    let tls_cfg = rustls_config().map_err(ConnectError::Other)?;
                    let connector = TlsConnector::from(Arc::new(tls_cfg));
                    let domain: ServerName<'static> = ServerName::try_from(host.as_str())
                        .map_err(|e| {
                            ConnectError::Other(format!("invalid hostname for TLS SNI: {e}"))
                        })?
                        .to_owned();
                    let tls_connect = PgTlsConnect { connector, domain };
                    let (client, connection) = pg_cfg
                        .connect_raw(stream, tls_connect)
                        .await
                        .map_err(handshake)?;
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
                    .map_err(|e| {
                        ConnectError::Other(format!("SET statement_timeout failed: {e}"))
                    })?;
            }

            Ok::<Client, ConnectError>(client)
        })?;

        Ok(Connection { rt, client })
    }
}

/// Classify a failed startup. SQLSTATE class 28 is "invalid authorization
/// specification" — a wrong password (28P01) or a role that does not exist
/// (28000). Both are answers about the credential, and neither changes for a
/// session whose credential key was fixed at open.
///
/// The server's own message is passed through. libpq-style errors name the
/// role and the database and never the password, which is the property that
/// makes this safe — and the one reason this component never builds a message
/// out of the credential itself.
fn handshake(e: tokio_postgres::Error) -> ConnectError {
    let authentication = e.code().is_some_and(|c| {
        *c == SqlState::INVALID_PASSWORD || *c == SqlState::INVALID_AUTHORIZATION_SPECIFICATION
    });
    if authentication {
        ConnectError::Authentication(format!("the server refused the credential: {e}"))
    } else {
        ConnectError::Other(format!("postgres handshake failed: {e}"))
    }
}

/// Parse a DSN and refuse the two things it must not carry: a password, in any
/// of its three spellings, and userinfo of any kind.
///
/// The password check runs on the *parsed* config rather than on the text,
/// which is what makes it total: `postgres://u:p@h/db`, `?password=p` and
/// `host=h password=p` all land in the same field, and the parser that decides
/// is the same one that later builds the connection — so there is no gap
/// between the string validated and the string used.
///
/// The userinfo check does read the text, because a parsed config cannot say
/// where its `user` came from. It refuses the whole `user@host` slot, not just
/// the `:password` half: telling `postgres://a:b@h` from `postgres://a@h` by
/// eye is exactly the mistake this component is closing, `user` has its own
/// argument, and a rule about a character is one a reviewer can check.
///
/// It refuses **any** `@` in a URL-form DSN, not only one inside the
/// authority, because that is what tokio-postgres itself does:
/// `UrlParser::parse_credentials` takes everything up to the *first* `@` in
/// the whole string as userinfo, so `postgres://h/db?application_name=job@1`
/// parses as user `h/db?application_name=job` against host `1`. A narrower
/// rule here would accept a string the parser reads completely differently,
/// which is the class of bug this function exists to prevent. `%40` is the
/// spelling for a literal one, and the parser never decodes it back into a
/// separator.
///
/// Neither refusal echoes the DSN — it is the string that would carry the
/// password.
fn parse_dsn(dsn: &str) -> Result<tokio_postgres::Config, String> {
    if let Some(rest) = strip_scheme(dsn)
        && rest.contains('@')
    {
        return Err(format!(
            "connection_string must not carry userinfo (postgres://user:pass@host/db). \
             postgres authenticates from the credential store entry named by \
             credential_key: put the password in the {} field and the role in the `user` \
             argument or the {} field. A literal '@' elsewhere in the URL — in \
             application_name, say — must be written '%40', because everything before the \
             first '@' is read as userinfo.",
            crate::creds::FIELD_PASSWORD,
            crate::creds::FIELD_USER
        ));
    }
    let cfg = dsn
        .parse::<tokio_postgres::Config>()
        // The parser's message names the offending *keyword*, never a value.
        .map_err(|e| format!("connection_string is not a valid PostgreSQL DSN: {e}"))?;
    if cfg.get_password().is_some() {
        return Err(format!(
            "connection_string must not carry a password. It is plaintext in the agent's \
             context and in the audit record the moment it becomes a session argument; \
             postgres authenticates from the credential store entry named by \
             credential_key instead:\n  \
             act secret set <component-ref> --key default --field {} --fields-stdin",
            crate::creds::FIELD_PASSWORD
        ));
    }
    Ok(cfg)
}

/// The part of a DSN after `postgres://` or `postgresql://`, or `None` for the
/// keyword/value form, which has no authority to inspect.
fn strip_scheme(dsn: &str) -> Option<&str> {
    ["postgres://", "postgresql://"]
        .iter()
        .find_map(|s| dsn.strip_prefix(s))
}

/// A `host` argument is a host, not an authority.
///
/// `@` is the same refusal `parse_dsn` makes, in the place the same paste
/// lands: `--host user:pass@db.internal` would otherwise be handed to the
/// resolver whole, fail to resolve, and report a DNS error carrying the
/// password. `:` and `/` are refused for the neighbouring mistakes (`host:5432`
/// and a whole URL), which the resolver reports just as unhelpfully.
fn check_host(host: &str) -> Result<&str, String> {
    let host = host.trim();
    if host.is_empty() {
        return Err("host must not be empty.".into());
    }
    if host.contains('@') {
        return Err(format!(
            "host must not carry userinfo (user:pass@host). postgres authenticates from \
             the credential store entry named by credential_key: put the password in the \
             {} field and the role in the `user` argument.",
            crate::creds::FIELD_PASSWORD
        ));
    }
    if let Some(bad) = host.chars().find(|c| matches!(c, ':' | '/' | ' ')) {
        return Err(format!(
            "host must be a hostname or IP address and nothing else — no '{bad}'. Use the \
             `port` argument for a port, and `connection_string` for a DSN."
        ));
    }
    Ok(host)
}

// ── v1: TLS without full cert verification — see CHANGELOG ──────────────────
//
// wasip2 has no system certificate store, so we cannot verify the server's
// certificate chain in v1. We accept any cert presented by the server to allow
// connections to real Postgres instances (including self-signed dev setups).
// Full chain verification is tracked for a follow-up milestone.
//
// Handshake signatures are checked by the crypto provider, but because the
// certificate chain is NOT verified those signatures are validated against an
// UNTRUSTED cert — so this gives confidentiality (encryption) only, with NO
// server authentication and NO protection against an active MITM presenting
// any certificate. Equivalent in spirit to libpq sslmode=require (not verify-*).

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
                .map_err(io::Error::other)?;
            Ok(PgTlsStream(tls_stream))
        })
    }
}

// ── Connection ───────────────────────────────────────────────────────────────

/// A live connection: a per-session current_thread tokio runtime driving a
/// tokio-postgres `Client` over a wasi:sockets TCP stream.
///
/// Holds no credential. The password was consumed by
/// [`ConnTarget::connect`] and dropped with the config clone it was set on;
/// what survives is an authenticated socket, which is the point of fetching a
/// secret at all.
///
/// The session's `mode` and row cap live on the session, not here: they are
/// decisions about what the *caller* may ask for, and a connection that
/// carried them would have to be rebuilt to change one.
pub struct Connection {
    rt: Runtime,
    client: Client,
}

impl Connection {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn dsn(s: &str) -> TargetArgs {
        TargetArgs {
            connection_string: Some(s.into()),
            ..Default::default()
        }
    }

    fn host(s: &str) -> TargetArgs {
        TargetArgs {
            host: Some(s.into()),
            ..Default::default()
        }
    }

    /// The password has three spellings in a DSN and all three are refused.
    /// The URL-query and keyword forms are the ones a text search for `@`
    /// would miss, which is why the check runs on the parsed config.
    #[test]
    fn a_dsn_may_not_carry_a_password_in_any_spelling() {
        for s in [
            "postgres://alice:hunter2@db.internal:5432/app",
            "postgres://db.internal:5432/app?password=hunter2",
            "host=db.internal dbname=app password=hunter2",
        ] {
            let e = ConnTarget::prepare(dsn(s)).expect_err("refused");
            assert!(!e.contains("hunter2"), "leaked the password: {e}");
            assert!(
                e.contains("credential_key") || e.contains("credential store"),
                "the refusal must name the way to authenticate: {e}"
            );
        }
    }

    /// Userinfo is refused whole, not just its `:password` half. Telling
    /// `postgres://a:b@h` from `postgres://a@h` by eye is the mistake being
    /// closed, and `user` has its own argument.
    #[test]
    fn a_dsn_may_not_carry_userinfo_even_without_a_password() {
        let e = ConnTarget::prepare(dsn("postgres://alice@db.internal/app")).expect_err("refused");
        assert!(e.contains("userinfo"), "got {e}");
        assert!(e.contains(crate::creds::FIELD_PASSWORD), "got {e}");
    }

    /// An `@` anywhere in a URL-form DSN is refused, because tokio-postgres
    /// reads everything before the first one as userinfo: this DSN parses as
    /// user `db.internal/app?application_name=job` against host `1`. The
    /// refusal is what stops that from silently connecting somewhere else,
    /// and the message says how to write a literal one.
    #[test]
    fn any_at_sign_in_a_url_dsn_is_userinfo_as_far_as_the_parser_is_concerned() {
        let e = ConnTarget::prepare(dsn("postgres://db.internal/app?application_name=job@1"))
            .expect_err("refused");
        assert!(e.contains("%40"), "got {e}");

        let t = ConnTarget::prepare(dsn("postgres://db.internal/app?application_name=job%401"))
            .expect("accepted");
        assert_eq!(t.host, "db.internal");
    }

    /// The keyword/value form has no userinfo slot at all, so an `@` in a
    /// value is just a character there.
    #[test]
    fn the_keyword_form_carries_no_userinfo_slot() {
        let t =
            ConnTarget::prepare(dsn("host=db.internal application_name=job@1")).expect("accepted");
        assert_eq!(t.host, "db.internal");
    }

    #[test]
    fn a_host_argument_may_not_carry_userinfo_or_a_port() {
        let e = ConnTarget::prepare(host("alice:hunter2@db.internal")).expect_err("refused");
        assert!(!e.contains("hunter2"), "leaked the password: {e}");
        assert!(e.contains("userinfo"), "got {e}");

        let e = ConnTarget::prepare(host("db.internal:5432")).expect_err("refused");
        assert!(e.contains("`port`"), "got {e}");
    }

    #[test]
    fn the_two_forms_are_alternatives_and_one_is_required() {
        let both = TargetArgs {
            connection_string: Some("postgres://a/b".into()),
            host: Some("c".into()),
            ..Default::default()
        };
        assert!(ConnTarget::prepare(both).is_err());
        assert!(ConnTarget::prepare(TargetArgs::default()).is_err());

        let with_port = TargetArgs {
            connection_string: Some("postgres://a/b".into()),
            port: Some(5433),
            ..Default::default()
        };
        assert!(ConnTarget::prepare(with_port).is_err());
    }

    /// Session args override the DSN — the precedence lib.rs documents and
    /// resolves the login role with.
    #[test]
    fn a_user_argument_overrides_the_dsn() {
        let mut a = dsn("postgres://db.internal/app?user=from_dsn");
        assert_eq!(
            ConnTarget::prepare(dsn("postgres://db.internal/app?user=from_dsn"))
                .expect("accepted")
                .user(),
            Some("from_dsn")
        );
        a.user = Some("from_args".into());
        assert_eq!(
            ConnTarget::prepare(a).expect("accepted").user(),
            Some("from_args")
        );
    }

    /// The session arg wins, the DSN is honoured when there is no arg, and
    /// `prefer` is the fallback. This is the parameter `connect_raw` reads
    /// itself, so getting it wrong connects in the clear.
    #[test]
    fn the_sslmode_argument_overrides_the_dsn_and_the_dsn_is_otherwise_honoured() {
        let t = ConnTarget::prepare(dsn("postgres://h/db?sslmode=disable")).expect("accepted");
        assert_eq!(t.sslmode, SslMode::Disable);
        assert_eq!(
            t.pg.get_ssl_mode(),
            tokio_postgres::config::SslMode::Disable
        );

        let mut a = dsn("postgres://h/db?sslmode=disable");
        a.sslmode = Some(SslMode::Require);
        let t = ConnTarget::prepare(a).expect("accepted");
        assert_eq!(t.sslmode, SslMode::Require);
        // Written back onto the config: `connect_raw` returns a plaintext
        // stream for `disable` whatever connector it is handed.
        assert_eq!(
            t.pg.get_ssl_mode(),
            tokio_postgres::config::SslMode::Require
        );

        assert_eq!(
            ConnTarget::prepare(host("h")).expect("accepted").sslmode,
            SslMode::Prefer
        );
    }

    #[test]
    fn a_host_list_is_refused_rather_than_silently_reduced_to_its_first_entry() {
        let e = ConnTarget::prepare(dsn("host=a,b dbname=app")).expect_err("refused");
        assert!(e.contains("one host"), "got {e}");
    }

    #[test]
    fn direct_tls_negotiation_is_refused_because_it_would_hang_the_handshake() {
        let e =
            ConnTarget::prepare(dsn("postgres://h/db?sslnegotiation=direct")).expect_err("refused");
        assert!(e.contains("ALPN"), "got {e}");
    }

    /// `resource` leaves the component for the host, which may show it to a
    /// human. It is rebuilt from validated parts, so there is nothing in it
    /// to leak — and the role is left out, because the host is prompting for
    /// the credential rather than describing one.
    #[test]
    fn the_resource_description_names_the_target_and_no_credential() {
        let mut a = dsn("postgres://db.internal:5433/app?user=alice");
        a.dbname = Some("reporting".into());
        let t = ConnTarget::prepare(a).expect("accepted");
        assert_eq!(t.resource(), "postgres://db.internal:5433/reporting");
        assert!(!t.resource().contains("alice"));

        assert_eq!(
            ConnTarget::prepare(host("db.internal"))
                .expect("accepted")
                .resource(),
            "postgres://db.internal:5432"
        );
    }

    #[test]
    fn the_discrete_form_defaults_to_the_standard_port() {
        let t = ConnTarget::prepare(host("db.internal")).expect("accepted");
        assert_eq!((t.host.as_str(), t.port), ("db.internal", 5432));

        let mut a = host("db.internal");
        a.port = Some(6432);
        assert_eq!(ConnTarget::prepare(a).expect("accepted").port, 6432);
    }

    /// Whatever else a target carries, it never carries a password: nothing
    /// in `TargetArgs` can express one, and `prepare` refuses the DSN
    /// spellings that can.
    #[test]
    fn a_prepared_target_never_holds_a_password() {
        let t = ConnTarget::prepare(dsn("postgres://db.internal/app?user=alice")).expect("ok");
        assert!(t.pg.get_password().is_none());
    }
}
