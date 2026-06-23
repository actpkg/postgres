//! The live Postgres connection: a per-session current_thread tokio runtime
//! driving a tokio-postgres Client over a wasi:sockets TCP stream.

use std::net::ToSocketAddrs;
use tokio::runtime::Runtime;
use tokio_postgres::{Client, NoTls};

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
        cfg.user(user).dbname(dbname);
        if let Some(pw) = password {
            cfg.password(pw);
        }

        let client = rt.block_on(async move {
            let stream = tokio::net::TcpStream::connect(addr)
                .await
                .map_err(|e| format!("tcp connect {addr} failed: {e}"))?;
            let (client, connection) = cfg
                .connect_raw(stream, NoTls)
                .await
                .map_err(|e| format!("postgres handshake failed: {e}"))?;
            // Drive the connection's I/O task on this runtime; it is polled
            // during every subsequent block_on call.
            tokio::spawn(async move {
                let _ = connection.await;
            });
            Ok::<Client, String>(client)
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
