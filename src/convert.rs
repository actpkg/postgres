//! Dynamic parameter binding (CBOR/JSON value -> Postgres) and Row -> CBOR.

use bytes::BytesMut;
use ciborium::value::Value as Cv;
use std::error::Error;
use tokio_postgres::types::{to_sql_checked, IsNull, ToSql, Type};
use tokio_postgres::Row;

/// A dynamic SQL bind value. Wraps a CBOR value (host projects JSON/CBOR args
/// into this). Supports the common scalar types; binds best-effort to the
/// server-inferred parameter type.
#[derive(Debug)]
pub struct PgParam(pub Cv);

impl<'de> serde::Deserialize<'de> for PgParam {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(PgParam(Cv::deserialize(d)?))
    }
}

impl schemars::JsonSchema for PgParam {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "PgParam".into()
    }
    fn inline_schema() -> bool {
        true
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({}) // any scalar: null/bool/number/string
    }
}

impl ToSql for PgParam {
    fn to_sql(
        &self,
        ty: &Type,
        out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn Error + Sync + Send>> {
        match &self.0 {
            Cv::Null => Ok(IsNull::Yes),
            Cv::Bool(b) => b.to_sql(ty, out),
            Cv::Integer(i) => {
                let n: i128 = (*i).into();
                match *ty {
                    Type::INT2 => (n as i16).to_sql(ty, out),
                    Type::INT4 => (n as i32).to_sql(ty, out),
                    Type::FLOAT4 => (n as f32).to_sql(ty, out),
                    Type::FLOAT8 => (n as f64).to_sql(ty, out),
                    _ => (n as i64).to_sql(ty, out), // INT8 and fallback
                }
            }
            Cv::Float(f) => match *ty {
                Type::FLOAT4 => (*f as f32).to_sql(ty, out),
                _ => f.to_sql(ty, out),
            },
            Cv::Text(s) => s.to_sql(ty, out),
            other => Err(format!("unsupported bind value: {other:?}").into()),
        }
    }
    fn accepts(_: &Type) -> bool {
        true // best-effort; to_sql handles the actual encoding per inferred type
    }
    to_sql_checked!();
}

pub fn param_refs(params: &[PgParam]) -> Vec<&(dyn ToSql + Sync)> {
    params.iter().map(|p| p as &(dyn ToSql + Sync)).collect()
}

/// Decode one column into CBOR by its Postgres type. Unsupported types render
/// as a CBOR text marker so a query never panics (type coverage is incremental).
fn cell_to_cbor(row: &Row, i: usize) -> Cv {
    let ty = row.columns()[i].type_().clone();
    macro_rules! get {
        ($t:ty) => {
            row.try_get::<_, Option<$t>>(i).ok().flatten()
        };
    }
    match ty {
        Type::BOOL => get!(bool).map(Cv::Bool).unwrap_or(Cv::Null),
        Type::INT2 => get!(i16).map(|v| Cv::from(v as i64)).unwrap_or(Cv::Null),
        Type::INT4 => get!(i32).map(|v| Cv::from(v as i64)).unwrap_or(Cv::Null),
        Type::INT8 => get!(i64).map(Cv::from).unwrap_or(Cv::Null),
        Type::FLOAT4 => get!(f32).map(|v| Cv::Float(v as f64)).unwrap_or(Cv::Null),
        Type::FLOAT8 => get!(f64).map(Cv::Float).unwrap_or(Cv::Null),
        Type::TEXT | Type::VARCHAR | Type::BPCHAR | Type::NAME | Type::UNKNOWN => {
            get!(String).map(Cv::Text).unwrap_or(Cv::Null)
        }
        Type::BYTEA => get!(Vec<u8>).map(Cv::Bytes).unwrap_or(Cv::Null),
        other => Cv::Text(format!("<unsupported pg type: {}>", other.name())),
    }
}

/// Convert rows to an array of `{column: value}` CBOR maps, capped at `max_rows`.
/// Returns `(rows, truncated)`.
pub fn rows_to_cbor(rows: &[Row], max_rows: usize) -> (Vec<Cv>, bool) {
    let truncated = rows.len() > max_rows;
    let out = rows
        .iter()
        .take(max_rows)
        .map(|row| {
            let pairs = row
                .columns()
                .iter()
                .enumerate()
                .map(|(i, c)| (Cv::Text(c.name().to_string()), cell_to_cbor(row, i)))
                .collect();
            Cv::Map(pairs)
        })
        .collect();
    (out, truncated)
}
