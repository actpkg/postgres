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
                    Type::INT2 => i16::try_from(n)
                        .map_err(|_| {
                            Box::<dyn Error + Sync + Send>::from(format!(
                                "value {n} out of range for INT2"
                            ))
                        })?
                        .to_sql(ty, out),
                    Type::INT4 => i32::try_from(n)
                        .map_err(|_| {
                            Box::<dyn Error + Sync + Send>::from(format!(
                                "value {n} out of range for INT4"
                            ))
                        })?
                        .to_sql(ty, out),
                    Type::FLOAT4 => (n as f32).to_sql(ty, out),
                    Type::FLOAT8 => (n as f64).to_sql(ty, out),
                    _ => i64::try_from(n)
                        .map_err(|_| {
                            Box::<dyn Error + Sync + Send>::from(format!(
                                "value {n} out of range for INT8"
                            ))
                        })?
                        .to_sql(ty, out), // INT8 and fallback
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
    // Distinguish Ok(Some(v)) → value, Ok(None) → Null, Err(_) → decode-error marker.
    macro_rules! get {
        ($t:ty, $map:expr) => {
            match row.try_get::<_, Option<$t>>(i) {
                Ok(Some(v)) => $map(v),
                Ok(None) => Cv::Null,
                Err(_) => Cv::Text(format!("<decode error: {}>", ty.name())),
            }
        };
    }
    match ty {
        Type::BOOL => get!(bool, Cv::Bool),
        Type::INT2 => get!(i16, |v: i16| Cv::from(v as i64)),
        Type::INT4 => get!(i32, |v: i32| Cv::from(v as i64)),
        Type::INT8 => get!(i64, Cv::from),
        Type::FLOAT4 => get!(f32, |v: f32| Cv::Float(v as f64)),
        Type::FLOAT8 => get!(f64, Cv::Float),
        Type::TEXT | Type::VARCHAR | Type::BPCHAR | Type::NAME | Type::UNKNOWN => {
            get!(String, Cv::Text)
        }
        Type::BYTEA => get!(Vec<u8>, Cv::Bytes),
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

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use ciborium::value::Integer as CborInt;
    use tokio_postgres::types::Type;

    // CborInt::from only accepts up to i64/u64; build from i64 parts.
    fn int_param(n: i64) -> PgParam {
        PgParam(Cv::Integer(CborInt::from(n)))
    }

    fn int_param_big(n: u64) -> PgParam {
        PgParam(Cv::Integer(CborInt::from(n)))
    }

    #[test]
    fn int2_overflow_returns_err() {
        // 99999 does not fit in i16 — must return Err, never silently wrap.
        let param = int_param(99999);
        let result = ToSql::to_sql(&param, &Type::INT2, &mut BytesMut::new());
        assert!(result.is_err(), "expected Err for 99999 -> INT2, got Ok");
    }

    #[test]
    fn int2_in_range_returns_ok() {
        // 100 fits in i16 — must succeed.
        let param = int_param(100);
        let result = ToSql::to_sql(&param, &Type::INT2, &mut BytesMut::new());
        assert!(result.is_ok(), "expected Ok for 100 -> INT2");
    }

    #[test]
    fn int4_overflow_returns_err() {
        let param = int_param(i64::from(i32::MAX) + 1);
        let result = ToSql::to_sql(&param, &Type::INT4, &mut BytesMut::new());
        assert!(result.is_err(), "expected Err for i32::MAX+1 -> INT4, got Ok");
    }

    #[test]
    fn int8_overflow_returns_err() {
        // i64::MAX + 1 can't be represented in i64, use u64 > i64::MAX.
        let param = int_param_big(u64::from(u32::MAX) * u64::from(u32::MAX));
        let result = ToSql::to_sql(&param, &Type::INT8, &mut BytesMut::new());
        assert!(result.is_err(), "expected Err for large u64 -> INT8, got Ok");
    }
}
