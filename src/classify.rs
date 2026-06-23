//! Classify a SQL string into the capability Tier it requires. Pure: depends
//! only on sqlparser. Host-testable with `cargo test --target x86_64-unknown-linux-gnu`.

use sqlparser::ast::Statement;
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tier {
    Read,
    Write,
    Ddl,
    Drop,
}

impl Tier {
    fn rank(self) -> u8 {
        match self {
            Tier::Read => 0,
            Tier::Write => 1,
            Tier::Ddl => 2,
            Tier::Drop => 3,
        }
    }
    /// The semantic capability id for this tier.
    pub fn cap_id(self) -> &'static str {
        match self {
            Tier::Read => "db:read",
            Tier::Write => "db:write",
            Tier::Ddl => "db:ddl",
            Tier::Drop => "db:drop",
        }
    }
}

fn classify_one(stmt: &Statement) -> Tier {
    match stmt {
        Statement::Query(_)
        | Statement::Explain { .. }
        | Statement::ExplainTable { .. }
        | Statement::ShowVariable { .. }
        | Statement::ShowColumns { .. }
        | Statement::ShowTables { .. } => Tier::Read,

        Statement::Insert { .. }
        | Statement::Update { .. }
        | Statement::Delete { .. }
        | Statement::Merge { .. }
        | Statement::Copy { .. } => Tier::Write,

        Statement::Drop { .. } | Statement::Truncate { .. } => Tier::Drop,

        // Everything else that mutates structure/permissions is DDL.
        _ => Tier::Ddl,
    }
}

pub fn required_tier(sql: &str) -> Result<Tier, String> {
    let stmts = Parser::parse_sql(&PostgreSqlDialect {}, sql)
        .map_err(|e| format!("SQL parse error: {e}"))?;
    if stmts.is_empty() {
        return Err("empty SQL".to_string());
    }
    Ok(stmts
        .iter()
        .map(classify_one)
        .max_by_key(|t| t.rank())
        .unwrap())
}

pub fn assert_single_statement(sql: &str) -> Result<(), String> {
    let stmts = Parser::parse_sql(&PostgreSqlDialect {}, sql)
        .map_err(|e| format!("SQL parse error: {e}"))?;
    match stmts.len() {
        1 => Ok(()),
        0 => Err("empty SQL".to_string()),
        n => Err(format!("expected a single statement, got {n}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(sql: &str) -> Tier {
        required_tier(sql).unwrap()
    }

    #[test]
    fn reads() {
        assert_eq!(t("SELECT 1"), Tier::Read);
        assert_eq!(t("EXPLAIN SELECT * FROM t"), Tier::Read);
        assert_eq!(t("WITH x AS (SELECT 1) SELECT * FROM x"), Tier::Read);
    }
    #[test]
    fn writes() {
        assert_eq!(t("INSERT INTO t VALUES (1)"), Tier::Write);
        assert_eq!(t("UPDATE t SET a=1"), Tier::Write);
        assert_eq!(t("DELETE FROM t"), Tier::Write);
    }
    #[test]
    fn ddl() {
        assert_eq!(t("CREATE TABLE t (id int)"), Tier::Ddl);
        assert_eq!(t("ALTER TABLE t ADD COLUMN c int"), Tier::Ddl);
        assert_eq!(t("CREATE INDEX i ON t (id)"), Tier::Ddl);
    }
    #[test]
    fn drops() {
        assert_eq!(t("DROP TABLE t"), Tier::Drop);
        assert_eq!(t("TRUNCATE t"), Tier::Drop);
    }
    #[test]
    fn max_over_batch() {
        assert_eq!(t("SELECT 1; DROP TABLE t"), Tier::Drop);
    }
    #[test]
    fn parse_error_is_err() {
        assert!(required_tier("NOT SQL ;;").is_err());
        assert!(required_tier("").is_err());
    }
    #[test]
    fn single_statement_guard() {
        assert!(assert_single_statement("SELECT 1").is_ok());
        assert!(assert_single_statement("SELECT 1; SELECT 2").is_err());
    }
}
