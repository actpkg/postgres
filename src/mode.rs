//! Session capability tier (`mode`) + the gate that maps a SQL string to its
//! required Tier and checks it against the session mode. Pure + host-testable.

use crate::classify::{required_tier, Tier};
use serde::Deserialize;
use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    #[default]
    ReadOnly,
    ReadWrite,
    Ddl,
    Full,
}

impl Mode {
    fn ceiling(self) -> u8 {
        match self {
            Mode::ReadOnly => 0,
            Mode::ReadWrite => 1,
            Mode::Ddl => 2,
            Mode::Full => 3,
        }
    }
    pub fn permits(self, tier: Tier) -> bool {
        let rank = match tier {
            Tier::Read => 0,
            Tier::Write => 1,
            Tier::Ddl => 2,
            Tier::Drop => 3,
        };
        rank <= self.ceiling()
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Mode::ReadOnly => "read-only",
            Mode::ReadWrite => "read-write",
            Mode::Ddl => "ddl",
            Mode::Full => "full",
        };
        f.write_str(s)
    }
}

/// A denied operation, carrying everything a future host consent request needs.
#[derive(Debug)]
pub struct GateError {
    pub cap_id: &'static str,
    pub key: String,
    pub summary: String,
}

/// Classify `sql` and check the required tier against the session `mode`.
pub fn require_tier(mode: Mode, sql: &str) -> Result<Tier, GateError> {
    let tier = required_tier(sql).map_err(|e| GateError {
        cap_id: "db:read",
        key: String::new(),
        summary: e,
    })?;

    // TODO(act-consent): there is NO guest-facing consent WIT today. Once the
    // act:consent WIT package + an act_sdk consent fn land, replace this local
    // tier check with a host-enforced consent request, e.g.
    //   match act_sdk::consent::request(tier.cap_id(), &key, &summary)? {
    //       Decision::Allow => {}
    //       Decision::Deny  => return Err(GateError { .. }),
    //       Decision::Ask   => { /* host prompts; honored by the host */ }
    //   }
    // The host's generic capability provider already classifies db:* via globs
    // over attrs {table, database, statement_kind}; this is the swap point.
    if !mode.permits(tier) {
        return Err(GateError {
            cap_id: tier.cap_id(),
            key: String::new(),
            summary: format!(
                "operation requires capability {} but session mode is {mode}",
                tier.cap_id()
            ),
        });
    }
    Ok(tier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_permits_only_reads() {
        assert!(Mode::ReadOnly.permits(Tier::Read));
        assert!(!Mode::ReadOnly.permits(Tier::Write));
        assert!(!Mode::ReadOnly.permits(Tier::Ddl));
        assert!(!Mode::ReadOnly.permits(Tier::Drop));
    }
    #[test]
    fn read_write_permits_read_and_write() {
        assert!(Mode::ReadWrite.permits(Tier::Write));
        assert!(!Mode::ReadWrite.permits(Tier::Ddl));
    }
    #[test]
    fn ddl_permits_through_ddl_not_drop() {
        assert!(Mode::Ddl.permits(Tier::Ddl));
        assert!(!Mode::Ddl.permits(Tier::Drop));
    }
    #[test]
    fn full_permits_everything() {
        assert!(Mode::Full.permits(Tier::Drop));
    }
    #[test]
    fn default_is_read_only() {
        assert_eq!(Mode::default(), Mode::ReadOnly);
    }
    #[test]
    fn gate_rejects_write_in_read_only() {
        let err = require_tier(Mode::ReadOnly, "DELETE FROM t").unwrap_err();
        assert_eq!(err.cap_id, "db:write");
    }
    #[test]
    fn gate_allows_read_in_read_only() {
        assert_eq!(require_tier(Mode::ReadOnly, "SELECT 1").unwrap(), Tier::Read);
    }
}
