//! The credential this component authenticates with, and how to read it.
//!
//! One credential, two fields, both in this component's own namespace.
//! `ACT-CONSTANTS.md` §8.2 registers field *types*, not field *names*: no name
//! is well-known, the party that reads a field is the party that asked for it,
//! and a component may not mint a name in the `std:` namespace at all (pack
//! refuses one).
//!
//! Pure by design: the `get-secret` call lives in `lib.rs`, because the WIT
//! bindings exist only inside the `#[act_component]` module. That split is what
//! lets everything below be driven on the host target.
//!
//! Nothing here prints a field *value*, in an error or anywhere else. Field
//! names are safe — `list-secrets` hands them to the agent already — and the
//! password never is.

use act_sdk::credentials::Secret;
use act_sdk::prelude::*;

/// `std:credential-required` (`ACT-CONSTANTS.md` §9): a credential the
/// component needs is absent from its profile, and the host surfaces the
/// provisioning command alongside it.
///
/// **Delete this when act-types exports it.** `act_sdk::constants` carries the
/// other six kinds; this one was added to the spec afterwards.
pub const ERR_CREDENTIAL_REQUIRED: &str = "std:credential-required";

/// The credential key a session uses when its args do not name one. Declared
/// in `act.toml` under exactly this name, so `act login` prompts for it.
pub const DEFAULT_CREDENTIAL_KEY: &str = "default";

/// The password. Required: this component has no other way to authenticate.
pub const FIELD_PASSWORD: &str = "postgres:password";

/// The role the password belongs to. Optional — see [`Credentials::user`].
pub const FIELD_USER: &str = "postgres:user";

/// Longest credential key this component will look up.
pub const MAX_CREDENTIAL_KEY: usize = 64;

/// What was read out of the stored credential.
pub struct Credentials {
    /// The role the password belongs to, when the credential carries one.
    ///
    /// A role and its password are rotated together, so storing them together
    /// is the arrangement that survives a rotation. It is optional because it
    /// is not credential material: a deployment that prefers to name the role
    /// in session args may, and then this is `None`.
    ///
    /// It is the **lowest** priority source for the login role — see
    /// [`resolve_user`].
    pub user: Option<String>,
    /// The password. Never printed, never logged, never put in an error.
    pub password: String,
}

/// Prints the role and redacts the password. `Debug` is where credential
/// material escapes by accident: a component author logs a struct while
/// debugging, or wraps one in an error type that derives `Debug`, and the
/// material lands in the guest's output. Written by hand rather than derived
/// for exactly that reason, and mirroring what the SDK does to `Secret`.
impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("user", &self.user)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Read a fetched secret. There is no shape accessor and no branch on
/// `secret.kind`: a `std:string` field's value *is* a CBOR string, so it is
/// read by name with `field_str`, and what a credential means lives in its
/// field names (`ACT-CONSTANTS.md` §8.2.1).
///
/// A field that is present but blank reads as absent. An empty password would
/// otherwise reach the server and come back as an authentication failure,
/// which poisons the session and sends the operator looking at the server
/// instead of at the store.
pub fn from_secret(secret: &Secret, key: &str) -> ActResult<Credentials> {
    let password = secret
        .field_str(FIELD_PASSWORD)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ActError::new(ERR_CREDENTIAL_REQUIRED, missing_password_message(key)))?
        .to_string();

    Ok(Credentials {
        password,
        user: secret
            .field_str(FIELD_USER)
            .filter(|s| !s.trim().is_empty())
            .map(str::to_string),
    })
}

/// `not-found` and `denied` are indistinguishable at the store boundary — the
/// host decides `denied` *before* it consults the store (ACT-AUTH §1.1.7), so
/// distinguishing them would invent a difference the host refuses to disclose,
/// and would turn the pair into a way to probe a profile for keys. This names
/// both causes and asserts neither.
///
/// `known` is the profile's key inventory when `list-secrets` answered, and
/// empty when it did not. Keys are not secret — `list-secrets` exists to hand
/// them to the agent.
pub fn credential_missing_message(key: &str, known: &[String]) -> String {
    let mut msg = format!(
        "No usable credential under key '{key}'. Either it is not set, or policy denies \
         act:credentials for this component. Set one with:\n  \
         act secret set <component-ref> --key {key} --field {FIELD_PASSWORD} --fields-stdin\n  \
         {{\"{FIELD_PASSWORD}\": \"...\"}}\n\
         Add --field {FIELD_USER} to store the role beside its password."
    );
    if !known.is_empty() {
        msg.push_str(&format!(
            "\nThis component's profile has: {}",
            known.join(", ")
        ));
    }
    msg
}

/// The credential exists but carries no password.
///
/// The kind is `std:credential-required`, not `std:invalid-args`: nothing about
/// the *call* was wrong, and the fix is the provisioning command a host
/// surfaces for exactly this kind (`ACT-CONSTANTS.md` §9). The `--field` name
/// is part of that command because `act secret set` has no default field set —
/// a credential IS its named fields.
pub fn missing_password_message(key: &str) -> String {
    format!(
        "The credential under key '{key}' carries no {FIELD_PASSWORD} field. postgres \
         authenticates with a password only. Store one with:\n  \
         act secret set <component-ref> --key {key} --field {FIELD_PASSWORD} --fields-stdin\n  \
         {{\"{FIELD_PASSWORD}\": \"...\"}}"
    )
}

/// The refusal a session answers with once the server has rejected its
/// credential. See `SessionState::credential_rejected` in `lib.rs`.
pub fn credential_rejected_message(key: &str) -> String {
    format!(
        "The PostgreSQL server rejected the credential under key '{key}', so this session \
         will not ask for it again. Fix the stored credential and open a new session:\n  \
         act secret set <component-ref> --key {key} --field {FIELD_PASSWORD} --fields-stdin\n\
         If the role is wrong rather than the password, check the session's `user` argument \
         and the credential's {FIELD_USER} field."
    )
}

/// Decide which role to log in as.
///
/// **Precedence: session args, then the credential.** `from_args` is what the
/// session asked for — the `user` argument, or the DSN's `user=`, already
/// collapsed by `ConnTarget::prepare` — and it wins, because it is the
/// explicit, non-secret override an operator reaches for when one stored
/// credential is used against two roles. The credential's [`FIELD_USER`] is
/// the fallback, and it exists so that a role and its password can be stored,
/// rotated and audited as one thing.
///
/// The pairing is not checked and cannot be: only the server knows whether
/// this role and this password go together. A mismatch therefore surfaces as
/// an authentication failure on the first tool call, which poisons the
/// session — and [`credential_rejected_message`] names both halves as
/// suspects for exactly that reason.
pub fn resolve_user(
    from_args: Option<&str>,
    from_credential: Option<&str>,
    key: &str,
) -> ActResult<String> {
    from_args
        .or(from_credential)
        .map(str::to_string)
        .ok_or_else(|| {
            ActError::invalid_args(format!(
                "no login role: pass `user` in the session args, put `user=` in the \
                 connection_string, or store the role beside its password:\n  \
                 act secret set <component-ref> --key {key} --field {FIELD_USER} \
                 --field {FIELD_PASSWORD} --fields-stdin"
            ))
        })
}

/// The leading credential-key-shaped run of `key`: letters, digits, `-`, `_`
/// and `.`, up to [`MAX_CREDENTIAL_KEY`] characters.
///
/// Returns the *prefix* so a refusal can name what was asked for without
/// repeating whatever followed — which, in a key pasted by a confused caller,
/// may be a password.
fn key_prefix(key: &str) -> &str {
    let end = key
        .as_bytes()
        .iter()
        .take(MAX_CREDENTIAL_KEY)
        .position(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')))
        .unwrap_or_else(|| key.len().min(MAX_CREDENTIAL_KEY));
    &key[..end]
}

/// Refuse a `credential_key` that is not a bounded name.
///
/// `credential_key` is agent-authored text that the host pastes verbatim into
/// the question a **human** answers when deciding to release a credential
/// (`act-cli/crates/act-runtime/src/credentials.rs`, `consent_summary`), where
/// only `hint` is sanitised on the stated reasoning that everything else is
/// host-derived. For this component it is not, so the guarantee is made here.
///
/// The hazard is not newline forgery — the prompter escapes control and bidi
/// characters — it is plainer: `default (approved by your administrator)`
/// renders in that question exactly as written, and the human cannot tell
/// which half the machine wrote. A key is a lookup name, so a bounded token
/// costs nothing and ends the question.
pub fn validate_credential_key(key: &str) -> ActResult<()> {
    let head = key_prefix(key);
    if head.is_empty() || head.len() != key.len() {
        return Err(ActError::invalid_args(format!(
            "credential_key must be a name: 1–{MAX_CREDENTIAL_KEY} characters of letters, \
             digits, '-', '_' or '.', and '{head}…' is not one. It is a lookup key in this \
             component's credential profile, not a sentence."
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use act_sdk::constants::ERR_INVALID_ARGS;
    use ciborium::Value;

    fn secret(pairs: &[(&str, &str)]) -> Secret {
        Secret {
            kind: "std:fields".into(),
            fields: pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), Value::Text((*v).to_string())))
                .collect(),
        }
    }

    #[test]
    fn a_password_alone_is_a_credential() {
        let c = from_secret(&secret(&[(FIELD_PASSWORD, "hunter2")]), "default").expect("valid");
        assert_eq!(c.password, "hunter2");
        assert!(
            c.user.is_none(),
            "the role may live in session args instead"
        );
    }

    #[test]
    fn a_role_may_be_stored_beside_its_password() {
        let c = from_secret(
            &secret(&[(FIELD_PASSWORD, "hunter2"), (FIELD_USER, "reporting")]),
            "default",
        )
        .expect("valid");
        assert_eq!(c.user.as_deref(), Some("reporting"));
    }

    /// A password of spaces is a password; a password of nothing is not one.
    /// The empty case is rejected here rather than at the server, where it
    /// arrives as an authentication failure and poisons the session.
    #[test]
    fn an_empty_password_is_not_a_credential_but_a_blank_one_is() {
        let e = from_secret(&secret(&[(FIELD_PASSWORD, "")]), "default").expect_err("refused");
        assert_eq!(e.kind, ERR_CREDENTIAL_REQUIRED);
        assert!(from_secret(&secret(&[(FIELD_PASSWORD, "  ")]), "default").is_ok());
    }

    #[test]
    fn a_blank_role_reads_as_absent_rather_than_as_an_empty_role() {
        let c = from_secret(
            &secret(&[(FIELD_PASSWORD, "hunter2"), (FIELD_USER, "   ")]),
            "default",
        )
        .expect("valid");
        assert!(c.user.is_none());
    }

    /// An integer field is not a string with extra steps: `field_str` returns
    /// `None`, and the refusal is the same one a missing field gets.
    #[test]
    fn a_password_that_is_not_a_string_is_not_a_password() {
        let s = Secret {
            kind: "std:fields".into(),
            fields: [(FIELD_PASSWORD.to_string(), Value::Integer(42.into()))]
                .into_iter()
                .collect(),
        };
        assert_eq!(
            from_secret(&s, "default").expect_err("refused").kind,
            ERR_CREDENTIAL_REQUIRED
        );
    }

    /// Every refusal has to say what to run. An error that only reports the
    /// absence sends its reader to the source.
    #[test]
    fn every_credential_refusal_names_the_command_that_fixes_it() {
        for message in [
            missing_password_message("default"),
            credential_missing_message("prod", &[]),
            credential_rejected_message("prod"),
        ] {
            assert!(message.contains("act secret set"), "got {message}");
            assert!(message.contains(FIELD_PASSWORD), "got {message}");
        }
    }

    #[test]
    fn the_missing_message_lists_the_keys_the_profile_does_have() {
        let m = credential_missing_message("prod", &["default".into(), "staging".into()]);
        assert!(m.contains("default, staging"), "got {m}");
    }

    /// No message may carry credential material — the whole point of the
    /// store. The key is the only caller-supplied string any of them quotes,
    /// and `validate_credential_key` has already bounded it.
    #[test]
    fn no_credential_message_can_carry_a_password() {
        let c = from_secret(
            &secret(&[(FIELD_PASSWORD, "s3cr3t"), (FIELD_USER, "reporting")]),
            "default",
        )
        .expect("valid");
        for message in [
            missing_password_message("default"),
            credential_missing_message("default", &["default".into()]),
            credential_rejected_message("default"),
        ] {
            assert!(!message.contains(&c.password), "leaked: {message}");
        }
    }

    #[test]
    fn a_credential_key_is_a_bounded_name() {
        for ok in ["default", "prod", "ro.reporting", "db_1-a"] {
            assert!(validate_credential_key(ok).is_ok(), "{ok} should pass");
        }
        for bad in [
            "",
            "default (approved by your administrator)",
            "prod\nreally",
            "key: value",
            &"x".repeat(MAX_CREDENTIAL_KEY + 1),
        ] {
            let e = validate_credential_key(bad).expect_err("refused");
            assert_eq!(e.kind, ERR_INVALID_ARGS, "{bad}");
        }
    }

    /// Only the valid prefix is echoed. A whole `key: password` line pasted
    /// as one key carries its material after the first invalid character.
    #[test]
    fn the_key_refusal_echoes_the_prefix_and_not_what_followed() {
        let e = validate_credential_key("prod: hunter2").expect_err("refused");
        assert!(e.message.contains("'prod…'"), "got {}", e.message);
        assert!(!e.message.contains("hunter2"), "leaked: {}", e.message);
    }

    #[test]
    fn the_session_args_name_the_role_and_the_credential_is_the_fallback() {
        assert_eq!(
            resolve_user(Some("from_args"), Some("from_credential"), "default").unwrap(),
            "from_args"
        );
        assert_eq!(
            resolve_user(None, Some("from_credential"), "default").unwrap(),
            "from_credential"
        );
    }

    /// Neither source named a role. Refused before the socket rather than as
    /// a server-side "role \"\" does not exist".
    #[test]
    fn a_session_with_no_role_anywhere_is_refused_with_both_remedies() {
        let e = resolve_user(None, None, "prod").expect_err("refused");
        assert_eq!(e.kind, ERR_INVALID_ARGS);
        assert!(e.message.contains("user"), "got {}", e.message);
        assert!(e.message.contains("act secret set"), "got {}", e.message);
    }
}
