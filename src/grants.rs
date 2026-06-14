//! Row-level access grants (the GRANT language).
//!
//! A grant is a *contract*: `GRANT read, write ON messages WHERE user_id =
//! auth.uid()` means a token user may query `messages`, but only for rows their
//! query already restricts to `user_id = <their uid>`. It is NOT a filter that
//! gets silently AND'ed in. On every request the server resolves the grant
//! predicate against the principal and checks that the client's query
//! **satisfies** it (contains the grant's conditions). If it does, the query
//! runs as written; if not, it's rejected. The client must explicitly scope its
//! query to what it's entitled to.
//!
//! Scopes: `read` (SELECT and `.live()`) and `write` (INSERT/UPDATE/DELETE).
//! No grant for a (table, scope) => deny-by-default. Operator / service key
//! bypasses grants entirely.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Read,
    Write,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Read => "read",
            Scope::Write => "write",
        }
    }
    pub fn parse(s: &str) -> Option<Scope> {
        match s.to_ascii_lowercase().as_str() {
            "read" => Some(Scope::Read),
            "write" => Some(Scope::Write),
            _ => None,
        }
    }
}

/// Right-hand side of a grant condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operand {
    /// `auth.uid()` - the principal's user id.
    AuthUid,
    /// `auth.<claim>` - a named claim from the principal (e.g. `auth.role`).
    AuthClaim(String),
    /// A literal value.
    Literal(String),
}

/// A single `column <op> <operand>` condition in a grant predicate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Condition {
    pub column: String,
    pub op: String,
    pub operand: Operand,
}

/// A grant predicate: a conjunction (AND) of conditions. Empty = unconditional.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Predicate {
    pub conditions: Vec<Condition>,
}

/// A grant: one or more scopes over a table, with a predicate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub table: String,
    pub scopes: Vec<Scope>,
    pub predicate: Predicate,
}

/// A grant condition with `auth.*` operands resolved to concrete values, plus a
/// query condition - same shape - so the two can be compared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCond {
    pub column: String,
    pub op: String,
    pub value: String,
}

const VALID_OPS: &[&str] = &["=", "!=", ">", "<", ">=", "<="];

fn parse_operand(tok: &str) -> Operand {
    if tok.eq_ignore_ascii_case("auth.uid()") {
        Operand::AuthUid
    } else if let Some(claim) = tok
        .strip_prefix("auth.")
        .or_else(|| tok.strip_prefix("AUTH."))
    {
        Operand::AuthClaim(claim.to_string())
    } else {
        Operand::Literal(tok.to_string())
    }
}

/// Parse a predicate from `column op operand [AND ...]` tokens.
pub fn parse_predicate(tokens: &[&str]) -> Result<Predicate, String> {
    let mut conditions = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        if i + 2 >= tokens.len() {
            return Err("ERR incomplete grant predicate (expected column op operand)".to_string());
        }
        let column = tokens[i].to_string();
        let op = tokens[i + 1].to_string();
        if !VALID_OPS.contains(&op.as_str()) {
            return Err(format!(
                "ERR unsupported operator '{op}' in grant (use = != > < >= <=)"
            ));
        }
        conditions.push(Condition {
            column,
            op,
            operand: parse_operand(tokens[i + 2]),
        });
        i += 3;
        if i < tokens.len() {
            if tokens[i].eq_ignore_ascii_case("AND") {
                i += 1;
            } else {
                return Err(format!(
                    "ERR expected 'AND' between grant conditions, got '{}'",
                    tokens[i]
                ));
            }
        }
    }
    Ok(Predicate { conditions })
}

/// Parse a `GRANT` body: `<read[, write]> ON <table> [WHERE <predicate>]`.
/// (The leading `GRANT` keyword is consumed by the dispatcher.) Scopes may be
/// comma- and/or space-separated.
pub fn parse_grant(tokens: &[&str]) -> Result<Grant, String> {
    let on_pos = tokens
        .iter()
        .position(|t| t.eq_ignore_ascii_case("ON"))
        .ok_or_else(|| {
            "ERR usage: GRANT <read[, write]> ON <table> [WHERE <predicate>]".to_string()
        })?;
    if on_pos == 0 {
        return Err("ERR GRANT requires at least one scope".to_string());
    }
    let mut scopes = Vec::new();
    for tok in &tokens[..on_pos] {
        let s = tok.trim_end_matches(',');
        if s.is_empty() {
            continue;
        }
        let scope =
            Scope::parse(s).ok_or_else(|| format!("ERR invalid scope '{s}' (use read/write)"))?;
        if !scopes.contains(&scope) {
            scopes.push(scope);
        }
    }
    if scopes.is_empty() {
        return Err("ERR GRANT requires at least one scope".to_string());
    }
    let table = tokens
        .get(on_pos + 1)
        .ok_or_else(|| "ERR GRANT requires a table name after ON".to_string())?
        .to_string();
    let predicate = match tokens.iter().position(|t| t.eq_ignore_ascii_case("WHERE")) {
        Some(w) => parse_predicate(&tokens[w + 1..])?,
        None => Predicate::default(),
    };
    Ok(Grant {
        table,
        scopes,
        predicate,
    })
}

/// Parse a `REVOKE` body: `<read[, write]> ON <table>`.
pub fn parse_revoke(tokens: &[&str]) -> Result<(String, Vec<Scope>), String> {
    let on_pos = tokens
        .iter()
        .position(|t| t.eq_ignore_ascii_case("ON"))
        .ok_or_else(|| "ERR usage: REVOKE <read[, write]> ON <table>".to_string())?;
    let mut scopes = Vec::new();
    for tok in &tokens[..on_pos] {
        let s = tok.trim_end_matches(',');
        if s.is_empty() {
            continue;
        }
        scopes.push(Scope::parse(s).ok_or_else(|| format!("ERR invalid scope '{s}'"))?);
    }
    let table = tokens
        .get(on_pos + 1)
        .ok_or_else(|| "ERR REVOKE requires a table name after ON".to_string())?
        .to_string();
    if scopes.is_empty() {
        return Err("ERR REVOKE requires at least one scope".to_string());
    }
    Ok((table, scopes))
}

/// Serialize a predicate to canonical text for storage / display.
pub fn predicate_to_string(pred: &Predicate) -> String {
    pred.conditions
        .iter()
        .map(|c| {
            let rhs = match &c.operand {
                Operand::AuthUid => "auth.uid()".to_string(),
                Operand::AuthClaim(name) => format!("auth.{name}"),
                Operand::Literal(v) => v.clone(),
            };
            format!("{} {} {}", c.column, c.op, rhs)
        })
        .collect::<Vec<_>>()
        .join(" AND ")
}

/// Resolve a grant predicate's `auth.*` operands against the principal into
/// concrete `(column, op, value)` conditions. `claim` looks up a claim value.
pub fn resolve(
    pred: &Predicate,
    uid: &str,
    claim: impl Fn(&str) -> Option<String>,
) -> Result<Vec<ResolvedCond>, String> {
    let mut out = Vec::with_capacity(pred.conditions.len());
    for c in &pred.conditions {
        let value = match &c.operand {
            Operand::AuthUid => uid.to_string(),
            Operand::AuthClaim(name) => claim(name)
                .ok_or_else(|| format!("ERR grant references auth.{name} but it is not present"))?,
            Operand::Literal(v) => v.clone(),
        };
        out.push(ResolvedCond {
            column: c.column.clone(),
            op: c.op.clone(),
            value,
        });
    }
    Ok(out)
}

/// True if the client's `query` conditions satisfy (imply) the resolved `grant`
/// conditions: every grant condition must appear in the query as an identical
/// constraint, so the query requests only grant-permitted rows. Conservative by
/// design - a query that is logically a subset but doesn't literally carry the
/// grant condition is rejected, which is safe and predictable.
pub fn query_satisfies(grant: &[ResolvedCond], query: &[ResolvedCond]) -> bool {
    grant.iter().all(|g| {
        query
            .iter()
            .any(|q| q.column == g.column && q.op == g.op && q.value == g.value)
    })
}

/// Compare a concrete value against `op target`, numeric when both parse.
fn cmp(actual: &str, op: &str, target: &str) -> bool {
    if let (Ok(a), Ok(t)) = (actual.parse::<f64>(), target.parse::<f64>()) {
        return match op {
            "=" => a == t,
            "!=" => a != t,
            ">" => a > t,
            "<" => a < t,
            ">=" => a >= t,
            "<=" => a <= t,
            _ => false,
        };
    }
    match op {
        "=" => actual == target,
        "!=" => actual != target,
        ">" => actual > target,
        "<" => actual < target,
        ">=" => actual >= target,
        "<=" => actual <= target,
        _ => false,
    }
}

/// WITH CHECK: true if the row (looked up by `value(column)`) satisfies every
/// resolved grant condition. Used on writes - the new row must fall inside the
/// grant (e.g. you can't insert a row with someone else's `user_id`).
pub fn row_satisfies(grant: &[ResolvedCond], value: impl Fn(&str) -> Option<String>) -> bool {
    grant.iter().all(|g| {
        value(&g.column)
            .map(|v| cmp(&v, &g.op, &g.value))
            .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rc(col: &str, op: &str, val: &str) -> ResolvedCond {
        ResolvedCond {
            column: col.into(),
            op: op.into(),
            value: val.into(),
        }
    }

    #[test]
    fn grant_read_write_one_statement() {
        let g = parse_grant(&[
            "read,",
            "write",
            "ON",
            "messages",
            "WHERE",
            "user_id",
            "=",
            "auth.uid()",
        ])
        .unwrap();
        assert_eq!(g.table, "messages");
        assert_eq!(g.scopes, vec![Scope::Read, Scope::Write]);
        assert_eq!(g.predicate.conditions[0].operand, Operand::AuthUid);
    }

    #[test]
    fn grant_single_scope_no_predicate() {
        let g = parse_grant(&["read", "ON", "public_posts"]).unwrap();
        assert_eq!(g.scopes, vec![Scope::Read]);
        assert!(g.predicate.conditions.is_empty());
    }

    #[test]
    fn resolve_auth_uid_and_claim() {
        let g = parse_grant(&[
            "read",
            "ON",
            "docs",
            "WHERE",
            "owner",
            "=",
            "auth.uid()",
            "AND",
            "org",
            "=",
            "auth.org_id",
        ])
        .unwrap();
        let resolved = resolve(&g.predicate, "123abc", |c| {
            (c == "org_id").then(|| "acme".to_string())
        })
        .unwrap();
        assert_eq!(
            resolved,
            vec![rc("owner", "=", "123abc"), rc("org", "=", "acme")]
        );
    }

    #[test]
    fn resolve_missing_claim_errors() {
        let g = parse_grant(&["read", "ON", "docs", "WHERE", "org", "=", "auth.org_id"]).unwrap();
        assert!(resolve(&g.predicate, "123abc", |_| None).is_err());
    }

    // ---- query-satisfies-grant: the security crux ----

    #[test]
    fn query_matching_grant_is_allowed() {
        let grant = vec![rc("user_id", "=", "123abc")];
        assert!(query_satisfies(&grant, &[rc("user_id", "=", "123abc")]));
        // query is stricter (extra filter) - still satisfies
        assert!(query_satisfies(
            &grant,
            &[rc("user_id", "=", "123abc"), rc("status", "=", "active")]
        ));
    }

    #[test]
    fn unscoped_query_is_denied() {
        let grant = vec![rc("user_id", "=", "123abc")];
        // no filter at all -> asks for everything -> denied
        assert!(!query_satisfies(&grant, &[]));
    }

    #[test]
    fn wrong_user_is_denied() {
        let grant = vec![rc("user_id", "=", "123abc")];
        assert!(!query_satisfies(
            &grant,
            &[rc("user_id", "=", "someone_else")]
        ));
        // different operator doesn't satisfy an equality grant
        assert!(!query_satisfies(&grant, &[rc("user_id", "!=", "123abc")]));
    }

    #[test]
    fn multi_condition_grant_requires_all() {
        let grant = vec![rc("user_id", "=", "123abc"), rc("org", "=", "acme")];
        assert!(!query_satisfies(&grant, &[rc("user_id", "=", "123abc")]));
        assert!(query_satisfies(
            &grant,
            &[rc("org", "=", "acme"), rc("user_id", "=", "123abc")]
        ));
    }

    #[test]
    fn unconditional_grant_allows_any_query() {
        // GRANT read ON public_posts  (no WHERE) -> any query ok
        assert!(query_satisfies(&[], &[]));
        assert!(query_satisfies(&[], &[rc("anything", "=", "x")]));
    }

    #[test]
    fn rejects_bad_scope() {
        assert!(parse_grant(&["delete", "ON", "messages"]).is_err());
        assert!(parse_grant(&["read", "messages"]).is_err());
    }

    #[test]
    fn revoke_parses_scopes() {
        let (t, s) = parse_revoke(&["read,", "write", "ON", "messages"]).unwrap();
        assert_eq!(t, "messages");
        assert_eq!(s, vec![Scope::Read, Scope::Write]);
    }
}
