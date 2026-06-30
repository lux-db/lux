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

/// Right-hand side of a simple grant comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operand {
    /// `auth.uid()` - the principal's user id.
    AuthUid,
    /// `auth.<claim>` - a named claim from the principal (e.g. `auth.role`).
    AuthClaim(String),
    /// A literal value.
    Literal(String),
}

/// A subquery operand: `( SELECT <projected> FROM <table> [WHERE <inner>] )`.
///
/// `inner` is uncorrelated: it may reference `auth.*`, literals, and the
/// subquery table's own columns, never the outer row. At enforcement time the
/// subquery is executed once to a set of values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subquery {
    pub projected: String,
    pub table: String,
    pub inner: Predicate,
}

/// A single condition in a grant predicate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    /// `column <op> <operand>`.
    Cmp {
        column: String,
        op: String,
        operand: Operand,
    },
    /// `column [NOT] IN ( SELECT ... )` - membership in a subquery result set.
    InSubquery {
        column: String,
        negated: bool,
        subquery: Subquery,
    },
}

/// A grant predicate: alternatives (OR) of conjunctions (AND). `conditions` is
/// the first conjunction for compatibility with older callers/tests; each entry
/// in `alternatives` is another OR branch. Empty first conjunction means
/// unconditional.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Predicate {
    pub conditions: Vec<Condition>,
    pub alternatives: Vec<Vec<Condition>>,
}

impl Predicate {
    pub fn clauses(&self) -> impl Iterator<Item = &[Condition]> {
        std::iter::once(self.conditions.as_slice())
            .chain(self.alternatives.iter().map(Vec::as_slice))
    }

    pub fn append_alternatives(&mut self, other: &Predicate) {
        if self.conditions.is_empty() || other.conditions.is_empty() {
            self.conditions.clear();
            self.alternatives.clear();
            return;
        }
        self.alternatives.push(other.conditions.clone());
        self.alternatives.extend(other.alternatives.clone());
    }
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

/// A grant condition with `auth.*` substituted, but subqueries *not yet
/// executed*. Execution needs store access, so it happens in `auth.rs`; this
/// keeps the parser/resolver in this module pure and unit-testable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedCondition {
    Cmp(ResolvedCond),
    InSubqueryResolved {
        column: String,
        negated: bool,
        inner_table: String,
        inner_projected: String,
        /// Inner WHERE conditions with `auth.*` already substituted.
        inner_conds: Vec<ResolvedCondition>,
    },
}

/// A grant condition fully resolved *and* executed: subqueries have become a
/// concrete membership set. This is what the read/write/live paths enforce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcedCondition {
    Cmp(ResolvedCond),
    /// `column [NOT] IN (<values>)`. Empty positive set => match nothing (deny);
    /// empty negated set => match everything.
    InSet {
        column: String,
        negated: bool,
        values: Vec<String>,
    },
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

/// Parse a predicate: `<condition> [AND <condition> ...]`, where a condition is
/// either `column op operand` or `column [NOT] IN ( SELECT ... )`.
pub fn parse_predicate(tokens: &[&str]) -> Result<Predicate, String> {
    let ranges = split_top_level(tokens, "OR");
    let mut clauses = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        clauses.push(parse_predicate_inner(&tokens[start..end])?);
    }
    let mut clauses = clauses.into_iter();
    let conditions = clauses.next().unwrap_or_default();
    Ok(Predicate {
        conditions,
        alternatives: clauses.collect(),
    })
}

fn split_top_level(tokens: &[&str], sep: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut depth = 0usize;
    for (i, tok) in tokens.iter().enumerate() {
        if *tok == "(" {
            depth += 1;
        } else if *tok == ")" {
            depth = depth.saturating_sub(1);
        } else if depth == 0 && tok.eq_ignore_ascii_case(sep) {
            out.push((start, i));
            start = i + 1;
        }
    }
    out.push((start, tokens.len()));
    out
}

fn parse_predicate_inner(tokens: &[&str]) -> Result<Vec<Condition>, String> {
    let mut conditions = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let (cond, next) = parse_one_condition(tokens, i)?;
        conditions.push(cond);
        i = next;
        if i < tokens.len() {
            if tokens[i].eq_ignore_ascii_case("AND") {
                i += 1;
                if i >= tokens.len() {
                    return Err("ERR trailing 'AND' in grant predicate".to_string());
                }
            } else {
                return Err(format!(
                    "ERR expected 'AND' or 'OR' between grant conditions, got '{}'",
                    tokens[i]
                ));
            }
        }
    }
    Ok(conditions)
}

/// Parse one condition starting at `i`; return it and the index just past it.
fn parse_one_condition(tokens: &[&str], i: usize) -> Result<(Condition, usize), String> {
    let column = tokens
        .get(i)
        .ok_or_else(|| "ERR incomplete grant predicate (expected column)".to_string())?
        .to_string();
    let op_tok = tokens
        .get(i + 1)
        .ok_or_else(|| format!("ERR incomplete grant condition after '{column}'"))?;

    // `column IN ( SELECT ... )`
    if op_tok.eq_ignore_ascii_case("IN") {
        let (subquery, next) = parse_subquery(tokens, i + 2)?;
        return Ok((
            Condition::InSubquery {
                column,
                negated: false,
                subquery,
            },
            next,
        ));
    }
    // `column NOT IN ( SELECT ... )`
    if op_tok.eq_ignore_ascii_case("NOT") {
        let in_tok = tokens
            .get(i + 2)
            .ok_or_else(|| format!("ERR expected 'IN' after 'NOT' for column '{column}'"))?;
        if !in_tok.eq_ignore_ascii_case("IN") {
            return Err(format!("ERR expected 'IN' after 'NOT', got '{in_tok}'"));
        }
        let (subquery, next) = parse_subquery(tokens, i + 3)?;
        return Ok((
            Condition::InSubquery {
                column,
                negated: true,
                subquery,
            },
            next,
        ));
    }

    // Simple `column op operand`.
    let op = op_tok.to_string();
    if !VALID_OPS.contains(&op.as_str()) {
        return Err(format!(
            "ERR unsupported operator '{op}' in grant (use = != > < >= <= or [NOT] IN)"
        ));
    }
    let operand_tok = tokens
        .get(i + 2)
        .ok_or_else(|| format!("ERR grant condition '{column} {op}' is missing its value"))?;
    Ok((
        Condition::Cmp {
            column,
            op,
            operand: parse_operand(operand_tok),
        },
        i + 3,
    ))
}

/// Parse `( SELECT <col> FROM <table> [WHERE <inner-pred>] )` starting at the
/// opening paren. Returns the subquery and the index just past the `)`.
fn parse_subquery(tokens: &[&str], mut i: usize) -> Result<(Subquery, usize), String> {
    let expect = |i: usize, want: &str| -> Result<(), String> {
        match tokens.get(i) {
            Some(t) if t.eq_ignore_ascii_case(want) => Ok(()),
            Some(t) => Err(format!(
                "ERR expected '{want}' in grant subquery, got '{t}'"
            )),
            None => Err(format!(
                "ERR grant subquery ended early (expected '{want}')"
            )),
        }
    };
    expect(i, "(")?;
    i += 1;
    expect(i, "SELECT")?;
    i += 1;
    let projected = tokens
        .get(i)
        .ok_or_else(|| "ERR grant subquery expects a column after SELECT".to_string())?
        .to_string();
    if projected == ")" || projected.eq_ignore_ascii_case("FROM") {
        return Err("ERR grant subquery expects a single column after SELECT".to_string());
    }
    i += 1;
    expect(i, "FROM")?;
    i += 1;
    let table = tokens
        .get(i)
        .ok_or_else(|| "ERR grant subquery expects a table after FROM".to_string())?
        .to_string();
    if table.to_ascii_lowercase().starts_with("auth.") {
        return Err("ERR grant subquery may not read reserved 'auth.*' tables".to_string());
    }
    i += 1;

    // Optional inner WHERE, gathered up to the matching `)`.
    let mut inner_tokens: Vec<&str> = Vec::new();
    if matches!(tokens.get(i), Some(t) if t.eq_ignore_ascii_case("WHERE")) {
        i += 1;
        let mut depth = 0usize;
        while i < tokens.len() {
            if tokens[i] == ")" {
                if depth == 0 {
                    break;
                }
                depth -= 1;
                inner_tokens.push(tokens[i]);
                i += 1;
                continue;
            }
            if tokens[i] == "(" {
                depth += 1;
            }
            inner_tokens.push(tokens[i]);
            i += 1;
        }
    }
    expect(i, ")")?;
    i += 1;

    let inner = parse_predicate(&inner_tokens)?;
    Ok((
        Subquery {
            projected,
            table,
            inner,
        },
        i,
    ))
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

/// Serialize a predicate to canonical text for storage / display. The output is
/// whitespace-separable so `load_grant_predicate` can re-tokenize it with
/// `split_whitespace()` and parse back an identical predicate (every token,
/// including parens, is space-delimited).
pub fn predicate_to_string(pred: &Predicate) -> String {
    pred.clauses()
        .map(|conditions| {
            conditions
                .iter()
                .map(condition_to_string)
                .collect::<Vec<_>>()
                .join(" AND ")
        })
        .collect::<Vec<_>>()
        .join(" OR ")
}

fn operand_to_string(operand: &Operand) -> String {
    match operand {
        Operand::AuthUid => "auth.uid()".to_string(),
        Operand::AuthClaim(name) => format!("auth.{name}"),
        Operand::Literal(v) => v.clone(),
    }
}

fn condition_to_string(c: &Condition) -> String {
    match c {
        Condition::Cmp {
            column,
            op,
            operand,
        } => format!("{column} {op} {}", operand_to_string(operand)),
        Condition::InSubquery {
            column,
            negated,
            subquery,
        } => {
            let kw = if *negated { "NOT IN" } else { "IN" };
            let inner = predicate_to_string(&subquery.inner);
            if inner.is_empty() {
                format!(
                    "{column} {kw} ( SELECT {} FROM {} )",
                    subquery.projected, subquery.table
                )
            } else {
                format!(
                    "{column} {kw} ( SELECT {} FROM {} WHERE {inner} )",
                    subquery.projected, subquery.table
                )
            }
        }
    }
}

fn resolve_operand(
    operand: &Operand,
    uid: &str,
    claim: &impl Fn(&str) -> Option<String>,
) -> Result<String, String> {
    Ok(match operand {
        Operand::AuthUid => uid.to_string(),
        Operand::AuthClaim(name) => claim(name)
            .ok_or_else(|| format!("ERR grant references auth.{name} but it is not present"))?,
        Operand::Literal(v) => v.clone(),
    })
}

fn resolve_predicate(
    conditions: &[Condition],
    uid: &str,
    claim: &impl Fn(&str) -> Option<String>,
) -> Result<Vec<ResolvedCondition>, String> {
    let mut out = Vec::with_capacity(conditions.len());
    for c in conditions {
        match c {
            Condition::Cmp {
                column,
                op,
                operand,
            } => out.push(ResolvedCondition::Cmp(ResolvedCond {
                column: column.clone(),
                op: op.clone(),
                value: resolve_operand(operand, uid, claim)?,
            })),
            Condition::InSubquery {
                column,
                negated,
                subquery,
            } => {
                if !subquery.inner.alternatives.is_empty() {
                    return Err("ERR OR inside grant subquery is not supported".to_string());
                }
                out.push(ResolvedCondition::InSubqueryResolved {
                    column: column.clone(),
                    negated: *negated,
                    inner_table: subquery.table.clone(),
                    inner_projected: subquery.projected.clone(),
                    inner_conds: resolve_predicate(&subquery.inner.conditions, uid, claim)?,
                });
            }
        }
    }
    Ok(out)
}

/// Resolve the first grant predicate clause's `auth.*` operands. Most callers
/// should use `resolve_clauses`; this exists for unit tests and older helpers.
#[cfg(test)]
pub fn resolve(
    pred: &Predicate,
    uid: &str,
    claim: impl Fn(&str) -> Option<String>,
) -> Result<Vec<ResolvedCondition>, String> {
    resolve_predicate(&pred.conditions, uid, &claim)
}

/// Resolve all OR branches of a grant predicate's `auth.*` operands against the
/// principal. Subquery conditions keep their resolved inner WHERE for later
/// execution.
pub fn resolve_clauses(
    pred: &Predicate,
    uid: &str,
    claim: impl Fn(&str) -> Option<String>,
) -> Result<Vec<Vec<ResolvedCondition>>, String> {
    pred.clauses()
        .map(|conditions| resolve_predicate(conditions, uid, &claim))
        .collect()
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

/// True if `value` is in (or, when negated, out of) the membership set.
/// Equality is the membership test (`IN`); both sides are canonical engine
/// string reps of the same column, so string equality is correct.
fn in_set(value: &str, negated: bool, values: &[String]) -> bool {
    let present = values.iter().any(|v| v == value);
    present != negated
}

/// WITH CHECK over enforced conditions (the new row must satisfy every one).
/// A missing column can't satisfy a condition (deny).
pub fn enforced_row_satisfies(
    conds: &[EnforcedCondition],
    value: impl Fn(&str) -> Option<String>,
) -> bool {
    conds.iter().all(|c| match c {
        EnforcedCondition::Cmp(rc) => value(&rc.column)
            .map(|v| cmp(&v, &rc.op, &rc.value))
            .unwrap_or(false),
        EnforcedCondition::InSet {
            column,
            negated,
            values,
        } => value(column)
            .map(|v| in_set(&v, *negated, values))
            .unwrap_or(false),
    })
}

/// UPDATE WITH CHECK: only re-validate conditions whose column the statement
/// actually sets (untouched columns were already in-scope via USING).
pub fn enforced_set_satisfies(conds: &[EnforcedCondition], set_fields: &[(&str, &str)]) -> bool {
    conds.iter().all(|c| {
        let col = match c {
            EnforcedCondition::Cmp(rc) => rc.column.as_str(),
            EnforcedCondition::InSet { column, .. } => column.as_str(),
        };
        match set_fields.iter().find(|(f, _)| *f == col) {
            None => true,
            Some((_, new_val)) => match c {
                EnforcedCondition::Cmp(rc) => cmp(new_val, &rc.op, &rc.value),
                EnforcedCondition::InSet {
                    negated, values, ..
                } => in_set(new_val, *negated, values),
            },
        }
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
        assert!(matches!(
            &g.predicate.conditions[0],
            Condition::Cmp {
                operand: Operand::AuthUid,
                ..
            }
        ));
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
            vec![
                ResolvedCondition::Cmp(rc("owner", "=", "123abc")),
                ResolvedCondition::Cmp(rc("org", "=", "acme")),
            ]
        );
    }

    #[test]
    fn resolve_missing_claim_errors() {
        let g = parse_grant(&["read", "ON", "docs", "WHERE", "org", "=", "auth.org_id"]).unwrap();
        assert!(resolve(&g.predicate, "123abc", |_| None).is_err());
    }

    // ---- WITH CHECK (enforced_row_satisfies): the write-side security crux ----

    fn ec(col: &str, op: &str, val: &str) -> EnforcedCondition {
        EnforcedCondition::Cmp(rc(col, op, val))
    }

    #[test]
    fn row_inside_grant_is_allowed() {
        let grant = vec![ec("user_id", "=", "123abc")];
        let row = |c: &str| (c == "user_id").then(|| "123abc".to_string());
        assert!(enforced_row_satisfies(&grant, row));
    }

    #[test]
    fn row_outside_grant_is_denied() {
        let grant = vec![ec("user_id", "=", "123abc")];
        let row = |c: &str| (c == "user_id").then(|| "someone_else".to_string());
        assert!(!enforced_row_satisfies(&grant, row));
        // a missing column can't satisfy a grant condition
        assert!(!enforced_row_satisfies(&grant, |_| None));
    }

    #[test]
    fn row_must_satisfy_every_condition() {
        let grant = vec![ec("user_id", "=", "123abc"), ec("org", "=", "acme")];
        let only_user = |c: &str| (c == "user_id").then(|| "123abc".to_string());
        assert!(!enforced_row_satisfies(&grant, only_user));
        let both = |c: &str| match c {
            "user_id" => Some("123abc".to_string()),
            "org" => Some("acme".to_string()),
            _ => None,
        };
        assert!(enforced_row_satisfies(&grant, both));
    }

    #[test]
    fn unconditional_grant_admits_any_row() {
        // GRANT write ON public_posts (no WHERE) -> any row passes WITH CHECK.
        assert!(enforced_row_satisfies(&[], |_| None));
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

    // ---- subquery (membership) grants ----

    /// `messages WHERE workspace_id IN ( SELECT workspace_id FROM members WHERE user_id = auth.uid() )`
    fn membership_grant() -> Grant {
        parse_grant(&[
            "read",
            "ON",
            "messages",
            "WHERE",
            "workspace_id",
            "IN",
            "(",
            "SELECT",
            "workspace_id",
            "FROM",
            "members",
            "WHERE",
            "user_id",
            "=",
            "auth.uid()",
            ")",
        ])
        .unwrap()
    }

    #[test]
    fn parses_in_subquery() {
        let g = membership_grant();
        match &g.predicate.conditions[0] {
            Condition::InSubquery {
                column,
                negated,
                subquery,
            } => {
                assert_eq!(column, "workspace_id");
                assert!(!negated);
                assert_eq!(subquery.projected, "workspace_id");
                assert_eq!(subquery.table, "members");
                assert_eq!(subquery.inner.conditions.len(), 1);
            }
            other => panic!("expected InSubquery, got {other:?}"),
        }
    }

    #[test]
    fn parses_not_in_subquery() {
        let g = parse_grant(&[
            "read",
            "ON",
            "messages",
            "WHERE",
            "workspace_id",
            "NOT",
            "IN",
            "(",
            "SELECT",
            "workspace_id",
            "FROM",
            "banned",
            ")",
        ])
        .unwrap();
        match &g.predicate.conditions[0] {
            Condition::InSubquery {
                negated, subquery, ..
            } => {
                assert!(negated);
                assert!(subquery.inner.conditions.is_empty()); // no inner WHERE
            }
            other => panic!("expected InSubquery, got {other:?}"),
        }
    }

    #[test]
    fn subquery_round_trips_through_string() {
        let g = membership_grant();
        let s = predicate_to_string(&g.predicate);
        assert_eq!(
            s,
            "workspace_id IN ( SELECT workspace_id FROM members WHERE user_id = auth.uid() )"
        );
        // The stored string re-tokenizes (split_whitespace) and parses identically.
        let toks: Vec<&str> = s.split_whitespace().collect();
        let reparsed = parse_predicate(&toks).unwrap();
        assert_eq!(reparsed, g.predicate);
    }

    #[test]
    fn subquery_combines_with_cmp() {
        let g = parse_grant(&[
            "read",
            "ON",
            "messages",
            "WHERE",
            "tenant",
            "=",
            "auth.org_id",
            "AND",
            "workspace_id",
            "IN",
            "(",
            "SELECT",
            "workspace_id",
            "FROM",
            "members",
            "WHERE",
            "user_id",
            "=",
            "auth.uid()",
            ")",
        ])
        .unwrap();
        assert_eq!(g.predicate.conditions.len(), 2);
        assert!(matches!(g.predicate.conditions[0], Condition::Cmp { .. }));
        assert!(matches!(
            g.predicate.conditions[1],
            Condition::InSubquery { .. }
        ));
    }

    #[test]
    fn predicate_round_trips_or_alternatives() {
        let g = parse_grant(&[
            "read",
            "ON",
            "profiles",
            "WHERE",
            "id",
            "=",
            "auth.uid()",
            "OR",
            "id",
            "IN",
            "(",
            "SELECT",
            "user_id",
            "FROM",
            "members",
            "WHERE",
            "team_id",
            "IN",
            "(",
            "SELECT",
            "team_id",
            "FROM",
            "members",
            "WHERE",
            "user_id",
            "=",
            "auth.uid()",
            ")",
            ")",
        ])
        .unwrap();
        let s = predicate_to_string(&g.predicate);
        assert_eq!(
            s,
            "id = auth.uid() OR id IN ( SELECT user_id FROM members WHERE team_id IN ( SELECT team_id FROM members WHERE user_id = auth.uid() ) )"
        );
        let toks: Vec<&str> = s.split_whitespace().collect();
        let reparsed = parse_predicate(&toks).unwrap();
        assert_eq!(reparsed, g.predicate);
        assert_eq!(g.predicate.conditions.len(), 1);
        assert_eq!(g.predicate.alternatives.len(), 1);
    }

    #[test]
    fn parses_nested_subquery() {
        let g = parse_grant(&[
            "read", "ON", "m", "WHERE", "a", "IN", "(", "SELECT", "x", "FROM", "t", "WHERE", "y",
            "IN", "(", "SELECT", "z", "FROM", "u", ")", ")",
        ])
        .unwrap();
        let s = predicate_to_string(&g.predicate);
        assert_eq!(s, "a IN ( SELECT x FROM t WHERE y IN ( SELECT z FROM u ) )");
        let toks: Vec<&str> = s.split_whitespace().collect();
        let reparsed = parse_predicate(&toks).unwrap();
        assert_eq!(reparsed, g.predicate);
        match &g.predicate.conditions[0] {
            Condition::InSubquery { subquery, .. } => {
                assert!(matches!(
                    subquery.inner.conditions[0],
                    Condition::InSubquery { .. }
                ));
            }
            other => panic!("expected InSubquery, got {other:?}"),
        }
    }

    #[test]
    fn parses_team_membership_grant_with_two_subquery_layers() {
        let g = parse_grant(&[
            "read",
            "ON",
            "profiles",
            "WHERE",
            "id",
            "IN",
            "(",
            "SELECT",
            "user_id",
            "FROM",
            "members",
            "WHERE",
            "team_id",
            "IN",
            "(",
            "SELECT",
            "team_id",
            "FROM",
            "members",
            "WHERE",
            "user_id",
            "=",
            "auth.uid()",
            ")",
            ")",
        ])
        .unwrap();
        assert_eq!(
            predicate_to_string(&g.predicate),
            "id IN ( SELECT user_id FROM members WHERE team_id IN ( SELECT team_id FROM members WHERE user_id = auth.uid() ) )"
        );
    }

    #[test]
    fn rejects_reserved_inner_table() {
        let err = parse_grant(&[
            "read",
            "ON",
            "m",
            "WHERE",
            "a",
            "IN",
            "(",
            "SELECT",
            "id",
            "FROM",
            "auth.users",
            ")",
        ])
        .unwrap_err();
        assert!(err.contains("reserved"), "got: {err}");
    }

    #[test]
    fn rejects_cmp_operator_with_subquery_keywords() {
        // `=` cannot take a subquery; only IN / NOT IN do.
        let g = parse_grant(&[
            "read", "ON", "m", "WHERE", "a", "=", "(", "SELECT", "x", "FROM", "t", ")",
        ]);
        // `=` parses `(` as a literal operand, leaving stray tokens => error.
        assert!(g.is_err());
    }

    #[test]
    fn resolve_substitutes_inside_subquery() {
        let g = membership_grant();
        let resolved = resolve(&g.predicate, "user-42", |_| None).unwrap();
        match &resolved[0] {
            ResolvedCondition::InSubqueryResolved {
                column,
                negated,
                inner_table,
                inner_projected,
                inner_conds,
            } => {
                assert_eq!(column, "workspace_id");
                assert!(!negated);
                assert_eq!(inner_table, "members");
                assert_eq!(inner_projected, "workspace_id");
                assert_eq!(
                    inner_conds,
                    &vec![ResolvedCondition::Cmp(rc("user_id", "=", "user-42"))]
                );
            }
            other => panic!("expected InSubqueryResolved, got {other:?}"),
        }
    }

    #[test]
    fn resolve_substitutes_inside_nested_subquery() {
        let g = parse_grant(&[
            "read",
            "ON",
            "profiles",
            "WHERE",
            "id",
            "IN",
            "(",
            "SELECT",
            "user_id",
            "FROM",
            "members",
            "WHERE",
            "team_id",
            "IN",
            "(",
            "SELECT",
            "team_id",
            "FROM",
            "members",
            "WHERE",
            "user_id",
            "=",
            "auth.uid()",
            ")",
            ")",
        ])
        .unwrap();
        let resolved = resolve(&g.predicate, "user-42", |_| None).unwrap();
        match &resolved[0] {
            ResolvedCondition::InSubqueryResolved {
                inner_table,
                inner_projected,
                inner_conds,
                ..
            } => {
                assert_eq!(inner_table, "members");
                assert_eq!(inner_projected, "user_id");
                match &inner_conds[0] {
                    ResolvedCondition::InSubqueryResolved {
                        inner_table,
                        inner_projected,
                        inner_conds,
                        ..
                    } => {
                        assert_eq!(inner_table, "members");
                        assert_eq!(inner_projected, "team_id");
                        assert_eq!(
                            inner_conds,
                            &vec![ResolvedCondition::Cmp(rc("user_id", "=", "user-42"))]
                        );
                    }
                    other => panic!("expected nested InSubqueryResolved, got {other:?}"),
                }
            }
            other => panic!("expected InSubqueryResolved, got {other:?}"),
        }
    }

    #[test]
    fn resolve_missing_claim_inside_subquery_errors() {
        let g = parse_grant(&[
            "read",
            "ON",
            "m",
            "WHERE",
            "a",
            "IN",
            "(",
            "SELECT",
            "x",
            "FROM",
            "t",
            "WHERE",
            "org",
            "=",
            "auth.org_id",
            ")",
        ])
        .unwrap();
        assert!(resolve(&g.predicate, "u", |_| None).is_err());
    }

    // ---- enforced (post-execution) membership checks ----

    #[test]
    fn enforced_in_set_membership() {
        let conds = vec![EnforcedCondition::InSet {
            column: "workspace_id".into(),
            negated: false,
            values: vec!["w1".into(), "w2".into()],
        }];
        let row = |c: &str| (c == "workspace_id").then(|| "w1".to_string());
        assert!(enforced_row_satisfies(&conds, row));
        let outside = |c: &str| (c == "workspace_id").then(|| "w9".to_string());
        assert!(!enforced_row_satisfies(&conds, outside));
    }

    #[test]
    fn enforced_empty_in_set_denies_but_empty_not_in_admits() {
        let deny = vec![EnforcedCondition::InSet {
            column: "w".into(),
            negated: false,
            values: vec![],
        }];
        assert!(!enforced_row_satisfies(&deny, |c| (c == "w").then(|| "x".into())));
        let admit = vec![EnforcedCondition::InSet {
            column: "w".into(),
            negated: true,
            values: vec![],
        }];
        assert!(enforced_row_satisfies(&admit, |c| (c == "w").then(|| "x".into())));
    }

    #[test]
    fn enforced_set_satisfies_only_checks_touched_columns() {
        let conds = vec![EnforcedCondition::InSet {
            column: "workspace_id".into(),
            negated: false,
            values: vec!["w1".into()],
        }];
        // Not setting workspace_id => fine (USING already scoped the row).
        assert!(enforced_set_satisfies(&conds, &[("body", "hello")]));
        // Setting it out of the membership set => denied.
        assert!(!enforced_set_satisfies(&conds, &[("workspace_id", "w9")]));
        assert!(enforced_set_satisfies(&conds, &[("workspace_id", "w1")]));
    }
}
