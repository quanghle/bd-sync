//! Small SQL builder for the dynamic WHERE clauses of list/ready/reclaim.

use rusqlite::types::Value as SqlValue;

use crate::model::WorkFilter;

/// Accumulates CTEs, WHERE clauses, and their positional parameters in the
/// order they appear in the final statement.
#[derive(Default)]
pub(crate) struct QueryParts {
    ctes: Vec<String>,
    cte_params: Vec<SqlValue>,
    conds: String,
    cond_params: Vec<SqlValue>,
}

impl QueryParts {
    pub fn cte(&mut self, sql: &str, params: impl IntoIterator<Item = SqlValue>) {
        self.ctes.push(sql.to_string());
        self.cte_params.extend(params);
    }

    pub fn cond(&mut self, sql: &str, params: impl IntoIterator<Item = SqlValue>) {
        self.conds.push_str(" AND ");
        self.conds.push_str(sql);
        self.cond_params.extend(params);
    }

    /// Build `WITH ... <select> WHERE 1=1 <conds> <tail>`; `tail_params`
    /// bind placeholders in `tail` (ORDER BY / LIMIT).
    pub fn build(self, select: &str, tail: &str, tail_params: Vec<SqlValue>) -> (String, Vec<SqlValue>) {
        let mut sql = String::new();
        if !self.ctes.is_empty() {
            sql.push_str("WITH RECURSIVE ");
            sql.push_str(&self.ctes.join(", "));
            sql.push(' ');
        }
        sql.push_str(select);
        sql.push_str(" WHERE 1=1");
        sql.push_str(&self.conds);
        sql.push(' ');
        sql.push_str(tail);
        let mut params = self.cte_params;
        params.extend(self.cond_params);
        params.extend(tail_params);
        (sql, params)
    }
}

pub(crate) fn placeholders(n: usize) -> String {
    let mut s = String::from("(");
    for i in 0..n {
        if i > 0 {
            s.push(',');
        }
        s.push('?');
    }
    s.push(')');
    s
}

pub(crate) fn text_values(items: &[String]) -> Vec<SqlValue> {
    items.iter().map(|s| SqlValue::Text(s.clone())).collect()
}

/// Every issue below `parent` in the hierarchy (any depth).
pub(crate) const UNDER_CTE: &str = "under(id) AS (
    SELECT issue_id FROM dependencies WHERE depends_on_id = ? AND dep_type = 'parent-child'
    UNION
    SELECT d.issue_id FROM dependencies d JOIN under u ON d.depends_on_id = u.id
    WHERE d.dep_type = 'parent-child')";

/// Apply a [`WorkFilter`] to issues aliased as `i`.
pub(crate) fn apply_work_filter(q: &mut QueryParts, f: &WorkFilter) {
    if f.unassigned {
        q.cond("i.assignee IS NULL", []);
    } else if let Some(a) = &f.assignee {
        q.cond("i.assignee = ?", [SqlValue::Text(a.clone())]);
    }
    if !f.types.is_empty() {
        q.cond(&format!("i.issue_type IN {}", placeholders(f.types.len())), text_values(&f.types));
    }
    if !f.exclude_types.is_empty() {
        q.cond(&format!("i.issue_type NOT IN {}", placeholders(f.exclude_types.len())), text_values(&f.exclude_types));
    }
    if let Some(p) = f.priority {
        q.cond("i.priority = ?", [SqlValue::Integer(i64::from(p))]);
    }
    if let Some(p) = f.max_priority {
        q.cond("i.priority <= ?", [SqlValue::Integer(i64::from(p))]);
    }
    for label in &f.labels_all {
        q.cond(
            "EXISTS (SELECT 1 FROM labels l WHERE l.issue_id = i.id AND l.label = ?)",
            [SqlValue::Text(label.clone())],
        );
    }
    if !f.labels_any.is_empty() {
        q.cond(
            &format!(
                "EXISTS (SELECT 1 FROM labels l WHERE l.issue_id = i.id AND l.label IN {})",
                placeholders(f.labels_any.len())
            ),
            text_values(&f.labels_any),
        );
    }
    if !f.exclude_labels.is_empty() {
        q.cond(
            &format!(
                "NOT EXISTS (SELECT 1 FROM labels l WHERE l.issue_id = i.id AND l.label IN {})",
                placeholders(f.exclude_labels.len())
            ),
            text_values(&f.exclude_labels),
        );
    }
    if let Some(parent) = &f.parent {
        q.cte(UNDER_CTE, [SqlValue::Text(parent.clone())]);
        q.cond("i.id IN (SELECT id FROM under)", []);
    }
    if !f.ids.is_empty() {
        q.cond(&format!("i.id IN {}", placeholders(f.ids.len())), text_values(&f.ids));
    }
}

/// Escape `%`, `_` and `\` for a LIKE pattern using `ESCAPE '\'`.
pub(crate) fn like_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}
