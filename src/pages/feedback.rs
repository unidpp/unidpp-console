//! The consumer-reports surface: the operator's window onto the
//! gateway's report channel (TODO 224) — the newest reports with
//! their contacts (the operator sees what the public citation form
//! withholds), linked to the public citation for cross-checking.

use std::sync::Arc;

use axum::extract::State;
use axum::response::Response;
use serde_json::Value;

use crate::html::esc;
use crate::http;
use crate::{page_for, AppState};

pub(crate) async fn feedback_page(State(state): State<Arc<AppState>>) -> Response {
    let body = match feedback_render(&state).await {
        Ok(body) => body,
        Err(error) => format!(r#"<div class="error">{}</div>"#, esc(&error)),
    };
    page_for(&state, "Consumer reports", "feedback", body)
}

pub(crate) async fn feedback_render(state: &Arc<AppState>) -> Result<String, String> {
    let (port, token) = state
        .with_manifest(|m| {
            m.services
                .gateway
                .as_ref()
                .map(|g| (http::port_of(&g.bind), g.admin_token.clone()))
        })
        .ok_or("this deployment declares no gateway service")?;
    let port = port.ok_or("the gateway's bind address has no port")?;

    let listing = match token.as_deref() {
        Some(token) => http::get_bearer(port, "/admin/feedback?limit=50", token).await,
        None => http::get_bearer(port, "/admin/feedback?limit=50", "").await,
    }
    .and_then(|r| r.json())
    .ok_or("the gateway's report channel is unreachable")?;

    let total = listing
        .get("total")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let mut rows = Vec::new();
    if let Some(records) = listing.get("records").and_then(Value::as_array) {
        for record in records {
            let seq = record.get("seq").and_then(Value::as_u64).unwrap_or_default();
            rows.push(format!(
                r#"<tr><td><a href="http://127.0.0.1:{port}/feedback/{seq}">{seq}</a></td><td>{}</td><td>{}</td><td style="word-break:break-all"><code>{}</code></td><td>{}</td><td style="word-break:break-all">{}</td></tr>"#,
                esc(record
                    .get("recorded_at")
                    .and_then(Value::as_str)
                    .unwrap_or("—")),
                esc(record
                    .get("category")
                    .and_then(Value::as_str)
                    .unwrap_or("—")),
                esc(record
                    .get("identifier")
                    .and_then(Value::as_str)
                    .unwrap_or("—")),
                esc(record
                    .get("contact")
                    .and_then(Value::as_str)
                    .filter(|c| !c.is_empty())
                    .unwrap_or("—")),
                esc(record
                    .get("details")
                    .and_then(Value::as_str)
                    .unwrap_or("—")),
            ));
        }
    }

    Ok(format!(
        r#"<h2>Consumer reports ({total})</h2>
<p>Newest first. The contact column is the operator view — the public
citation form (linked per sequence) withholds it by a stated omission.</p>
<table>
<thead><tr><th>seq</th><th>recorded</th><th>category</th><th>identifier</th><th>contact</th><th>details</th></tr></thead>
<tbody>{}</tbody>
</table>"#,
        rows.join("\n")
    ))
}
