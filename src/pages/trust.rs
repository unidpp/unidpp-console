//! The trust surface: anchors, standing, the graded readings.

use std::sync::Arc;

use axum::extract::State;
use axum::response::Response;
#[allow(unused)]
use serde::Deserialize;

use crate::html::esc;
#[allow(unused)]
use crate::http;
#[allow(unused)]
use crate::verify;
use crate::{page_for, AppState};

pub(crate) async fn trust_page(State(state): State<Arc<AppState>>) -> Response {
    let body = match trust_render(&state).await {
        Ok(body) => body,
        Err(error) => format!(r#"<div class="error">{}</div>"#, esc(&error)),
    };
    page_for(&state, "Trust", "trust", body)
}

pub(crate) async fn trust_render(state: &Arc<AppState>) -> Result<String, String> {
    let port = state
        .with_manifest(|m| {
            m.services
                .trust
                .as_ref()
                .and_then(|s| http::port_of(&s.bind))
        })
        .ok_or("this deployment declares no trust service")?;

    let mut probes = http::get_all(&[(Some(port), "/keyring"), (Some(port), "/revocations")]).await;
    let keyring = probes[0]
        .take()
        .and_then(|r| r.json())
        .ok_or("the trust service is unreachable")?;
    let revocations = probes[1].take().and_then(|r| r.json());

    let mode = keyring.get("mode").and_then(|m| m.as_str()).unwrap_or("—");
    let mut roles = Vec::new();
    if let Some(map) = keyring.get("roles").and_then(|r| r.as_object()) {
        for (role, entry) in map {
            roles.push(format!(
                r#"<tr><td><code>{}</code></td><td>{}</td><td><code>{}</code></td><td style="word-break:break-all"><code>{}</code></td></tr>"#,
                esc(role),
                esc(entry.get("suite").and_then(|v| v.as_str()).unwrap_or("—")),
                esc(entry.get("key_id").and_then(|v| v.as_str()).unwrap_or("—")),
                esc(entry
                    .get("public_serialized")
                    .and_then(|v| v.as_str())
                    .unwrap_or("—")),
            ));
        }
    }
    roles.sort();

    let mut rows = Vec::new();
    if let Some(doc) = &revocations {
        for r in doc
            .get("revocations")
            .and_then(|v| v.as_array())
            .unwrap_or(&vec![])
        {
            let subject = r
                .get("subject")
                .and_then(|s| s.get("label"))
                .and_then(|v| v.as_str())
                .unwrap_or("—");
            let reason = r
                .get("reason")
                .and_then(|s| s.get("token"))
                .and_then(|v| v.as_str())
                .unwrap_or("—");
            let retro = r
                .get("reason")
                .and_then(|s| s.get("retroactive"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let window = r
                .get("window")
                .map(|w| {
                    let start = w.get("start").and_then(|v| v.as_str()).unwrap_or("—");
                    let end = w.get("end").and_then(|v| v.as_str()).unwrap_or("open");
                    format!("{start} .. {end}")
                })
                .unwrap_or_else(|| "—".to_string());
            let standing = r
                .get("standing_at_as_of")
                .and_then(|v| v.as_str())
                .unwrap_or("—");
            let quorum = r
                .get("quorum")
                .map(|q| match q.get("quorate").and_then(|v| v.as_bool()) {
                    Some(true) => format!(
                        "quorate ({} × {}, form {})",
                        q.get("threshold").and_then(|v| v.as_u64()).unwrap_or(0),
                        q.get("quorum").and_then(|v| v.as_str()).unwrap_or("—"),
                        q.get("form").and_then(|v| v.as_str()).unwrap_or("—"),
                    ),
                    _ => "not quorate".to_string(),
                })
                .unwrap_or_else(|| "—".to_string());
            let badge = match standing {
                "valid" => "ok",
                "void-ab-initio" | "suspended-from" => "bad",
                _ => "warn",
            };
            rows.push(format!(
                r#"<tr><td><code>{}</code></td><td>{}{}</td><td><code>{}</code></td><td><span class="badge {}">{}</span></td><td>{}</td></tr>"#,
                esc(subject),
                esc(reason),
                if retro { " · retroactive" } else { "" },
                esc(&window),
                badge,
                esc(standing),
                esc(&quorum),
            ));
        }
    }
    let revocations_html = if rows.is_empty() {
        r#"<p>No revocations in force.</p>"#.to_string()
    } else {
        format!(
            r#"<h2>Revocations in force</h2>
<table><tr><th>Subject</th><th>Reason</th><th>Window</th><th>Standing</th><th>Quorum</th></tr>{}</table>
<p class="note">Standing is read as of now; retroactive windows void
their span ab initio — query the trust API with <code>?at=</code> for
any other moment.</p>"#,
            rows.join("")
        )
    };

    Ok(format!(
        r#"<h1>{title}</h1>
<p class="note">The anchors a verifier pins and the revocations in
force — read live from the trust service ({mode} mode). The
serialized anchors are the exact <code>suite:hex</code> forms
<code>unidpp verify --anchor</code> parses.</p>
<h2>Keyring</h2>
<table><tr><th>Role</th><th>Suite</th><th>Key id</th><th>Anchor</th></tr>{roles}</table>
{revocations_html}"#,
        title = "Trust",
        roles = roles.join(""),
    ))
}

// ---------------------------------------------------------------------------
// Backups (#111): the console triggers the operator script and lists
// the results; the logic lives in one place (unidpp-ops), never here.
// ---------------------------------------------------------------------------
