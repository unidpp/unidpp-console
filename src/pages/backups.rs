//! The backup surfaces: list, run, drill — the durability script contract surfaced.

use crate::i18n;
use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
#[allow(unused)]
use serde::Deserialize;

use crate::html::esc;
#[allow(unused)]
use crate::http;
#[allow(unused)]
use crate::verify;
use crate::{page_for, AppState};

/// The backups view: the bundle, its consistency point and the restore drills.
#[utoipa::path(
    get,
    path = "/backups",
    tag = "console",
    responses(
        (status = 200, description = "The page, rendered against the deployment manifest", body = String, content_type = "text/html"),
        (status = 303, description = "The session gate redirects an unauthenticated browser to `/login`"),
    )
)]
pub(crate) async fn backups_page(State(state): State<Arc<AppState>>) -> Response {
    let body = match backups_render(&state).await {
        Ok(body) => body,
        Err(error) => format!(r#"<div class="error">{}</div>"#, esc(&error)),
    };
    page_for(&state, "Backups", "backups", body)
}

pub(crate) async fn backups_render(state: &Arc<AppState>) -> Result<String, String> {
    let root = state
        .config
        .manifest_path
        .parent()
        .ok_or("no deployment root")?
        .to_path_buf();
    let dir = root.join("backups");
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let script = root.join("unidpp-ops");
    if !script.is_file() {
        return Ok(r#"<h1>Backups</h1><div class="error">The operator
script <code>unidpp-ops</code> is not present in the deployment
root.</div>"#
            .to_string());
    }
    let mut rows = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .map_err(|e| format!("cannot read {}: {e}", dir.display()))?
        .flatten()
        .collect();
    entries.sort_by_key(|e| e.file_name());
    entries.reverse();
    for entry in entries {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.ends_with(".tar.gz") {
            let meta = entry.metadata().ok();
            let size_kb = meta.as_ref().map(|m| m.len() / 1024).unwrap_or(0);
            rows.push(format!(
                r#"<tr><td><code>{}</code></td><td>{} KB</td></tr>"#,
                esc(&name),
                size_kb
            ));
        }
    }
    let listing = if rows.is_empty() {
        r#"<p>No backups yet.</p>"#.to_string()
    } else {
        format!(
            r#"<h2>Backups</h2><table><tr><th>Archive</th><th>Size</th></tr>{}</table>"#,
            rows.join("")
        )
    };
    // The schedule state (the script is the single home of the logic).
    let schedule = match std::process::Command::new("./unidpp-ops")
        .arg("schedule")
        .arg("--status")
        .current_dir(&root)
        .output()
    {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        }
        _ => "unknown (cannot ask unidpp-ops)".to_string(),
    };
    // The newest drill report (what was proven, when).
    let mut drills: Vec<_> = std::fs::read_dir(&dir)
        .map(|it| {
            it.flatten()
                .filter(|e| e.file_name().to_string_lossy().ends_with(".drill.json"))
                .collect()
        })
        .unwrap_or_default();
    drills.sort_by_key(|e| e.file_name());
    drills.reverse();
    let drill_html = match drills.first() {
        Some(entry) => {
            let path = entry.path();
            let doc = std::fs::read_to_string(&path)
                .ok()
                .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok());
            match doc {
                Some(doc) => {
                    let get = |k: &str| {
                        doc.get(k)
                            .and_then(|v| v.as_str())
                            .unwrap_or("—")
                            .to_string()
                    };
                    format!(
                        r#"<h2>Last restore drill</h2>
<table>
<tr><th>Drill</th><td><code>{}</code></td></tr>
<tr><th>Byte parity</th><td>{}</td></tr>
<tr><th>Restored manifest</th><td>{}</td></tr>
<tr><th>Consistency point</th><td><code>{}</code></td></tr>
</table>
<p class="note">Run <code>./unidpp-ops drill</code> after every
upgrade rehearsal. A backup nobody ever restored is a hope.</p>"#,
                        esc(&get("drill")),
                        esc(&get("byte_parity")),
                        esc(&get("manifest_validated")),
                        esc(&get("consistency_point")),
                    )
                }
                None => r#"<h2>Last restore drill</h2>
<p class="error">The newest drill report does not parse: {}</p>"#
                    .replace("{}", &esc(&path.display().to_string())),
            }
        }
        None => r#"<h2>Last restore drill</h2>
<p>No drill has run yet — a backup nobody ever restored is a hope,
not a capability.</p>"#
            .to_string(),
    };
    let backup_btn = state.with_manifest(|m| i18n::t(&m.branding.locale, "btn.backup"));
    let drill_btn = state.with_manifest(|m| i18n::t(&m.branding.locale, "btn.drill"));
    Ok(format!(
        r#"<h1>Backups</h1>
<p class="note">A backup is the deployment as data: the manifest, every
journal, the seed — checksummed, with the log tree head as the
consistency point. Restore is <code>unidpp-ops restore</code>.</p>
{listing}
{drill_html}
<h2>Schedule</h2>
<p>{}</p>
<h2>Take one now</h2>
<form method="post" action="/backups" style="display:inline">
  <button type="submit">{backup_btn}</button>
</form>
<form method="post" action="/backups/drill" style="display:inline">
  <button type="submit" class="secondary">{drill_btn}</button>
</form>
<p class="note">Requires a signed-in session.</p>"#,
        esc(&schedule),
        backup_btn = backup_btn,
        drill_btn = drill_btn,
    ))
}

/// Run a backup operation.
#[utoipa::path(
    post,
    path = "/backups",
    tag = "console",
    request_body(content = String, content_type = "application/x-www-form-urlencoded", description = "The backup form: the operation to run"),
    responses(
        (status = 303, description = "Run: a redirect back to the view with the result stated"),
        (status = 200, description = "The form is re-rendered with its error stated", body = String, content_type = "text/html"),
    )
)]
pub(crate) async fn backups_run(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if !state.session_valid(&headers) {
        return page_for(
            &state,
            "Backups",
            "backups",
            r#"<div class="error">Backups require a signed-in session.
<a href="/login">Sign in</a>.</div>"#
                .to_string(),
        );
    }
    let root = state
        .config
        .manifest_path
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let output = std::process::Command::new("./unidpp-ops")
        .arg("backup")
        .current_dir(&root)
        .output();
    let body = match output {
        Ok(output) if output.status.success() => format!(
            r#"<div class="note">Backup taken.</div><pre>{}</pre>
<a href="/backups">← backups</a>"#,
            esc(&String::from_utf8_lossy(&output.stdout))
        ),
        Ok(output) => format!(
            r#"<div class="error">The script failed, and nothing was lost.</div><pre>{}</pre>
<a href="/backups">← back</a>"#,
            esc(&String::from_utf8_lossy(&output.stderr))
        ),
        Err(e) => format!(
            r#"<div class="error">cannot run unidpp-ops: {e}</div><a href="/backups">← back</a>"#
        ),
    };
    page_for(&state, "Backups", "backups", body)
}

/// POST /backups/drill — run the restore rehearsal through the
/// operator script (session-gated; the script owns the logic).
#[utoipa::path(
    post,
    path = "/backups/drill",
    tag = "console",
    request_body(content = String, content_type = "application/x-www-form-urlencoded", description = "The drill form: the bundle to restore"),
    responses(
        (status = 303, description = "Drilled: a redirect back to the view with the drill report stated"),
        (status = 200, description = "The form is re-rendered with its error stated", body = String, content_type = "text/html"),
    )
)]
pub(crate) async fn backups_drill(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if !state.session_valid(&headers) {
        return page_for(
            &state,
            "Backups",
            "backups",
            r#"<div class="error">Drills require a signed-in session.
<a href="/login">Sign in</a>.</div>"#
                .to_string(),
        );
    }
    let root = state
        .config
        .manifest_path
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let output = std::process::Command::new("./unidpp-ops")
        .arg("drill")
        .current_dir(&root)
        .output();
    let body = match output {
        Ok(output) if output.status.success() => format!(
            r#"<div class="note">Drill GREEN: the restore path is proven.</div><pre>{}</pre>
<a href="/backups">← backups</a>"#,
            esc(&String::from_utf8_lossy(&output.stdout))
        ),
        Ok(output) => format!(
            r#"<div class="error">The drill failed; do not touch production
restore until it is understood.</div><pre>{}</pre>
<a href="/backups">← back</a>"#,
            esc(&String::from_utf8_lossy(&output.stderr))
        ),
        Err(e) => format!(
            r#"<div class="error">cannot run unidpp-ops: {e}</div><a href="/backups">← back</a>"#
        ),
    };
    page_for(&state, "Backups", "backups", body)
}

// ---------------------------------------------------------------------------
// Router + run
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Declarations (FW-5): the interop-declaration management surface —
// the registry's declaration-class items, listed and filtered. The
// console is a surface: every capability is the registry's own API.
