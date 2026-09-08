//! Inline pack verification — through the CLI's own pipeline (the one
//! an officer's terminal runs), never a parallel implementation.

use axum::extract::{Form, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde::Deserialize;
use std::sync::Arc;

use crate::html::esc;
use crate::{http, AppState};

/// The verification form (POSTs back here).
pub async fn form_html(issuer_port: u16) -> String {
    let port = issuer_port;
    format!(
        r#"<h2>Verify a pack</h2>
<p>Paste a pack (hex) — verification runs the CLI pipeline against the
issuer's published anchors:</p>
<form method="post" action="/passports">
  <textarea name="pack" spellcheck="false" style="min-height:7rem" aria-label="pack hex"></textarea>
  <button type="submit">Verify</button>
</form>
<p class="note">Anchors: <code>GET http://127.0.0.1:{port}/keyring</code></p>"#
    )
}

#[derive(Deserialize)]
pub struct VerifyForm {
    pub pack: String,
}

/// POST /passports with a pack: verify through the pipeline.
pub async fn submit(State(state): State<Arc<AppState>>, Form(form): Form<VerifyForm>) -> Response {
    let body = match verify_pack(&state, &form.pack).await {
        Ok(report) => report,
        Err(error) => format!(
            r#"<div class="error">{}</div><a href="/passports">← back</a>"#,
            esc(&error)
        ),
    };
    let full = state.with_manifest(|m| crate::html::page(m, "Verify", &body, "passports"));
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .body(axum::body::Body::from(full))
        .expect("static response parts")
}

/// Run the CLI pipeline: decode the hex, fetch the issuer's anchors,
/// verify with `verify_pack_with_anchors`, render the verdict.
async fn verify_pack(state: &Arc<AppState>, pack_hex: &str) -> Result<String, String> {
    let trimmed = pack_hex.trim();
    if trimmed.is_empty() {
        return Err("paste a pack first".to_string());
    }
    let bytes = unidpp_cli::encoding::hex_decode(trimmed).map_err(|e| format!("pack hex: {e}"))?;

    let issuer_port = state.with_manifest(|m| {
        m.services
            .issuer
            .as_ref()
            .and_then(|s| http::port_of(&s.bind))
    });
    let port = issuer_port.ok_or("this deployment declares no issuer")?;

    // The anchors the issuer's /keyring publishes (per-suite).
    let response = http::get(port, "/keyring")
        .await
        .ok_or("the issuer is unreachable")?;
    let doc: serde_json::Value =
        serde_json::from_str(&response.body).map_err(|e| format!("keyring parse: {e}"))?;
    let mut anchors = Vec::new();
    for (_suite, entry) in doc
        .get("roles")
        .and_then(|r| r.get("pack"))
        .and_then(|p| p.get("suites"))
        .and_then(|s| s.as_object())
        .into_iter()
        .flat_map(|s| s.iter())
    {
        if let Some(hex) = entry.get("public").and_then(|p| p.as_str()) {
            if let Ok(bytes) = unidpp_cli::encoding::hex_decode(hex) {
                // The public key shape: from_bytes infers the suite by
                // length; SM2 needs the suite-certain form.
                if let Ok(key) = unidpp_signatif::keyring::PublicKey::from_bytes(&bytes) {
                    anchors.push(key);
                }
            }
        }
    }

    let now = unidpp_model::Timestamp::now();
    let outcome = unidpp_cli::commands::verify::verify_pack_with_anchors(
        &bytes,
        &anchors,
        now,
        unidpp_cli::commands::verify::DEFAULT_MAX_AGE_SECS,
    );

    let grade = outcome.grade.token();
    let badge = match grade {
        "pass" => "ok",
        "degraded" => "warn",
        _ => "bad",
    };
    let mut findings = Vec::new();
    for finding in &outcome.findings {
        let fbadge = match finding.grade.token() {
            "pass" => "ok",
            "degraded" => "warn",
            _ => "bad",
        };
        findings.push(format!(
            r#"<tr><td><code>{}</code></td><td><span class="badge {}">{}</span></td><td>{}</td></tr>"#,
            esc(&finding.check),
            fbadge,
            esc(finding.grade.token()),
            esc(&finding.detail)
        ));
    }
    Ok(format!(
        r#"<h2>Verdict: <span class="badge {badge}">{grade}</span></h2>
<table><tr><th>Check</th><th>Grade</th><th>Detail</th></tr>
{}</table>
<p><a href="/passports">← verify another</a></p>"#,
        findings.join("\n")
    ))
}
