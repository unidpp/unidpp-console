//! The passports surface: the issuer's passports with inline pack verification.

use crate::futures_block;
use std::collections::HashMap;
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
use crate::{page_for, urlencode, AppState};

pub(crate) async fn passports_page(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> Response {
    let lookup = params.get("id").cloned().unwrap_or_default();
    let page: usize = params
        .get("page")
        .and_then(|p| p.parse().ok())
        .unwrap_or(1)
        .max(1);
    let issuer_port = state.with_manifest(|m| {
        m.services
            .issuer
            .as_ref()
            .and_then(|s| http::port_of(&s.bind))
    });
    let mut body = String::from(
        r#"<h1>Passports</h1>
<form method="get" action="/passports" style="display:flex;gap:.6rem">
  <input name="id" placeholder="passport id" style="flex:1" value="__LOOKUP__">
  <button type="submit" class="secondary">Look up</button>
</form>"#,
    );
    body = body.replace("__LOOKUP__", &esc(&lookup));
    if let Some(port) = issuer_port {
        let listing_path = format!("/passports?limit=100&offset={}", (page - 1) * 100);
        let (listing_resp, log_resp) = {
            let mut probes = http::get_all(&[
                (Some(port), listing_path.as_str()),
                (Some(port), "/admin/log?limit=20"),
            ])
            .await;
            (probes[0].take(), probes[1].take())
        };
        if let Some(resp) = listing_resp {
            if let Some(doc) = resp.json() {
                let mut rows = Vec::new();
                for entry in doc
                    .get("passports")
                    .and_then(|p| p.as_array())
                    .unwrap_or(&vec![])
                {
                    let id = entry
                        .get("passport_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let product = entry
                        .get("product_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let capability = entry
                        .get("capability")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let eo = entry.get("eo_id").and_then(|v| v.as_str()).unwrap_or("");
                    let events = entry.get("events").and_then(|v| v.as_u64()).unwrap_or(0);
                    rows.push(format!(
                        r#"<tr><td><a href="/passports?id={}"><code>{}</code></a></td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                        urlencode(id),
                        esc(id),
                        esc(product),
                        esc(capability),
                        esc(eo),
                        events
                    ));
                }
                let count = doc.get("count").and_then(|c| c.as_u64()).unwrap_or(0);
                let pages: usize = count.div_ceil(100) as usize;
                if page > 1 || pages > 1 {
                    let prev = if page > 1 {
                        format!(r#"<a href="/passports?page={}">&larr; newer</a>"#, page - 1)
                    } else {
                        String::new()
                    };
                    let next = if page < pages {
                        format!(r#"<a href="/passports?page={}">older &rarr;</a>"#, page + 1)
                    } else {
                        String::new()
                    };
                    rows.push(format!(
                        r#"<tr><td colspan="5">page {page} of {pages} · {prev} {next}</td></tr>"#
                    ));
                }
                if !rows.is_empty() {
                    body.push_str(&format!(
                        r#"<h2>Issued ({} passports)</h2>
<table><tr><th>Passport</th><th>Product</th><th>Capability</th><th>Economic operator</th><th>Events</th></tr>{}</table>"#,
                        count,
                        rows.join("")
                    ));
                }
            }
        }
        if !lookup.is_empty() {
            let path = format!("/passports/{}", urlencode(&lookup));
            match futures_block(http::get(port, &path)) {
                Some(resp) if resp.status == 200 => {
                    if let Some(doc) = resp.json() {
                        body.push_str(&format!(
                            r#"<h2>Document</h2><pre>{}</pre>"#,
                            esc(&serde_json::to_string_pretty(&doc).unwrap_or_default())
                        ));
                    }
                }
                _ => body.push_str(
                    r#"<div class="error">Not found (no information beyond that).</div>"#,
                ),
            }
        }
        // The audit log tail: recent lifecycle actions (probed in the
        // same fan-out as the listing above).
        if let Some(resp) = log_resp {
            if let Some(doc) = resp.json() {
                let mut rows = Vec::new();
                for entry in doc
                    .get("entries")
                    .and_then(|e| e.as_array())
                    .unwrap_or(&vec![])
                {
                    let seq = entry.get("seq").and_then(|v| v.as_u64()).unwrap_or(0);
                    let action = entry.get("action").and_then(|v| v.as_str()).unwrap_or("");
                    let subject = entry
                        .get("passport_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    rows.push(format!(
                        r#"<tr><td>{}</td><td>{}</td><td><code>{}</code></td></tr>"#,
                        seq,
                        esc(action),
                        esc(subject)
                    ));
                }
                if !rows.is_empty() {
                    body.push_str(&format!(
                        r#"<h2>Recent lifecycle (issuer audit log)</h2>
<table><tr><th>Seq</th><th>Action</th><th>Passport</th></tr>{}</table>"#,
                        rows.join("")
                    ));
                }
            }
        }
        // Pack verification through the CLI's own pipeline.
        let locale = state.with_manifest(|m| m.branding.locale.clone());
        body.push_str(&verify::form_html(port, &locale).await);
    } else {
        body.push_str(r#"<div class="error">This deployment declares no issuer.</div>"#);
    }
    page_for(&state, "Passports", "passports", body)
}
