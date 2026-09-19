//! The egress surface: the deployment's declared external calls.

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

/// The egress inventory: what leaves the deployment, sealed and real rows alike.
#[utoipa::path(
    get,
    path = "/egress",
    tag = "console",
    responses(
        (status = 200, description = "The page, rendered against the deployment manifest", body = String, content_type = "text/html"),
        (status = 303, description = "The session gate redirects an unauthenticated browser to `/login`"),
    )
)]
pub(crate) async fn egress_page(State(state): State<Arc<AppState>>) -> Response {
    let body = state.with_manifest(|m| {
        let sealed = m.sovereignty.external_calls == unidpp_config::EgressPolicy::None;
        let mut rows = Vec::new();
        let mut row = |service: &str, target: Option<&str>, note: &str| {
            let cell = match target {
                Some(url) => format!(
                    r#"<td><code>{}</code></td><td>{}</td>"#,
                    esc(url),
                    esc(note)
                ),
                None => r#"<td>—</td><td>sealed</td>"#.to_string(),
            };
            rows.push(format!(
                r#"<tr><td><code>{}</code></td>{}</tr>"#,
                esc(service),
                cell
            ));
        };
        row(
            "registry",
            None,
            "serves; makes no outbound calls",
        );
        row("trust", None, "serves; makes no outbound calls");
        row(
            "log",
            m.services
                .log
                .as_ref()
                .and_then(|l| l.external_tsa_url.as_deref()),
            "RFC 3161 time-stamp submission (the one configured egress)",
        );
        row(
            "issuer",
            m.services
                .issuer
                .as_ref()
                .and_then(|i| i.registry_url.as_deref())
                .filter(|u| !u.starts_with("http://127.0.0.1")),
            "registry forwarding when the registry is off-box",
        );
        row(
            "gateway",
            m.services
                .gateway
                .as_ref()
                .and_then(|g| g.issuer_url.as_deref())
                .filter(|u| !u.starts_with("http://127.0.0.1")),
            "issuer upstream when off-box",
        );
        row("console", None, "loopback services only");
        let banner = if sealed {
            r#"<div class="note"><strong>Sealed.</strong> This deployment's
egress policy is <code>none</code>: nothing leaves the box. The public
surface below is ingress: answers, not calls.</div>"#
        } else {
            r#"<div class="note">Rows marked <code>sealed</code> make no
outbound calls. The public surface is ingress.</div>"#
        };
        format!(
            r#"<h1>Egress inventory</h1>
<p>What leaves the box, itemized — derived from the deployment's own
manifest ({}, residency {}).</p>
{banner}
<h2>Outbound calls</h2>
<table><tr><th>Service</th><th>Target</th><th>What</th></tr>{}</table>
<h2>Public surface (ingress)</h2>
<table><tr><th>Service</th><th>Target</th><th>What</th></tr>
<tr><td><code>deployment</code></td><td><code>{}</code></td><td>the public base URL (answers requests; calls nothing)</td></tr>
</table>"#,
            esc(m.deployment.profile.as_str()),
            esc(m
                .sovereignty
                .data_residency
                .as_deref()
                .unwrap_or("undeclared")),
            rows.join("\n"),
            esc(&m.deployment.base_url),
        )
    });
    page_for(&state, "Egress", "egress", body)
}

// ---------------------------------------------------------------------------
// Tenants (#106): provisioning from a template — the console writes
// data; it never spawns processes.
// ---------------------------------------------------------------------------
