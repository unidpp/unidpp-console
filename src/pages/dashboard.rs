//! The dashboard: health cards, service identity, metric cards, the egress labels and bind notes.

use crate::i18n;
use std::sync::Arc;
use unidpp_config::OperatorManifest;

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

pub(crate) async fn dashboard(State(state): State<Arc<AppState>>) -> Response {
    let declared: Vec<(String, String, String, String)> = state.with_manifest(|m| {
        m.service_names()
            .iter()
            .map(|name| {
                let (bind, note) = service_bind_note(m, name);
                let public = m
                    .service_public_url(name)
                    .map(|u| u.to_string())
                    .unwrap_or_default();
                (name.to_string(), bind, note, public)
            })
            .collect()
    });
    // One fan-out, two probes per service: /healthz and the discovery
    // doc (which build is live) — N down services cost one timeout.
    let mut targets: Vec<(Option<u16>, &str)> = Vec::new();
    for (_, bind, _, _) in &declared {
        let port = http::port_of(bind);
        targets.push((port, "/healthz"));
        targets.push((port, "/"));
    }
    let probes = http::get_all(&targets).await;
    let paired: Vec<_> = probes
        .chunks(2)
        .map(|c| (c[0].clone(), c[1].clone()))
        .collect();
    let mut services = Vec::new();
    for ((name, bind, note, public), (probe, id_probe)) in declared.iter().zip(paired) {
        let loc = state.with_manifest(|m| m.branding.locale.clone());
        let health = match http::port_of(bind) {
            Some(_) => match probe {
                Some(resp) if resp.status == 200 => {
                    format!(
                        r#"<span class="badge ok">{}</span>"#,
                        i18n::t(&loc, "mx.healthy")
                    )
                }
                Some(resp) => format!(r#"<span class="badge bad">HTTP {}</span>"#, resp.status),
                None => format!(
                    r#"<span class="badge bad">{}</span>"#,
                    i18n::t(&loc, "mx.unreachable")
                ),
            },
            None => format!(
                r#"<span class="badge warn">{}</span>"#,
                i18n::t(&loc, "mx.no_bind")
            ),
        };
        let public_cell = if public.is_empty() {
            format!(
                r#"<span class="badge warn">{}</span>"#,
                i18n::t(&loc, "mx.loopback")
            )
        } else {
            format!(r#"<a href="{}">{}</a>"#, esc(public), esc(public))
        };
        let version = id_probe
            .and_then(|r| r.json())
            .and_then(|d| {
                d.get("version")
                    .and_then(|v| v.as_str())
                    .map(|v| v.to_string())
            })
            .unwrap_or_else(|| "—".to_string());
        services.push(format!(
            r#"<tr><td><code>{}</code></td><td><code>{}</code></td><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td></tr>"#,
            esc(name),
            esc(bind),
            esc(note),
            public_cell,
            esc(&version),
            health
        ));
    }
    let summary = state.with_manifest(|m| {
        let loc = &m.branding.locale;
        format!(
            r#"<div class="grid">
  <div class="card"><div class="label">{}</div><div class="value">{}</div></div>
  <div class="card"><div class="label">{}</div><div class="value">{}</div></div>
  <div class="card"><div class="label">{}</div><div class="value" style="font-size:.95rem">{}</div></div>
  <div class="card"><div class="label">{}</div><div class="value" style="font-size:.95rem">{}</div></div>
</div>"#,
            i18n::t(loc, "card.deployment"),
            esc(&m.deployment.name),
            i18n::t(loc, "card.profile"),
            esc(m.deployment.profile.as_str()),
            i18n::t(loc, "card.base_url"),
            esc(&m.deployment.base_url),
            i18n::t(loc, "card.egress"),
            esc(&egress_label(m)),
        )
    });
    let metrics = metrics_cards(&state).await;
    let locale = state.with_manifest(|m| m.branding.locale.clone());
    let body = format!(
        r#"<h1>{title}</h1>
{summary}
{metrics}
<h2>Services</h2>
<table><tr><th>{svc}</th><th>{bind}</th><th>{role}</th><th>{public}</th><th>{ver}</th><th>{health}</th></tr>
{rows}</table>"#,
        title = i18n::t(&locale, "page.dashboard"),
        svc = i18n::t(&locale, "mx.service"),
        bind = i18n::t(&locale, "mx.bind"),
        role = i18n::t(&locale, "mx.role"),
        public = i18n::t(&locale, "mx.public"),
        health = i18n::t(&locale, "mx.health"),
        ver = i18n::t(&locale, "mx.version"),
        rows = services.join("\n"),
    );
    page_for(&state, "Dashboard", "dashboard", body)
}

pub(crate) fn egress_label(m: &OperatorManifest) -> String {
    let base = match m.sovereignty.external_calls {
        unidpp_config::EgressPolicy::None => "none".to_string(),
        unidpp_config::EgressPolicy::TsaOnly => "tsa-only".to_string(),
        unidpp_config::EgressPolicy::External => "external".to_string(),
    };
    if let Some(residency) = &m.sovereignty.data_residency {
        format!("{base} · residency {residency}")
    } else {
        base
    }
}

pub(crate) fn service_bind_note(m: &OperatorManifest, name: &str) -> (String, String) {
    let services = &m.services;
    match name {
        "registry" => (
            services
                .registry
                .as_ref()
                .map(|s| s.bind.clone())
                .unwrap_or_default(),
            "ISO 19135 item + discovery registry".to_string(),
        ),
        "trust" => (
            services
                .trust
                .as_ref()
                .map(|s| s.bind.clone())
                .unwrap_or_default(),
            "SIGNATIF trust graph, revocations".to_string(),
        ),
        "log" => (
            services
                .log
                .as_ref()
                .map(|s| s.bind.clone())
                .unwrap_or_default(),
            "transparency log (RFC 6962)".to_string(),
        ),
        "issuer" => (
            services
                .issuer
                .as_ref()
                .map(|s| s.bind.clone())
                .unwrap_or_default(),
            "passport lifecycle issuer".to_string(),
        ),
        "projector" => (
            services
                .projector
                .as_ref()
                .map(|s| s.bind.clone())
                .unwrap_or_default(),
            "lens projection service".to_string(),
        ),
        "gateway" => (
            services
                .gateway
                .as_ref()
                .map(|s| s.bind.clone())
                .unwrap_or_default(),
            "UNTP + EN 18222 renders, ingest".to_string(),
        ),
        "archive" => (
            services
                .archive
                .as_ref()
                .map(|s| s.bind.clone())
                .unwrap_or_default(),
            "Tier-C notarized snapshots".to_string(),
        ),
        "console" => (
            services
                .console
                .as_ref()
                .map(|s| s.bind.clone())
                .unwrap_or_default(),
            "this console".to_string(),
        ),
        "resolver" => (
            services
                .resolver
                .as_ref()
                .map(|s| s.bind.clone())
                .unwrap_or_default(),
            "RFC 9264 linkset resolver".to_string(),
        ),
        "hub" => (
            services
                .hub
                .as_ref()
                .map(|s| s.bind.clone())
                .unwrap_or_default(),
            "translation hub (stateless relay)".to_string(),
        ),
        other => (String::new(), other.to_string()),
    }
}

pub(crate) async fn metrics_cards(state: &Arc<AppState>) -> String {
    let registry_port = state.with_manifest(|m| {
        m.services
            .registry
            .as_ref()
            .and_then(|s| http::port_of(&s.bind))
    });
    let log_port =
        state.with_manifest(|m| m.services.log.as_ref().and_then(|s| http::port_of(&s.bind)));
    let issuer_port = state.with_manifest(|m| {
        m.services
            .issuer
            .as_ref()
            .and_then(|s| http::port_of(&s.bind))
    });
    let card = |label: &str, value: String| {
        format!(
            r#"<div class="card"><div class="label">{label}</div><div class="value">{value}</div></div>"#
        )
    };
    fn count_at(resp: Option<http::HttpResponse>) -> Option<u64> {
        resp.and_then(|r| r.json())
            .and_then(|doc| doc.get("count").and_then(|c| c.as_u64()))
    }
    // One fan-out: the four probes run concurrently.
    let mut probes = http::get_all(&[
        (registry_port, "/items?limit=1"),
        (
            registry_port,
            "/items?class=data-element&register=untded&limit=1",
        ),
        (log_port, "/tree/head"),
        (issuer_port, "/passports"),
    ])
    .await;
    let items = count_at(probes[0].take())
        .map(|c| c.to_string())
        .unwrap_or_else(|| "—".to_string());
    let untded = count_at(probes[1].take())
        .map(|c| c.to_string())
        .unwrap_or_else(|| "—".to_string());
    let tree_size = probes[2]
        .take()
        .and_then(|r| r.json())
        .and_then(|d| d.get("tree_size").and_then(|c| c.as_u64()))
        .map(|c| c.to_string())
        .unwrap_or_else(|| "—".to_string());
    let passports = probes[3]
        .take()
        .and_then(|r| r.json())
        .and_then(|d| d.get("count").and_then(|c| c.as_u64()))
        .map(|c| c.to_string())
        .unwrap_or_else(|| "—".to_string());
    let loc = state.with_manifest(|m| m.branding.locale.clone());
    format!(
        r#"<div class="grid">{}</div>"#,
        [
            card(i18n::t(&loc, "card.registry_items"), items),
            card(i18n::t(&loc, "card.untded"), untded),
            card(i18n::t(&loc, "card.passports"), passports),
            card(i18n::t(&loc, "card.log_tree"), tree_size),
        ]
        .join("")
    )
}

// ---------------------------------------------------------------------------
// Egress inventory (#105): what leaves the box, derived from the
// manifest — sovereignty made visible, not aspirational.
// ---------------------------------------------------------------------------
