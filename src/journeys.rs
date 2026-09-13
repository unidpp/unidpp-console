//! The FW-5 journey surfaces: interop declarations, coverage,
//! carrier generation, profile intake and archival — one pattern
//! per surface (the service's port from the manifest, the probe or
//! the submit, the render or the honest refusal). A new journey
//! surface lands here without touching the console's core.

use crate::html::esc;
use crate::http;
use crate::{page_for, AppState};

fn urlencode(value: &str) -> String {
    crate::urlencode(value)
}
use axum::extract::{Form, State};
use axum::response::Response;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

// ---------------------------------------------------------------------------

pub(crate) async fn declarations_page(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> Response {
    let register = params.get("register").cloned().unwrap_or_default();
    let page: usize = params
        .get("page")
        .and_then(|p| p.parse().ok())
        .unwrap_or(1)
        .max(1);
    let body = match declarations_render(&state, &register, page).await {
        Ok(body) => body,
        Err(error) => format!(r#"<div class="error">{}</div>"#, esc(&error)),
    };
    page_for(&state, "Interop declarations", "declarations", body)
}

pub(crate) async fn declarations_render(
    state: &Arc<AppState>,
    register: &str,
    page: usize,
) -> Result<String, String> {
    let port = state
        .with_manifest(|m| {
            m.services
                .registry
                .as_ref()
                .and_then(|s| http::port_of(&s.bind))
        })
        .ok_or("this deployment declares no registry service")?;
    let mut path = format!(
        "/items?limit=50&offset={}&class=declaration",
        (page - 1) * 50
    );
    if !register.is_empty() {
        path.push_str(&format!("&register={register}"));
    }
    let response = http::get(port, &path)
        .await
        .ok_or("the registry service is unreachable".to_string())?;
    let doc = response
        .json()
        .ok_or("the registry returned a non-JSON body".to_string())?;
    let count = doc.get("count").and_then(|c| c.as_u64()).unwrap_or(0);
    let mut rows = Vec::new();
    for item in doc
        .get("items")
        .and_then(|i| i.as_array())
        .unwrap_or(&vec![])
    {
        let id = item
            .get("identifier")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let reg = item.get("register").and_then(|v| v.as_str()).unwrap_or("");
        let status = item.get("status").and_then(|v| v.as_str()).unwrap_or("");
        rows.push(format!(
            r#"<tr><td><code>{}</code></td><td>{}</td><td>{}</td></tr>"#,
            esc(id),
            esc(reg),
            esc(status)
        ));
    }
    Ok(format!(
        r#"<h2>Interop declarations</h2>
<p>The signed, versioned posture each scheme publishes — per counterpart
and data class: harmonization level, recognition mode, transports
offered. Managed as registry items of the <code>declaration</code> class;
listed from the registry's own API.</p>
<table class="data"><thead><tr><th>Declaration</th><th>Register</th><th>Status</th></tr></thead>
<tbody>{}</tbody></table>
<p class="meta">{} item(s)</p>"#,
        rows.join("\n"),
        count
    ))
}

// ---------------------------------------------------------------------------
// Coverage (FW-5): the route/coverage visualization surface — the
// projector's view of one passport, its coverage report rendered.
// ---------------------------------------------------------------------------

pub(crate) async fn coverage_page(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> Response {
    let passport = params.get("passport").cloned().unwrap_or_default();
    let profile = params.get("profile").cloned().unwrap_or_default();
    let body = match coverage_render(&state, &passport, &profile).await {
        Ok(body) => body,
        Err(error) => format!(r#"<div class="error">{}</div>"#, esc(&error)),
    };
    page_for(&state, "Coverage", "coverage", body)
}

pub(crate) async fn coverage_render(
    state: &Arc<AppState>,
    passport: &str,
    profile: &str,
) -> Result<String, String> {
    if passport.is_empty() || profile.is_empty() {
        return Ok(r#"<h2>Coverage</h2>
<p>Enter a passport identifier and a profile item to see the projector's
view — the selected elements, the coverage report (what the profile
saw, what it did not, and why), and the per-element trust markers.</p>
<form method="get" action="/coverage" style="display:flex;gap:.6rem;flex-wrap:wrap">
  <input name="passport" placeholder="urn:unidpp:passport:…" style="flex:1;min-width:16rem" required>
  <input name="profile" placeholder="urn:unidpp:profile:…" style="flex:1;min-width:16rem" required>
  <button type="submit">View</button>
</form>"#
            .into());
    }
    let port = state
        .with_manifest(|m| {
            m.services
                .projector
                .as_ref()
                .and_then(|s| http::port_of(&s.bind))
        })
        .ok_or("this deployment declares no projector service".to_string())?;
    let path = format!(
        "/view?passport={}&profile={}&actor=console",
        urlencode(passport),
        urlencode(profile)
    );
    let response = http::get(port, &path)
        .await
        .ok_or("the projector service is unreachable".to_string())?;
    let doc = response
        .json()
        .ok_or("the projector returned a non-JSON body".to_string())?;
    let mut entries = Vec::new();
    if let Some(report) = doc.get("coverage").and_then(|c| c.as_object()) {
        if let Some(items) = report.get("entries").and_then(|e| e.as_array()) {
            for entry in items {
                let class = entry.get("class").and_then(|v| v.as_str()).unwrap_or("—");
                let evidence = entry
                    .get("evidence")
                    .and_then(|v| v.as_str())
                    .unwrap_or("—");
                let policy = entry
                    .get("governing_policy")
                    .and_then(|v| v.as_str())
                    .unwrap_or("—");
                entries.push(format!(
                    r#"<tr><td><code>{}</code></td><td>{}</td><td><code>{}</code></td></tr>"#,
                    esc(class),
                    esc(evidence),
                    esc(policy)
                ));
            }
        }
    }
    Ok(format!(
        r#"<h2>Coverage — {}</h2>
<p>The projector's view under <code>{}</code>: the coverage report
names, per class, the evidence kind and the governing policy.</p>
<table class="data"><thead><tr><th>Class</th><th>Evidence</th><th>Governing policy</th></tr></thead>
<tbody>{}</tbody></table>"#,
        esc(passport),
        esc(profile),
        entries.join("\n")
    ))
}

// ---------------------------------------------------------------------------
// FW-5 surfaces: carrier generation, profile intake, archival.
// Each renders from the loopback services' own APIs, degrades
// honestly when a service is absent, and never invents state the
// services do not hold.
// ---------------------------------------------------------------------------

/// A loopback response as parsed JSON, or the service's own refusal
/// stated (the console surfaces errors, never swallows them).
fn json_or_refusal(
    response: http::HttpResponse,
    service: &str,
) -> Result<serde_json::Value, String> {
    if response.status >= 400 {
        return Err(format!(
            "{} refused (HTTP {}): {}",
            service,
            response.status,
            response.body.chars().take(400).collect::<String>()
        ));
    }
    response
        .json()
        .ok_or_else(|| format!("{service} returned a non-JSON body"))
}

// --- Carrier: mint the Tier-A pack, the QR budget shown ----------

pub(crate) async fn carrier_page(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> Response {
    let passport = params.get("passport").cloned().unwrap_or_default();
    let body = match carrier_render(&state, &passport).await {
        Ok(body) => body,
        Err(error) => format!(r#"<div class="error">{}</div>"#, esc(&error)),
    };
    page_for(&state, "Carrier", "carrier", body)
}

pub(crate) async fn carrier_render(
    state: &Arc<AppState>,
    passport: &str,
) -> Result<String, String> {
    let port = state
        .with_manifest(|m| {
            m.services
                .issuer
                .as_ref()
                .and_then(|s| http::port_of(&s.bind))
        })
        .ok_or("this deployment declares no issuer service")?;
    if passport.is_empty() {
        let listing = http::get(port, "/passports?limit=100&offset=0")
            .await
            .and_then(|r| r.json())
            .ok_or("the issuer service is unreachable")?;
        let mut options = Vec::new();
        for entry in listing
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
            if !id.is_empty() {
                options.push(format!(
                    r#"<option value="{}">{} ({})</option>"#,
                    esc(id),
                    esc(id),
                    esc(product)
                ));
            }
        }
        if options.is_empty() {
            return Ok(
                "<h2>Carrier generation</h2>\n<p>The issuer holds no passports to pack.</p>".into(),
            );
        }
        return Ok(format!(
            r#"<h2>Carrier generation</h2>
<p>Mint the Tier-A carrier pack for a passport — the offline minimum,
signed by the issuer's pack key with the QR budget enforced at mint.</p>
<form method="get" action="/carrier" style="display:flex;gap:.6rem;flex-wrap:wrap">
  <select name="passport" style="flex:1;min-width:16rem" required>{}</select>
  <button type="submit">Mint pack</button>
</form>"#,
            options.join("")
        ));
    }
    let path = format!("/passports/{}/pack", urlencode(passport));
    let response = http::post(port, &path, "{}")
        .await
        .ok_or("the issuer service is unreachable")?;
    let doc = json_or_refusal(response, "the issuer")?;
    let pack = doc.get("pack").and_then(|v| v.as_str()).unwrap_or("");
    let fact = |key: &str| -> String {
        doc.get(key)
            .map(|v| v.to_string())
            .unwrap_or_else(|| "—".into())
    };
    let signature = doc
        .get("signature")
        .and_then(|s| s.as_object())
        .map(|s| {
            format!(
                "{} ({})",
                s.get("suite").and_then(|v| v.as_str()).unwrap_or("—"),
                s.get("key_id").and_then(|v| v.as_str()).unwrap_or("—")
            )
        })
        .unwrap_or_else(|| "unsigned (sign=false)".into());
    Ok(format!(
        r#"<h2>Carrier — {}</h2>
<p>The Tier-A pack, minted and signed by the issuer's pipeline — the
same bytes an officer's terminal verifies offline.</p>
<h3>Pack ({})</h3>
<textarea readonly spellcheck="false" style="min-height:10rem;width:100%;font-family:monospace;font-size:.78rem">{}</textarea>
<h3>QR budget</h3>
<table class="data"><thead><tr><th>Fact</th><th>Value</th></tr></thead><tbody>
<tr><td>bytes used / projected</td><td><code>{}</code> / <code>{}</code></td></tr>
<tr><td>QR version</td><td><code>{}</code></td></tr>
<tr><td>error correction</td><td><code>{}</code></td></tr>
<tr><td>margin (modules)</td><td><code>{}</code></td></tr>
<tr><td>carrier signature</td><td><code>{}</code></td></tr>
</tbody></table>
<p><a href="/carrier">Mint another</a></p>"#,
        esc(passport),
        esc(doc
            .get("encoding")
            .and_then(|v| v.as_str())
            .unwrap_or("hex")),
        esc(pack),
        esc(&fact("bytes")),
        esc(&fact("projected")),
        esc(&fact("qr_version")),
        esc(&fact("ec")),
        esc(&fact("margin")),
        esc(&signature)
    ))
}

// --- Profiles: the registry intake of a signed profile manifest ---

#[derive(Debug, Default, Deserialize)]
pub(crate) struct ProfileIntakeForm {
    register_id: String,
    item_id: String,
    version: String,
    definition: String,
    issuer_class: String,
    issuer: String,
    signature_hex: String,
    subject_capability: Option<String>,
    axes: Option<String>,
    element: Option<String>,
    min_capability: Option<String>,
    fresh_within: Option<String>,
    token: String,
}

/// An HTML form's absent optional field arrives as the empty string —
/// normalize to `None`.
fn blank(v: Option<String>) -> Option<String> {
    v.filter(|s| !s.trim().is_empty())
}

fn issuer_class_options(selected: &str) -> String {
    ["law", "treaty", "consensus", "declaration", "attestation"]
        .iter()
        .map(|c| {
            if *c == selected {
                format!(r#"<option value="{c}" selected>{c}</option>"#)
            } else {
                format!(r#"<option value="{c}">{c}</option>"#)
            }
        })
        .collect()
}

fn capability_options(selected: &str) -> String {
    let mut out = r#"<option value="">—</option>"#.to_string();
    for c in ["S0", "S1", "S2", "S3"] {
        if c == selected {
            out.push_str(&format!(r#"<option value="{c}" selected>{c}</option>"#));
        } else {
            out.push_str(&format!(r#"<option value="{c}">{c}</option>"#));
        }
    }
    out
}

pub(crate) async fn profiles_page(State(state): State<Arc<AppState>>) -> Response {
    let body = match profiles_render(&state).await {
        Ok(body) => body,
        Err(error) => format!(r#"<div class="error">{}</div>"#, esc(&error)),
    };
    page_for(&state, "Profiles", "profiles", body)
}

pub(crate) async fn profiles_render(state: &Arc<AppState>) -> Result<String, String> {
    let port = state
        .with_manifest(|m| {
            m.services
                .registry
                .as_ref()
                .and_then(|s| http::port_of(&s.bind))
        })
        .ok_or("this deployment declares no registry service")?;
    let listed = http::get(port, "/profiles")
        .await
        .and_then(|r| r.json())
        .ok_or("the registry service is unreachable")?;
    let mut rows = Vec::new();
    for item in listed
        .get("items")
        .and_then(|i| i.as_array())
        .unwrap_or(&vec![])
    {
        let id = item
            .get("identifier")
            .and_then(|v| v.as_str())
            .unwrap_or("—");
        let status = item.get("status").and_then(|v| v.as_str()).unwrap_or("—");
        let title = item.get("title").and_then(|v| v.as_str()).unwrap_or("");
        rows.push(format!(
            r#"<tr><td><code>{}</code></td><td>{}</td><td>{}</td></tr>"#,
            esc(id),
            esc(title),
            esc(status)
        ));
    }
    Ok(format!(
        r#"<h2>Profile authoring</h2>
<p>A profile registers only in its SIGNED form: the issuer class, the
issuing node, and a signature slot. The console submits the manifest
to the registry's own intake — every check (signature form, schema,
satisfiability) runs there, and its findings are stated below.</p>
<form method="post" action="/profiles" style="display:grid;gap:.5rem;max-width:44rem">
  <div style="display:flex;gap:.6rem;flex-wrap:wrap">
    <input name="register_id" placeholder="register (e.g. unidpp)" required style="flex:1;min-width:10rem">
    <input name="item_id" placeholder="item id (e.g. battery-eu)" required style="flex:1;min-width:10rem">
    <input name="version" placeholder="version (e.g. 1)" required style="flex:0;min-width:6rem">
  </div>
  <input name="definition" placeholder="definition / title" required>
  <div style="display:flex;gap:.6rem;flex-wrap:wrap">
    <select name="issuer_class" required style="flex:1;min-width:10rem">{}</select>
    <input name="issuer" placeholder="issuer (signer of record)" required style="flex:2;min-width:14rem">
  </div>
  <input name="signature_hex" placeholder="signature value (hex — the signed form's slot)" required>
  <div style="display:flex;gap:.6rem;flex-wrap:wrap">
    <select name="subject_capability" style="flex:1;min-width:10rem">{}</select>
    <input name="axes" placeholder="axes (comma-separated: jurisdiction, sector, characteristic)" style="flex:2;min-width:14rem">
  </div>
  <fieldset style="display:grid;gap:.4rem"><legend>First data point (optional)</legend>
    <div style="display:flex;gap:.6rem;flex-wrap:wrap">
      <input name="element" placeholder="element" style="flex:2;min-width:12rem">
      <select name="min_capability" style="flex:1;min-width:8rem">{}</select>
      <input name="fresh_within" placeholder="fresh_within (ISO 8601, e.g. P30D)" style="flex:1;min-width:10rem">
    </div>
  </fieldset>
  <input name="token" type="password" placeholder="registry admin token (submitted, never stored)" required>
  <button type="submit">Submit to the registry intake</button>
</form>
<h3>Registered profiles</h3>
<table class="data"><thead><tr><th>Profile</th><th>Title</th><th>Status</th></tr></thead>
<tbody>{}</tbody></table>"#,
        issuer_class_options("consensus"),
        capability_options(""),
        capability_options("S1"),
        rows.join("\n")
    ))
}

pub(crate) async fn profiles_intake(
    State(state): State<Arc<AppState>>,
    Form(f): Form<ProfileIntakeForm>,
) -> Response {
    let body = match profiles_submit(&state, f).await {
        Ok(body) => body,
        Err(error) => format!(r#"<div class="error">{}</div>"#, esc(&error)),
    };
    page_for(&state, "Profiles", "profiles", body)
}

pub(crate) async fn profiles_submit(
    state: &Arc<AppState>,
    f: ProfileIntakeForm,
) -> Result<String, String> {
    let port = state
        .with_manifest(|m| {
            m.services
                .registry
                .as_ref()
                .and_then(|s| http::port_of(&s.bind))
        })
        .ok_or("this deployment declares no registry service")?;
    let mut manifest = serde_json::json!({
        "version": f.version.trim(),
        "issuer_class": f.issuer_class.trim(),
        "issuer": f.issuer.trim(),
        "signature": {"algorithm": "ed25519", "signature": f.signature_hex.trim()},
    });
    if let Some(cap) = blank(f.subject_capability.clone()) {
        manifest["subject_capability"] = serde_json::json!(cap);
    }
    if let Some(axes) = blank(f.axes.clone()) {
        let list: Vec<String> = axes
            .split(',')
            .map(|a| a.trim().to_string())
            .filter(|a| !a.is_empty())
            .collect();
        manifest["axes"] = serde_json::json!(list);
    }
    if let Some(element) = blank(f.element.clone()) {
        let mut point = serde_json::json!({
            "element": element,
            "min_capability": blank(f.min_capability.clone()).unwrap_or_else(|| "S1".into()),
        });
        if let Some(fresh) = blank(f.fresh_within.clone()) {
            point["fresh_within"] = serde_json::json!(fresh);
        }
        manifest["data_points"] = serde_json::json!([point]);
    }
    let body = serde_json::json!({
        "register_id": f.register_id.trim(),
        "item_id": f.item_id.trim(),
        "version": f.version.trim(),
        "definition": f.definition.trim(),
        "manifest": manifest,
    });
    let response = http::post_bearer(
        port,
        "/profiles",
        &serde_json::to_string(&body).unwrap(),
        f.token.trim(),
    )
    .await
    .ok_or("the registry service is unreachable")?;
    let doc = json_or_refusal(response, "the registry")?;
    let id = doc
        .get("identifier")
        .and_then(|v| v.as_str())
        .unwrap_or("—");
    let version = doc
        .get("version")
        .and_then(|v| {
            v.as_str().map(str::to_string).or_else(|| {
                v.get("version")
                    .and_then(|s| s.as_str())
                    .map(str::to_string)
            })
        })
        .unwrap_or_else(|| "—".into());
    let audit = doc
        .get("audit_seq")
        .map(|v| v.to_string())
        .unwrap_or_else(|| "—".into());
    let mut warnings = String::new();
    if let Some(w) = doc.get("warnings").and_then(|w| w.as_array()) {
        for warning in w {
            warnings.push_str(&format!(
                r#"<li>{} — {}</li>"#,
                esc(warning
                    .get("check")
                    .and_then(|v| v.as_str())
                    .unwrap_or("check")),
                esc(warning
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or(""))
            ));
        }
    }
    Ok(format!(
        r#"<h2>Registered</h2>
<p>Profile <code>{}</code> version <code>{}</code> passed the intake
checks (audit sequence <code>{}</code>).</p>
{}<p><a href="/profiles">Author another</a></p>"#,
        esc(id),
        esc(&version),
        esc(&audit),
        if warnings.is_empty() {
            String::new()
        } else {
            format!("<p>Intake warnings (stated, not blocking):</p><ul>{warnings}</ul>")
        }
    ))
}

// --- Archival: the Tier-C snapshots, listed and intakeable -------

#[derive(Debug, Default, Deserialize)]
pub(crate) struct SnapshotIntakeForm {
    passport_id: String,
    state_hash: String,
    log_head: String,
    submitter: Option<String>,
    token: String,
}

pub(crate) async fn archival_page(State(state): State<Arc<AppState>>) -> Response {
    let body = match archival_render(&state).await {
        Ok(body) => body,
        Err(error) => format!(r#"<div class="error">{}</div>"#, esc(&error)),
    };
    page_for(&state, "Archival", "archival", body)
}

pub(crate) async fn archival_render(state: &Arc<AppState>) -> Result<String, String> {
    let port = state
        .with_manifest(|m| {
            m.services
                .archive
                .as_ref()
                .and_then(|s| http::port_of(&s.bind))
        })
        .ok_or("this deployment declares no archive service")?;
    let doc = http::get(port, "/snapshots")
        .await
        .and_then(|r| r.json())
        .ok_or("the archive service is unreachable")?;
    let mut rows = Vec::new();
    for snap in doc
        .get("snapshots")
        .and_then(|s| s.as_array())
        .unwrap_or(&vec![])
    {
        let id = snap
            .get("snapshot_id")
            .and_then(|v| v.as_str())
            .unwrap_or("—");
        let passport = snap
            .get("passport_id")
            .and_then(|v| v.as_str())
            .unwrap_or("—");
        let at = snap
            .get("notarized_at")
            .and_then(|v| v.as_str())
            .unwrap_or("—");
        let anchored = snap
            .get("anchored")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let receipt = snap
            .get("receipt_id")
            .and_then(|v| v.as_str())
            .unwrap_or("—");
        let tree = snap
            .get("tree_size")
            .map(|v| v.to_string())
            .unwrap_or_else(|| "—".into());
        rows.push(format!(
            r#"<tr><td><code>{}</code></td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
            esc(id),
            esc(passport),
            esc(at),
            if anchored { "anchored" } else { "unanchored" },
            esc(&format!("receipt {receipt} / tree {tree}"))
        ));
    }
    Ok(format!(
        r#"<h2>Archival (Tier C)</h2>
<p>The archive service's notarized snapshots — each sealed by the
notary key and, when the transparency log answered, anchored with its
inclusion receipt.</p>
<table class="data"><thead><tr><th>Snapshot</th><th>Passport</th><th>Notarized at</th><th>Anchoring</th><th>Receipt</th></tr></thead>
<tbody>{}</tbody></table>
<h3>Submit a snapshot</h3>
<p>The snapshot intake is an operator action: the passport whose core
state is being archived, the state hash and log head (each a
64-character hex SHA-256), and the admin token the archive holds.</p>
<form method="post" action="/archival" style="display:grid;gap:.5rem;max-width:44rem">
  <input name="passport_id" placeholder="passport id (urn:unidpp:passport:…)" required>
  <div style="display:flex;gap:.6rem;flex-wrap:wrap">
    <input name="state_hash" placeholder="state hash (64-hex)" required style="flex:1;min-width:14rem;font-family:monospace">
    <input name="log_head" placeholder="log head (64-hex)" required style="flex:1;min-width:14rem;font-family:monospace">
  </div>
  <input name="submitter" placeholder="submitter (optional)">
  <input name="token" type="password" placeholder="archive admin token (submitted, never stored)" required>
  <button type="submit">Notarize and anchor</button>
</form>"#,
        rows.join("\n")
    ))
}

pub(crate) async fn archival_intake(
    State(state): State<Arc<AppState>>,
    Form(f): Form<SnapshotIntakeForm>,
) -> Response {
    let body = match archival_submit(&state, f).await {
        Ok(body) => body,
        Err(error) => format!(r#"<div class="error">{}</div>"#, esc(&error)),
    };
    page_for(&state, "Archival", "archival", body)
}

pub(crate) async fn archival_submit(
    state: &Arc<AppState>,
    f: SnapshotIntakeForm,
) -> Result<String, String> {
    let port = state
        .with_manifest(|m| {
            m.services
                .archive
                .as_ref()
                .and_then(|s| http::port_of(&s.bind))
        })
        .ok_or("this deployment declares no archive service")?;
    let mut body = serde_json::json!({
        "passport_id": f.passport_id.trim(),
        "state_hash": f.state_hash.trim(),
        "log_head": f.log_head.trim(),
    });
    if let Some(submitter) = blank(f.submitter.clone()) {
        body["submitter"] = serde_json::json!(submitter);
    }
    let response = http::post_bearer(
        port,
        "/snapshots",
        &serde_json::to_string(&body).unwrap(),
        f.token.trim(),
    )
    .await
    .ok_or("the archive service is unreachable")?;
    // The create response is the Tier-C archival document: as_of at
    // the top, the anchoring status under oais.provenance.
    let doc = json_or_refusal(response, "the archive")?;
    let id = doc
        .get("snapshot_id")
        .and_then(|v| v.as_str())
        .unwrap_or("—");
    let at = doc.get("as_of").and_then(|v| v.as_str()).unwrap_or("—");
    let anchored = doc
        .pointer("/oais/provenance/anchoring/status")
        .and_then(|v| v.as_str())
        .unwrap_or("—");
    Ok(format!(
        r#"<h2>Snapshot notarized</h2>
<p>Snapshot <code>{}</code> sealed at <code>{}</code>; anchoring
status: <code>{}</code>.</p>
<p><a href="/archival">Back to the snapshots</a></p>"#,
        esc(id),
        esc(at),
        esc(anchored)
    ))
}
