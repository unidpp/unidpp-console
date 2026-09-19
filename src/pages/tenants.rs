//! The tenant surfaces: creation (the whitelabel wizard), listing, per-tenant manifests.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use unidpp_config::load as load_manifest;

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

pub(crate) fn tenants_dir(state: &AppState) -> PathBuf {
    state
        .config
        .manifest_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("tenants")
}

pub(crate) fn list_tenants(state: &AppState) -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(entries) = std::fs::read_dir(tenants_dir(state)) {
        for entry in entries.flatten() {
            if entry.path().join("unidpp-operator.yaml").is_file() {
                if let Some(name) = entry.file_name().to_str() {
                    names.push(name.to_string());
                }
            }
        }
    }
    names.sort();
    names
}

pub(crate) fn tenant_manifest_yaml(form: &TenantForm) -> String {
    let suites = form.suites.join(", ");
    let mut yaml = format!(
        r#"api_version: unidpp.org/v1
deployment:
  name: {name}
  profile: {profile}
  base_url: https://dpp.{name}.example.org
branding:
  organization: "{organization}"
  product_name: "{product_name}"
  theme:
    primary: "{primary}"
    accent: "{accent}"
services:
  registry:
    bind: 127.0.0.1:{registry_port}
    state_file: tenants/{name}/registry-journal.jsonl
  issuer:
    bind: 127.0.0.1:{issuer_port}
    state_file: tenants/{name}/issuer-journal.jsonl
    pack_suites: [{suites}]
  console:
    bind: 127.0.0.1:{console_port}
sovereignty:
  data_residency: "{residency}"
  external_calls: none
"#,
        name = esc(&form.name),
        profile = esc(&form.profile),
        organization = esc(&form.organization),
        product_name = esc(&form.product_name),
        primary = esc(&form.primary),
        accent = esc(&form.accent),
        registry_port = form.base_port,
        issuer_port = form.base_port + 3,
        console_port = form.base_port.saturating_sub(1).max(1024),
        residency = esc(&form.residency),
    );
    let _ = &mut yaml;
    yaml
}

#[derive(Deserialize, Default, Clone, serde::Serialize)]
pub(crate) struct TenantForm {
    pub(crate) name: String,
    pub(crate) organization: String,
    pub(crate) product_name: String,
    pub(crate) profile: String,
    pub(crate) residency: String,
    pub(crate) primary: String,
    pub(crate) accent: String,
    pub(crate) suites: Vec<String>,
    pub(crate) base_port: u16,
}

pub(crate) async fn tenants_page(State(state): State<Arc<AppState>>) -> Response {
    let existing: Vec<String> = list_tenants(&state);
    let listing = if existing.is_empty() {
        r#"<p>No tenants yet.</p>"#.to_string()
    } else {
        format!(
            r#"<h2>Existing tenants</h2><table><tr><th>Tenant</th><th>Run</th></tr>{}</table>"#,
            existing
                .iter()
                .map(|n| format!(
                    r#"<tr><td><code>{}</code></td><td><code>tenants/up.sh {}</code></td></tr>"#,
                    esc(n),
                    esc(n)
                ))
                .collect::<Vec<_>>()
                .join("")
        )
    };
    let body = format!(
        r##"<h1>Tenants</h1>
<p class="note">A tenant is a manifest. This page writes
<code>tenants/&lt;name&gt;/unidpp-operator.yaml</code>, validated before
saving; bringing it up is one command, shown after creation. The
console never starts processes.</p>
{listing}
<h2>Create a tenant</h2>
<form method="post" action="/tenants" style="display:grid;gap:.6rem;max-width:34rem">
  <input name="name" placeholder="name (letters, digits, -)" required>
  <input name="organization" placeholder="organization" required>
  <input name="product_name" placeholder="product name" required>
  <select name="profile">
    <option value="whitelabel">whitelabel</option>
    <option value="sovereign">sovereign</option>
    <option value="reference">reference</option>
  </select>
  <input name="residency" placeholder="data residency (e.g. EU, CN)">
  <div style="display:flex;gap:.6rem">
    <input name="primary" placeholder="#rrggbb primary" value="#0f62fe">
    <input name="accent" placeholder="#rrggbb accent" value="#08bdba">
  </div>
  <fieldset style="border:1px solid var(--line);border-radius:8px">
    <legend>Pack suites</legend>
    <label><input type="checkbox" name="suites" value="ecdsa-p256" checked> ecdsa-p256</label>
    <label><input type="checkbox" name="suites" value="sm2"> sm2</label>
    <label><input type="checkbox" name="suities" value="ml-dsa-65"> ml-dsa-65</label>
  </fieldset>
  <input name="base_port" type="number" placeholder="base port (registry binds here)" value="9390">
  <button type="submit">Validate &amp; create</button>
</form>"##
    );
    page_for(&state, "Tenants", "tenants", body)
}

pub(crate) async fn tenants_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::RawForm(bytes): axum::extract::RawForm,
) -> Response {
    if !state.session_valid(&headers) {
        return page_for(
            &state,
            "Tenants",
            "tenants",
            r#"<div class="error">Creating tenants requires a signed-in
session. <a href="/login">Sign in</a>.</div><a href="/tenants">← back</a>"#
                .to_string(),
        );
    }
    // The checkboxes post one `suites` key per box — a sequence.
    // axum's Form (serde_urlencoded) cannot read repeated keys, so
    // the tenant form parses through serde_html_form.
    let form: TenantForm = match serde_html_form::from_bytes(&bytes) {
        Ok(form) => form,
        Err(error) => {
            return tenant_error(
                &state,
                &format!("the form did not parse: {error}"),
                &TenantForm::default(),
            );
        }
    };
    let name_ok = !form.name.is_empty()
        && form
            .name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-');
    if !name_ok {
        return tenant_error(
            &state,
            "the name must be letters, digits, and hyphens",
            &form,
        );
    }
    let target = tenants_dir(&state)
        .join(&form.name)
        .join("unidpp-operator.yaml");
    if target.exists() {
        return tenant_error(
            &state,
            &format!("tenant `{}` already exists", form.name),
            &form,
        );
    }
    let yaml = tenant_manifest_yaml(&form);
    match load_manifest(&yaml).map_err(|e| e.to_string()) {
        Ok(_) => {}
        Err(error) => return tenant_error(&state, &error, &form),
    }
    if let Err(e) = std::fs::create_dir_all(target.parent().expect("tenant dir")) {
        return tenant_error(
            &state,
            &format!("cannot create the tenant directory: {e}"),
            &form,
        );
    }
    if let Err(e) = std::fs::write(&target, &yaml) {
        return tenant_error(
            &state,
            &format!("cannot write {}: {e}", target.display()),
            &form,
        );
    }
    let body = format!(
        r#"<div class="note">Tenant <code>{}</code> created and validated.</div>
<h2>Bring it up</h2>
<pre>./tenants/up.sh {}</pre>
<p>Then its console answers on port {} (bind declared in its
manifest). <a href="/tenants">← tenants</a></p>"#,
        esc(&form.name),
        esc(&form.name),
        form.base_port.saturating_sub(1).max(1024),
    );
    page_for(&state, "Tenants", "tenants", body)
}

pub(crate) fn tenant_error(state: &AppState, message: &str, form: &TenantForm) -> Response {
    let body = format!(
        r#"<div class="error">Not created: {}.</div>
<p>The form values were kept below; fix and resubmit.</p>
<pre>{}</pre>
<a href="/tenants">← start over</a>"#,
        esc(message),
        esc(&tenant_manifest_yaml(form)),
    );
    page_for(state, "Tenants", "tenants", body)
}

// ---------------------------------------------------------------------------
// Trust (#140): what a verifier pins, what stands — facts from the
// trust service's own APIs, never a second brain.
// ---------------------------------------------------------------------------
