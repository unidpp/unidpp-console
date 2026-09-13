//! The branding surface: the whitelabel identity applied through the validated save path.

use axum::extract::Form;

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

pub(crate) fn branding_form(b: &unidpp_config::Branding) -> String {
    fn opt(v: &Option<String>) -> &str {
        v.as_deref().unwrap_or("")
    }
    format!(
        r#"<h2>Edit</h2>
<p class="note">Saving rewrites the manifest's branding block through
the validated path (values preserved; YAML comment lines and hand
formatting normalize — the shipped manifests carry none). Hex colors
only.</p>
<form method="post" action="/branding">
<table>
<tr><th><label for="organization">Organization</label></th>
    <td><input name="organization" id="organization" style="width:100%" value="{}"></td></tr>
<tr><th><label for="product_name">Product name</label></th>
    <td><input name="product_name" id="product_name" style="width:100%" value="{}"></td></tr>
<tr><th><label for="logo">Logo URL</label></th>
    <td><input name="logo" id="logo" style="width:100%" value="{}"></td></tr>
<tr><th><label for="primary">Primary (hex)</label></th>
    <td><input name="primary" id="primary" value="{}"></td></tr>
<tr><th><label for="accent">Accent (hex)</label></th>
    <td><input name="accent" id="accent" value="{}"></td></tr>
<tr><th><label for="legal_url">Footer legal URL</label></th>
    <td><input name="legal_url" id="legal_url" style="width:100%" value="{}"></td></tr>
<tr><th><label for="contact_url">Footer contact URL</label></th>
    <td><input name="contact_url" id="contact_url" style="width:100%" value="{}"></td></tr>
</table>
<p><button type="submit">Save branding</button>
<span style="color:var(--muted)"> — requires a signed-in session</span></p>
</form>"#,
        esc(&b.organization),
        esc(&b.product_name),
        esc(opt(&b.logo)),
        esc(&b.theme.primary),
        esc(&b.theme.accent),
        esc(opt(&b.footer.legal_url)),
        esc(opt(&b.footer.contact_url)),
    )
}

#[derive(Deserialize)]
pub(crate) struct BrandingForm {
    pub(crate) organization: String,
    pub(crate) product_name: String,
    pub(crate) logo: String,
    pub(crate) primary: String,
    pub(crate) accent: String,
    pub(crate) legal_url: String,
    pub(crate) contact_url: String,
}

/// POST /branding — apply the form to the manifest's branding block
/// through the validated save path; nothing else in the manifest is
/// touched (the model is loaded, mutated, re-serialized).
pub(crate) async fn branding_save(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<BrandingForm>,
) -> Response {
    if !state.session_valid(&headers) {
        return page_for(
            &state,
            "Branding",
            "branding",
            r#"<div class="error">Editing requires a signed-in session.
<a href="/login">Sign in</a>.</div>"#
                .to_string(),
        );
    }
    let outcome = state.with_manifest(|m| {
        let mut manifest = m.clone();
        manifest.branding.organization = form.organization.trim().to_string();
        manifest.branding.product_name = form.product_name.trim().to_string();
        manifest.branding.logo = non_empty(&form.logo);
        manifest.branding.theme.primary = form.primary.trim().to_string();
        manifest.branding.theme.accent = form.accent.trim().to_string();
        manifest.branding.footer.legal_url = non_empty(&form.legal_url);
        manifest.branding.footer.contact_url = non_empty(&form.contact_url);
        serde_yaml::to_string(&manifest).map_err(|e| e.to_string())
    });
    let body = match outcome.and_then(|text| state.save_manifest(&text).map(|_| text)) {
        Ok(_) => r#"<div class="note">Branding saved and validated — the
console re-renders everywhere on the next page load.</div>"#
            .to_string(),
        Err(error) => format!(
            r#"<div class="error">Rejected — nothing was written: {}</div>"#,
            esc(&error)
        ),
    };
    let full = format!(
        r#"{}<p><a href="/branding">&larr; back to branding</a></p>"#,
        body
    );
    page_for(&state, "Branding", "branding", full)
}

pub(crate) fn non_empty(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

pub(crate) async fn branding_preview(State(state): State<Arc<AppState>>) -> Response {
    let body = state.with_manifest(|m| {
        let b = &m.branding;
        let editor = branding_form(b);
        format!(
            r#"<h1>Branding</h1>
<p>Every console and explorer surface renders from these values —
zero code between the reference deployment and yours.</p>
<div class="grid">
  <div class="card"><div class="label">Organization</div><div class="value">{}</div></div>
  <div class="card"><div class="label">Product name</div><div class="value">{}</div></div>
</div>
<h2>Theme</h2>
<div class="swatches">
  <div class="swatch" style="background:{}">primary</div>
  <div class="swatch" style="background:{}">accent</div>
</div>
<h2>Chrome preview</h2>
<div class="card" style="border-top:3px solid {}">
  <div style="display:flex;justify-content:space-between">
    <strong>{}</strong><span style="color:var(--muted)">{}</span>
  </div>
  <p style="color:var(--muted)">The dashboard header, login card, and badges
  inherit these colors; the footer carries the legal and contact links.</p>
</div>
{editor}
<h2>Manifest branding block</h2>
<pre>{}</pre>"#,
            esc(&b.organization),
            esc(&b.product_name),
            esc(&b.theme.primary),
            esc(&b.theme.accent),
            esc(&b.theme.primary),
            esc(&b.organization),
            esc(&b.product_name),
            esc(&serde_yaml_to_string(&serde_json::json!({
                "organization": b.organization,
                "product_name": b.product_name,
                "theme": {"primary": b.theme.primary, "accent": b.theme.accent},
            }))),
        )
    });
    page_for(&state, "Branding", "branding", body)
}

pub(crate) fn serde_yaml_to_string(value: &serde_json::Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Live metrics (#109): the numbers an operator checks, from the
// services' own APIs; a down service degrades to "—", never an error.
// ---------------------------------------------------------------------------
