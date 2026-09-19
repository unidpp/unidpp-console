//! The configuration surface: the manifest editor, its env view, the validated save.

use axum::extract::Form;
use std::collections::HashMap;
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
use unidpp_config::render_env;

/// The manifest editor: the deployment as data, secrets still ${VAR} references.
#[utoipa::path(
    get,
    path = "/config",
    tag = "console",
    responses(
        (status = 200, description = "The page, rendered against the deployment manifest", body = String, content_type = "text/html"),
        (status = 303, description = "The session gate redirects an unauthenticated browser to `/login`"),
    )
)]
pub(crate) async fn config_page(State(state): State<Arc<AppState>>) -> Response {
    let text = state.manifest_text();
    let body = format!(
        r#"<h1>Configuration</h1>
<p class="note">The operator manifest is the deployment. Secrets stay
<code>${{'{{VAR}}'}}</code> references — the editor shows the file as stored, never
resolved values. Saving validates first; a rejected manifest is never
written.</p>
<form method="post" action="/config">
<textarea name="manifest" spellcheck="false" aria-label="operator manifest YAML">{}</textarea>
<div style="display:flex;gap:.6rem;margin-top:.8rem">
  <button type="submit">Validate &amp; save</button>
  <a href="/config"><button type="button" class="secondary">Reset</button></a>
</div>
</form>
<h2>Rendered environment</h2>
<p>Pick a service to preview the exact <code>UNIDPP_*</code> environment the
manifest produces:</p>
<form method="get" action="/config/env" class="inline" style="display:flex;gap:.6rem">
  <select name="service">{}</select>
  <button type="submit" class="secondary">Render</button>
</form>"#,
        esc(&text),
        state.with_manifest(|m| {
            m.service_names()
                .iter()
                .map(|n| format!("<option value=\"{n}\">{n}</option>"))
                .collect::<Vec<_>>()
                .join("")
        }),
    );
    page_for(&state, "Configuration", "config", body)
}

/// The rendered environment of the deployment, resolved secrets sealed.
#[utoipa::path(
    get,
    path = "/config/env",
    tag = "console",
    responses(
        (status = 200, description = "The page, rendered against the deployment manifest", body = String, content_type = "text/html"),
        (status = 303, description = "The session gate redirects an unauthenticated browser to `/login`"),
    )
)]
pub(crate) async fn config_env(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> Response {
    let service = params.get("service").cloned().unwrap_or_default();
    let rendered = state.with_manifest(|m| render_env(m, &service));
    let body = format!(
        r#"<h1>Rendered environment for <code>{}</code></h1>
<pre>{}</pre>
<p><a href="/config">← back to the manifest</a></p>"#,
        esc(&service),
        esc(&rendered.unwrap_or_else(|e| format!("error: {e}"))),
    );
    page_for(&state, "Environment", "config", body)
}

#[derive(Deserialize)]
pub(crate) struct ConfigForm {
    pub(crate) manifest: String,
}

/// Save the edited manifest.
#[utoipa::path(
    post,
    path = "/config",
    tag = "console",
    request_body(content = String, content_type = "application/x-www-form-urlencoded", description = "The edited manifest text"),
    responses(
        (status = 303, description = "Saved: a redirect back to the editor"),
        (status = 200, description = "The form is re-rendered with its error stated", body = String, content_type = "text/html"),
    )
)]
pub(crate) async fn config_save(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<ConfigForm>,
) -> Response {
    if !state.session_valid(&headers) {
        return page_for(
            &state,
            "Configuration",
            "config",
            r#"<div class="error">Saving requires a signed-in session (the
admin token). <a href="/login">Sign in</a>.</div>
<a href="/config">← back</a>"#
                .to_string(),
        );
    }
    // Validate without resolving secrets against the live env first:
    // show unset-variable errors distinctly (the file may be edited
    // before the operator exports the variable).
    let staged = form.manifest.clone();
    match state.save_manifest(&staged) {
        Ok(manifest) => {
            let body = format!(
                r#"<div class="note">Saved and validated: {} (profile {}, {} service(s)).</div>
<a href="/config">← back to the manifest</a> · <a href="/">dashboard →</a>"#,
                esc(&manifest.deployment.name),
                esc(manifest.deployment.profile.as_str()),
                manifest.service_names().len(),
            );
            page_for(&state, "Configuration", "config", body)
        }
        Err(error) => {
            let unset = if error.to_string().contains("unset variable") {
                r#"<p class="note">A referenced secret variable is not set in this
console's environment. Export it (or the deployment's service runner
exports it) and save again; the manifest itself is fine to stage.</p>"#
            } else {
                ""
            };
            let body = format!(
                r#"<div class="error">Rejected, and nothing was written:</div>
<pre>{}</pre>
{unset}
<form method="post" action="/config">
<textarea name="manifest" spellcheck="false">{}</textarea>
<button type="submit">Validate &amp; save</button>
</form>"#,
                esc(&error.to_string()),
                esc(&staged),
            );
            page_for(&state, "Configuration", "config", body)
        }
    }
}
