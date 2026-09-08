//! The UniDPP admin console — one branded pane over a deployment.
//!
//! The SaaS doctrine the console embodies: **a deployment is data**
//! (the operator manifest, [`unidpp_config`]) and **the console is a
//! surface, not a second brain** — every fact it shows comes from a
//! service's own API or from the manifest; every capability is a call
//! to an existing endpoint. It adds no domain logic (MECE by
//! construction) and it is itself configured by the same manifest it
//! manages: branding, binds, and the admin token all come from
//! `unidpp-operator.yaml` + environment.
//!
//! Pages: dashboard (per-service health), configuration (edit the
//! manifest YAML, validate, save atomically, preview any service's
//! rendered environment), registry (the item browser), passports (the
//! issuer's audit trail + inline pack verification through the CLI's
//! own pipeline), branding (the whitelabel preview).
//!
//! Security posture: mutations (config save) require a session; the
//! session requires the admin token (constant-time compare); secrets
//! are only ever shown as their `${VAR}` references — the console
//! loads the manifest for structure but never renders resolved
//! secret values; every interpolated string goes through
//! [`crate::html::esc`].

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Form, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;
use tokio::net::TcpListener;
use unidpp_config::{load as load_manifest, render_env, OperatorManifest};

mod html;
mod http;
mod verify;

use html::esc;

/// Session lifetime.
const SESSION_LIFETIME: Duration = Duration::from_secs(8 * 3600);

/// Deployment configuration (env-driven, house convention).
#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub manifest_path: PathBuf,
    pub admin_token: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Config, String> {
        let mut config = Config {
            bind: "127.0.0.1:8397".parse().expect("static bind"),
            manifest_path: PathBuf::from("unidpp-operator.yaml"),
            admin_token: None,
        };
        if let Ok(bind) = std::env::var("UNIDPP_CONSOLE_BIND") {
            config.bind = bind
                .parse()
                .map_err(|_| format!("bad UNIDPP_CONSOLE_BIND `{bind}`"))?;
        }
        if let Ok(path) = std::env::var("UNIDPP_CONSOLE_MANIFEST") {
            if !path.trim().is_empty() {
                config.manifest_path = PathBuf::from(path);
            }
        }
        if let Ok(token) = std::env::var("UNIDPP_CONSOLE_ADMIN_TOKEN") {
            if !token.is_empty() {
                config.admin_token = Some(token);
            }
        }
        Ok(config)
    }
}

/// Shared state: the config, the loaded manifest, and the sessions.
pub struct AppState {
    pub config: Config,
    /// The manifest text as stored on disk (secrets still `${VAR}`
    /// references — the source of truth for the editor).
    manifest_text: Mutex<String>,
    /// The parsed manifest (structure only; resolved secrets never
    /// leave this process).
    manifest: Mutex<OperatorManifest>,
    sessions: Mutex<HashMap<String, Instant>>,
}

impl AppState {
    pub fn new(config: Config) -> Result<AppState, String> {
        let text = std::fs::read_to_string(&config.manifest_path).map_err(|e| {
            format!(
                "cannot read manifest {}: {e}",
                config.manifest_path.display()
            )
        })?;
        let manifest = load_manifest(&text).map_err(|e| e.to_string())?;
        Ok(AppState {
            config,
            manifest_text: Mutex::new(text),
            manifest: Mutex::new(manifest),
            sessions: Mutex::new(HashMap::new()),
        })
    }

    fn with_manifest<R>(&self, f: impl FnOnce(&OperatorManifest) -> R) -> R {
        f(&self.manifest.lock().expect("manifest poisoned"))
    }

    fn manifest_text(&self) -> String {
        self.manifest_text
            .lock()
            .expect("manifest text poisoned")
            .clone()
    }

    fn save_manifest(&self, text: &str) -> Result<OperatorManifest, String> {
        let manifest = load_manifest(text).map_err(|e| e.to_string())?;
        // Atomic replace: a failed write never truncates the live one.
        let tmp = self.config.manifest_path.with_extension("yaml.tmp");
        std::fs::write(&tmp, text).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, &self.config.manifest_path).map_err(|e| {
            format!(
                "cannot replace {}: {e}",
                self.config.manifest_path.display()
            )
        })?;
        *self.manifest_text.lock().expect("manifest text poisoned") = text.to_string();
        *self.manifest.lock().expect("manifest poisoned") = manifest.clone();
        Ok(manifest)
    }

    fn issue_session(&self) -> String {
        let nonce = Instant::now().sub_nanos_since_epoch().to_le_bytes();
        let token = hex(&unidpp_model::sha256(&[
            b"UNIDPP-CONSOLE/SESSION",
            &nonce,
            self.config.admin_token.as_deref().unwrap_or("").as_bytes(),
        ])
        .0);
        self.sessions
            .lock()
            .expect("sessions poisoned")
            .insert(token.clone(), Instant::now() + SESSION_LIFETIME);
        token
    }

    fn session_valid(&self, headers: &HeaderMap) -> bool {
        // No token configured = open dev mode (house convention), but
        // config saves still require a session, which requires the
        // token — open mode is read-only by construction.
        if self.config.admin_token.is_none() {
            return false;
        }
        let cookie = headers
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .and_then(|c| {
                c.split(';')
                    .find_map(|p| p.trim().strip_prefix("unidpp_console="))
            })
            .unwrap_or("");
        if cookie.is_empty() {
            return false;
        }
        let mut sessions = self.sessions.lock().expect("sessions poisoned");
        match sessions.get(cookie) {
            Some(expiry) if *expiry > Instant::now() => true,
            Some(_) => {
                sessions.remove(cookie);
                false
            }
            None => false,
        }
    }
}

trait InstantExt {
    fn sub_nanos_since_epoch(self) -> u128;
}

impl InstantExt for Instant {
    fn sub_nanos_since_epoch(self) -> u128 {
        self.elapsed().as_nanos() ^ std::process::id() as u128
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Constant-time string equality (session tokens).
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

fn html_response(body: String) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .body(axum::body::Body::from(body))
        .expect("static response parts")
}

fn redirect(location: &str) -> Response {
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header("location", location)
        .body(axum::body::Body::empty())
        .expect("static response parts")
}

fn page_for(state: &AppState, title: &str, active: &str, body: String) -> Response {
    let full = state.with_manifest(|m| html::page(m, title, &body, active));
    html_response(full)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// The service identity (the orchestrator's probe reads it).
async fn service_identity(State(state): State<Arc<AppState>>) -> Response {
    let body = state.with_manifest(|m| {
        serde_json::json!({
            "service": "unidpp-console",
            "deployment": m.deployment.name,
            "profile": m.deployment.profile.as_str(),
            "product": m.branding.product_name,
        })
    });
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .expect("static response parts")
}

async fn healthz() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain")
        .body(axum::body::Body::from("ok"))
        .expect("static response parts")
}

async fn login_page(State(state): State<Arc<AppState>>) -> Response {
    if state.config.admin_token.is_none() {
        return page_for(
            &state,
            "Sign in",
            "",
            r#"<div class="card"><h1>Open dev mode</h1>
<p>No admin token is configured. The console is read-only:
configuration saves require <code>UNIDPP_CONSOLE_ADMIN_TOKEN</code>.</p>
<p><a href="/">Continue to the dashboard →</a></p></div>"#
                .to_string(),
        );
    }
    page_for(
        &state,
        "Sign in",
        "",
        r#"<div class="card" style="max-width:26rem;margin:4rem auto;text-align:center">
<h1>Sign in</h1>
<form method="post" action="/login">
  <input type="password" name="token" placeholder="admin token" style="width:100%" autofocus>
  <button type="submit" style="width:100%;margin-top:.6rem">Sign in</button>
</form></div>"#
            .to_string(),
    )
}

#[derive(Deserialize)]
struct LoginForm {
    token: String,
}

async fn login_submit(State(state): State<Arc<AppState>>, Form(form): Form<LoginForm>) -> Response {
    let expected = match &state.config.admin_token {
        Some(token) => token,
        None => return redirect("/"),
    };
    if !constant_time_eq(&form.token, expected) {
        return page_for(
            &state,
            "Sign in",
            "",
            r#"<div class="error">The token did not match.</div>"#.to_string(),
        );
    }
    let session = state.issue_session();
    let mut response = redirect("/");
    response.headers_mut().insert(
        "set-cookie",
        format!(
            "unidpp_console={session}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
            SESSION_LIFETIME.as_secs()
        )
        .parse()
        .expect("static cookie"),
    );
    response
}

async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(cookie) = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|c| {
            c.split(';')
                .find_map(|p| p.trim().strip_prefix("unidpp_console="))
        })
    {
        state
            .sessions
            .lock()
            .expect("sessions poisoned")
            .remove(cookie);
    }
    redirect("/login")
}

async fn dashboard(State(state): State<Arc<AppState>>) -> Response {
    let declared: Vec<(String, String, String)> = state.with_manifest(|m| {
        m.service_names()
            .iter()
            .map(|name| {
                let (bind, note) = service_bind_note(m, name);
                (name.to_string(), bind, note)
            })
            .collect()
    });
    let mut services = Vec::new();
    for (name, bind, note) in declared {
        let health = match http::port_of(&bind) {
            Some(port) => match http::get(port, "/healthz").await {
                Some(resp) if resp.status == 200 => {
                    r#"<span class="badge ok">healthy</span>"#.to_string()
                }
                Some(resp) => format!(r#"<span class="badge bad">HTTP {}</span>"#, resp.status),
                None => r#"<span class="badge bad">unreachable</span>"#.to_string(),
            },
            None => r#"<span class="badge warn">no bind</span>"#.to_string(),
        };
        services.push(format!(
            r#"<tr><td><code>{}</code></td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>"#,
            esc(&name),
            esc(&bind),
            esc(&note),
            health
        ));
    }
    let summary = state.with_manifest(|m| {
        format!(
            r#"<div class="grid">
  <div class="card"><div class="label">Deployment</div><div class="value">{}</div></div>
  <div class="card"><div class="label">Profile</div><div class="value">{}</div></div>
  <div class="card"><div class="label">Base URL</div><div class="value" style="font-size:.95rem">{}</div></div>
  <div class="card"><div class="label">Egress policy</div><div class="value" style="font-size:.95rem">{}</div></div>
</div>"#,
            esc(&m.deployment.name),
            esc(m.deployment.profile.as_str()),
            esc(&m.deployment.base_url),
            esc(&egress_label(m)),
        )
    });
    let metrics = metrics_cards(&state).await;
    let body = format!(
        r#"<h1>Dashboard</h1>
{summary}
{metrics}
<h2>Services</h2>
<table><tr><th>Service</th><th>Bind</th><th>Role</th><th>Health</th></tr>
{}</table>"#,
        services.join("\n")
    );
    page_for(&state, "Dashboard", "dashboard", body)
}

fn egress_label(m: &OperatorManifest) -> String {
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

fn service_bind_note(m: &OperatorManifest, name: &str) -> (String, String) {
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
        other => (String::new(), other.to_string()),
    }
}

async fn config_page(State(state): State<Arc<AppState>>) -> Response {
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

async fn config_env(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> Response {
    let service = params.get("service").cloned().unwrap_or_default();
    let rendered = state.with_manifest(|m| render_env(m, &service));
    let body = format!(
        r#"<h1>Rendered environment — <code>{}</code></h1>
<pre>{}</pre>
<p><a href="/config">← back to the manifest</a></p>"#,
        esc(&service),
        esc(&rendered.unwrap_or_else(|e| format!("error: {e}"))),
    );
    page_for(&state, "Environment", "config", body)
}

#[derive(Deserialize)]
struct ConfigForm {
    manifest: String,
}

async fn config_save(
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
exports it) and save again — the manifest itself is fine to stage.</p>"#
            } else {
                ""
            };
            let body = format!(
                r#"<div class="error">Rejected — nothing was written:</div>
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

async fn registry_browser(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> Response {
    let class = params.get("class").cloned().unwrap_or_default();
    let register = params.get("register").cloned().unwrap_or_default();
    let rows = state.with_manifest(|m| {
        let port = m
            .services
            .registry
            .as_ref()
            .and_then(|s| http::port_of(&s.bind))?;
        let mut path = "/items?limit=50".to_string();
        if !class.is_empty() {
            path.push_str(&format!("&class={class}"));
        }
        if !register.is_empty() {
            path.push_str(&format!("&register={register}"));
        }
        let response = futures_block(http::get(port, &path))?;
        let doc = response.json()?;
        let count = doc.get("count").and_then(|c| c.as_u64()).unwrap_or(0);
        let mut rows = Vec::new();
        for item in doc.get("items").and_then(|i| i.as_array()).unwrap_or(&vec![]) {
            let id = item.get("identifier").and_then(|v| v.as_str()).unwrap_or("");
            let iclass = item.get("item_class").and_then(|v| v.as_str()).unwrap_or("");
            let reg = item.get("register").and_then(|v| v.as_str()).unwrap_or("");
            rows.push(format!(
                r#"<tr><td><code>{}</code></td><td>{}</td><td>{}</td></tr>"#,
                esc(id),
                esc(iclass),
                esc(reg)
            ));
        }
        Some(format!(
            r#"<p>{} item(s)</p><table><tr><th>Identifier</th><th>Class</th><th>Register</th></tr>{}</table>"#,
            count,
            rows.join("")
        ))
    });
    let body = format!(
        r#"<h1>Registry</h1>
<form method="get" action="/registry" style="display:flex;gap:.6rem;flex-wrap:wrap">
  <input name="class" placeholder="class (e.g. profile)" value="{}">
  <input name="register" placeholder="register (e.g. untded)" value="{}">
  <button type="submit" class="secondary">Filter</button>
</form>
{}"#,
        esc(&class),
        esc(&register),
        rows.unwrap_or_else(|| {
            r#"<div class="error">The registry is not reachable (or this deployment
declares none).</div>"#
                .to_string()
        }),
    );
    page_for(&state, "Registry", "registry", body)
}

async fn passports_page(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> Response {
    let lookup = params.get("id").cloned().unwrap_or_default();
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
        // The audit log tail: recent lifecycle actions.
        if let Some(resp) = futures_block(http::get(port, "/admin/log?limit=20")) {
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
        body.push_str(&verify::form_html(port).await);
    } else {
        body.push_str(r#"<div class="error">This deployment declares no issuer.</div>"#);
    }
    page_for(&state, "Passports", "passports", body)
}

fn urlencode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b':' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Block on the async client from the sync manifest closure (the
/// closure borrows the manifest lock; the fetch itself is async).
fn futures_block<F: std::future::Future>(future: F) -> F::Output {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(future))
}

async fn branding_preview(State(state): State<Arc<AppState>>) -> Response {
    let body = state.with_manifest(|m| {
        let b = &m.branding;
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

fn serde_yaml_to_string(value: &serde_json::Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Live metrics (#109): the numbers an operator checks, from the
// services' own APIs; a down service degrades to "—", never an error.
// ---------------------------------------------------------------------------

async fn metrics_cards(state: &Arc<AppState>) -> String {
    let registry_port = state.with_manifest(|m| {
        m.services
            .registry
            .as_ref()
            .and_then(|s| http::port_of(&s.bind))
    });
    let log_port =
        state.with_manifest(|m| m.services.log.as_ref().and_then(|s| http::port_of(&s.bind)));
    let card = |label: &str, value: String| {
        format!(
            r#"<div class="card"><div class="label">{label}</div><div class="value">{value}</div></div>"#
        )
    };
    async fn count_at(port: Option<u16>, path: &str) -> Option<u64> {
        let doc = match port {
            Some(port) => http::get(port, path).await.and_then(|r| r.json()),
            None => None,
        }?;
        doc.get("count").and_then(|c| c.as_u64())
    }
    let items = count_at(registry_port, "/items?limit=1")
        .await
        .map(|c| c.to_string())
        .unwrap_or_else(|| "—".to_string());
    let untded = count_at(
        registry_port,
        "/items?class=data-element&register=untded&limit=1",
    )
    .await
    .map(|c| c.to_string())
    .unwrap_or_else(|| "—".to_string());
    let tree_size = match log_port {
        Some(port) => http::get(port, "/tree/head")
            .await
            .and_then(|r| r.json())
            .and_then(|d| d.get("tree_size").and_then(|c| c.as_u64()))
            .map(|c| c.to_string())
            .unwrap_or_else(|| "—".to_string()),
        None => "—".to_string(),
    };
    format!(
        r#"<div class="grid">{}</div>"#,
        [
            card("Registry items", items),
            card("UNTDED data elements", untded),
            card("Log tree size", tree_size),
        ]
        .join("")
    )
}

// ---------------------------------------------------------------------------
// Egress inventory (#105): what leaves the box, derived from the
// manifest — sovereignty made visible, not aspirational.
// ---------------------------------------------------------------------------

async fn egress_page(State(state): State<Arc<AppState>>) -> Response {
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
surface below is ingress — answers, not calls.</div>"#
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

fn tenants_dir(state: &AppState) -> PathBuf {
    state
        .config
        .manifest_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("tenants")
}

fn list_tenants(state: &AppState) -> Vec<String> {
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

fn tenant_manifest_yaml(form: &TenantForm) -> String {
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

#[derive(Deserialize, Default, Clone)]
struct TenantForm {
    name: String,
    organization: String,
    product_name: String,
    profile: String,
    residency: String,
    primary: String,
    accent: String,
    suites: Vec<String>,
    base_port: u16,
}

async fn tenants_page(State(state): State<Arc<AppState>>) -> Response {
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

async fn tenants_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<TenantForm>,
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

fn tenant_error(state: &AppState, message: &str, form: &TenantForm) -> Response {
    let body = format!(
        r#"<div class="error">Not created — {}.</div>
<p>The form values were kept below; fix and resubmit.</p>
<pre>{}</pre>
<a href="/tenants">← start over</a>"#,
        esc(message),
        esc(&tenant_manifest_yaml(form)),
    );
    page_for(state, "Tenants", "tenants", body)
}

// ---------------------------------------------------------------------------
// Backups (#111): the console triggers the operator script and lists
// the results; the logic lives in one place (unidpp-ops), never here.
// ---------------------------------------------------------------------------

async fn backups_page(State(state): State<Arc<AppState>>) -> Response {
    let body = match backups_render(&state).await {
        Ok(body) => body,
        Err(error) => format!(r#"<div class="error">{}</div>"#, esc(&error)),
    };
    page_for(&state, "Backups", "backups", body)
}

async fn backups_render(state: &Arc<AppState>) -> Result<String, String> {
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
    Ok(format!(
        r#"<h1>Backups</h1>
<p class="note">A backup is the deployment as data: the manifest, every
journal, the seed — checksummed, with the log tree head as the
consistency point. Restore is <code>unidpp-ops restore</code>.</p>
{listing}
<h2>Take one now</h2>
<form method="post" action="/backups">
  <button type="submit">Back up this deployment</button>
</form>
<p class="note">Requires a signed-in session.</p>"#
    ))
}

async fn backups_run(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
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
            r#"<div class="error">The script failed — nothing lost.</div><pre>{}</pre>
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

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/.well-known/unidpp-service", get(service_identity))
        .route("/", get(dashboard))
        .route("/login", get(login_page).post(login_submit))
        .route("/logout", post(logout))
        .route("/config", get(config_page).post(config_save))
        .route("/config/env", get(config_env))
        .route("/registry", get(registry_browser))
        .route("/passports", get(passports_page).post(verify::submit))
        .route("/branding", get(branding_preview))
        .route("/egress", get(egress_page))
        .route("/tenants", get(tenants_page).post(tenants_create))
        .route("/backups", get(backups_page).post(backups_run))
        .with_state(state)
}

/// Run until stopped.
pub async fn run(config: Config) -> std::io::Result<()> {
    let bind = config.bind;
    let state = Arc::new(AppState::new(config).unwrap_or_else(|e| {
        eprintln!("unidpp-console: {e}");
        std::process::exit(1);
    }));
    let listener = TcpListener::bind(bind).await?;
    eprintln!("unidpp-console listening on http://{bind}");
    axum::serve(listener, router(state)).await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_yaml() -> String {
        r#"api_version: unidpp.org/v1
deployment:
  name: console-test
  profile: whitelabel
  base_url: https://dpp.example.org
branding:
  organization: "<script>alert(1)</script> Corp"
  product_name: Example DPP
services:
  registry:
    bind: 127.0.0.1:1
"#
        .to_string()
    }

    fn state_with(manifest: &str) -> Arc<AppState> {
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("unidpp-console-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("unidpp-operator.yaml");
        std::fs::write(&path, manifest).unwrap();
        Arc::new(
            AppState::new(Config {
                bind: "127.0.0.1:0".parse().unwrap(),
                manifest_path: path,
                admin_token: Some("test-token".to_string()),
            })
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn every_interpolated_value_is_escaped() {
        let state = state_with(&manifest_yaml());
        let response = dashboard(axum::extract::State(state.clone())).await;
        let body = response_into_string(response).await;
        assert!(
            !body.contains("<script>alert(1)"),
            "the organization name must be escaped"
        );
        assert!(body.contains("&lt;script&gt;"), "escaped form present");
    }

    #[tokio::test]
    async fn login_requires_the_token_and_issues_a_session() {
        let state = state_with(&manifest_yaml());
        let wrong = login_submit(
            axum::extract::State(state.clone()),
            Form(LoginForm {
                token: "nope".to_string(),
            }),
        )
        .await;
        assert_eq!(status_of(&wrong), StatusCode::OK); // the refusal page
        assert!(session_cookie_of(&wrong).is_none());

        let right = login_submit(
            axum::extract::State(state.clone()),
            Form(LoginForm {
                token: "test-token".to_string(),
            }),
        )
        .await;
        assert_eq!(status_of(&right), StatusCode::SEE_OTHER);
        assert!(session_cookie_of(&right).is_some());
    }

    #[tokio::test]
    async fn config_save_is_session_gated_and_validates() {
        let state = state_with(&manifest_yaml());
        // Anonymous save: refused.
        let denied = config_save(
            axum::extract::State(state.clone()),
            HeaderMap::new(),
            Form(ConfigForm {
                manifest: manifest_yaml(),
            }),
        )
        .await;
        let body = response_into_string(denied).await;
        assert!(body.contains("requires a signed-in session"));

        // Signed-in save of a broken manifest: rejected, not written.
        let session = state.issue_session();
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            format!("unidpp_console={session}").parse().unwrap(),
        );
        let broken = manifest_yaml().replace("unidpp.org/v1", "unidpp.org/v9");
        let rejected = config_save(
            axum::extract::State(state.clone()),
            headers.clone(),
            Form(ConfigForm { manifest: broken }),
        )
        .await;
        let body = response_into_string(rejected).await;
        assert!(body.contains("Rejected"));
        assert_eq!(
            state.manifest_text(),
            manifest_yaml(),
            "nothing was written"
        );

        // A valid save round-trips into state.
        let valid = manifest_yaml().replace(
            "  registry:\n    bind: 127.0.0.1:1",
            "  registry:\n    bind: 127.0.0.1:1\n  issuer:\n    bind: 127.0.0.1:2\n    pack_suites: [sm2]",
        );
        let saved = config_save(
            axum::extract::State(state.clone()),
            headers,
            Form(ConfigForm { manifest: valid }),
        )
        .await;
        let body = response_into_string(saved).await;
        assert!(body.contains("Saved and validated"), "{body}");
        state.with_manifest(|m| assert_eq!(m.service_names().len(), 2));
    }

    #[tokio::test]
    async fn secrets_never_render_resolved() {
        std::env::set_var("UNIDPP_CONSOLE_TEST_SECRET", "supersecret");
        let manifest = manifest_yaml().replace(
            "    bind: 127.0.0.1:1",
            "    bind: 127.0.0.1:1\n    admin_token: ${UNIDPP_CONSOLE_TEST_SECRET}",
        );
        let state = state_with(&manifest);
        let response = config_page(axum::extract::State(state.clone())).await;
        let body = response_into_string(response).await;
        assert!(
            body.contains("${UNIDPP_CONSOLE_TEST_SECRET}"),
            "the reference shows"
        );
        assert!(!body.contains("supersecret"), "the value never does");
    }

    #[tokio::test]
    async fn egress_inventory_shows_sealed_and_real_rows() {
        let state = state_with(&manifest_yaml());
        let response = egress_page(axum::extract::State(state.clone())).await;
        let body = response_into_string(response).await;
        // The test manifest has no TSA: the log row is sealed.
        assert!(body.contains("sealed"), "{body}");
        // A deployment WITH a TSA shows it as the configured egress.
        let with_tsa = manifest_yaml().replace(
            "services:\n  registry:",
            "services:\n  log:\n    bind: 127.0.0.1:3\n    external_tsa_url: http://tsa.example\n  registry:",
        );
        let state2 = state_with(&with_tsa);
        let response2 = egress_page(axum::extract::State(state2)).await;
        let body2 = response_into_string(response2).await;
        assert!(body2.contains("http://tsa.example"), "{body2}");
        assert!(body2.contains("RFC 3161"));
    }

    #[tokio::test]
    async fn tenant_wizard_creates_validates_and_refuses_duplicates() {
        let state = state_with(&manifest_yaml());
        let session = state.issue_session();
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            format!("unidpp_console={session}").parse().unwrap(),
        );
        let form = TenantForm {
            name: "wizard-test".to_string(),
            organization: "Wizard Org".to_string(),
            product_name: "Wizard DPP".to_string(),
            profile: "whitelabel".to_string(),
            residency: "EU".to_string(),
            primary: "#0f62fe".to_string(),
            accent: "#08bdba".to_string(),
            suites: vec!["ecdsa-p256".to_string(), "sm2".to_string()],
            base_port: 9490,
        };
        let created = tenants_create(
            axum::extract::State(state.clone()),
            headers.clone(),
            Form(form.clone()),
        )
        .await;
        let body = response_into_string(created).await;
        assert!(body.contains("created and validated"), "{body}");
        assert!(body.contains("tenants/up.sh wizard-test"));
        let written =
            std::fs::read_to_string(tenants_dir(&state).join("wizard-test/unidpp-operator.yaml"))
                .unwrap();
        load_manifest(&written).map_err(|e| e.to_string()).unwrap();
        assert!(written.contains("pack_suites: [ecdsa-p256, sm2]"));

        // Duplicate: refused.
        let dup = tenants_create(axum::extract::State(state.clone()), headers, Form(form)).await;
        let body = response_into_string(dup).await;
        assert!(body.contains("already exists"), "{body}");

        // Bad theme hex: the validator's message surfaces.
        let bad = TenantForm {
            name: "wizard-bad".to_string(),
            organization: "o".to_string(),
            product_name: "p".to_string(),
            profile: "whitelabel".to_string(),
            residency: "EU".to_string(),
            primary: "red".to_string(),
            accent: "#08bdba".to_string(),
            suites: vec!["ecdsa-p256".to_string()],
            base_port: 9590,
        };
        let session2 = state.issue_session();
        let mut h2 = HeaderMap::new();
        h2.insert(
            "cookie",
            format!("unidpp_console={session2}").parse().unwrap(),
        );
        let refused = tenants_create(axum::extract::State(state.clone()), h2, Form(bad)).await;
        let body = response_into_string(refused).await;
        assert!(body.contains("#rrggbb"), "{body}");
    }

    #[tokio::test]
    async fn metrics_degrade_to_a_dash_when_services_are_down() {
        let state = state_with(&manifest_yaml());
        let cards = metrics_cards(&state).await;
        assert!(cards.contains("—"), "down services degrade: {cards}");
        assert!(cards.contains("Registry items"));
        assert!(cards.contains("Log tree size"));
    }

    async fn response_into_string(response: Response) -> String {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8_lossy(&body).to_string()
    }

    fn status_of(response: &Response) -> StatusCode {
        response.status()
    }

    fn session_cookie_of(response: &Response) -> Option<String> {
        response
            .headers()
            .get("set-cookie")
            .and_then(|v| v.to_str().ok())
            .and_then(|c| c.split(';').next())
            .map(str::to_string)
    }
}
