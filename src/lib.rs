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
mod i18n;
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

// ---------------------------------------------------------------------------
// SV-7 (the console half): tenant isolation at the manifest boundary.
// A saved manifest may not reference state outside this deployment's
// scope. A console running from `tenants/<me>/` confines its journals
// to that subtree; the root console confines itself to non-tenant
// paths (each tenant has its own console). Absolute paths and
// traversal are refused outright, the resource named.
// ---------------------------------------------------------------------------

/// Every state-path field of a manifest, as (field, value) pairs.
fn state_paths(manifest: &OperatorManifest) -> Vec<(&'static str, String)> {
    fn common(
        out: &mut Vec<(&'static str, String)>,
        name: &'static str,
        service: Option<&unidpp_config::ServiceCommon>,
    ) {
        if let Some(state) = service.and_then(|s| s.state_file.as_deref()) {
            out.push((name, state.to_string()));
        }
    }
    let mut out = Vec::new();
    common(
        &mut out,
        "services.registry.state_file",
        manifest.services.registry.as_ref(),
    );
    common(
        &mut out,
        "services.trust.state_file",
        manifest.services.trust.as_ref(),
    );
    if let Some(state) = manifest
        .services
        .log
        .as_ref()
        .and_then(|s| s.state_file.as_deref())
    {
        out.push(("services.log.state_file", state.to_string()));
    }
    if let Some(state) = manifest
        .services
        .issuer
        .as_ref()
        .and_then(|s| s.state_file.as_deref())
    {
        out.push(("services.issuer.state_file", state.to_string()));
    }
    common(
        &mut out,
        "services.projector.state_file",
        manifest.services.projector.as_ref(),
    );
    common(
        &mut out,
        "services.archive.state_file",
        manifest.services.archive.as_ref(),
    );
    if let Some(state) = manifest
        .services
        .resolver
        .as_ref()
        .and_then(|s| s.state_file.as_deref())
    {
        out.push(("services.resolver.state_file", state.to_string()));
    }
    out
}

/// This console's tenant scope: `Some("tenants/<me>/")` when the
/// manifest lives under a tenants directory, `None` for the root
/// console.
fn tenant_scope(manifest_path: &Path) -> Option<String> {
    let parent = manifest_path.parent()?;
    let name = parent.file_name()?.to_str()?;
    if parent.parent()?.file_name()?.to_str()? == "tenants" {
        Some(format!("tenants/{name}/"))
    } else {
        None
    }
}

/// The SV-7 refusal: every state path stays inside the scope.
fn confine_state_paths(state: &AppState, manifest: &OperatorManifest) -> Result<(), String> {
    let scope = tenant_scope(&state.config.manifest_path);
    for (field, path) in state_paths(manifest) {
        let refusal = |why: &str| {
            Err(format!(
                "cross-tenant refusal: `{field}` = `{path}` {why} — nothing was written"
            ))
        };
        let is_absolute = Path::new(&path).is_absolute();
        let traverses = path.split(['/']).any(|component| component == "..");
        if is_absolute {
            return refusal("is an absolute path outside the deployment tree");
        }
        if traverses {
            return refusal("traverses outside the deployment tree");
        }
        match &scope {
            Some(mine) => {
                if !path.starts_with(mine.as_str()) {
                    return refusal(&format!(
                        "names state outside this tenant's subtree (`{mine}`)"
                    ));
                }
            }
            None => {
                if path.starts_with("tenants/") {
                    return refusal(
                        "names a tenant's state — tenants have their own consoles; \
                         the root console does not touch their journals",
                    );
                }
            }
        }
    }
    Ok(())
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
        confine_state_paths(self, &manifest)?;
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
    let full = state.with_manifest(|m| {
        let locale = m.branding.locale.clone();
        let localized = i18n::t(&locale, &format!("page.{}", title.to_lowercase()));
        let shown = if localized.is_empty() {
            title
        } else {
            localized
        };
        html::page(m, shown, &body, active)
    });
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
            "version": env!("CARGO_PKG_VERSION"),
            "build_id": option_env!("UNIDPP_BUILD_ID").unwrap_or("dev"),
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
    page_for(&state, "Sign in", "", {
        let locale = state.with_manifest(|m| m.branding.locale.clone());
        format!(
            r#"<div class="card" style="max-width:26rem;margin:4rem auto;text-align:center">
<h1>{}</h1>
<form method="post" action="/login">
  <input type="password" name="token" placeholder="{}" style="width:100%" autofocus>
  <button type="submit" style="width:100%;margin-top:.6rem">{}</button>
</form></div>"#,
            i18n::t(&locale, "login.title"),
            i18n::t(&locale, "login.hint"),
            i18n::t(&locale, "login.button"),
        )
    })
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
    // Secure exactly when the console is TLS-fronted — a manifest
    // fact (a declared public_url means an edge terminates TLS), never
    // a guess; loopback-only deployments keep plain cookies so local
    // HTTP keeps working.
    let tls_fronted = state.with_manifest(|m| m.service_public_url("console").is_some());
    let secure = if tls_fronted { "; Secure" } else { "" };
    response.headers_mut().insert(
        "set-cookie",
        format!(
            "unidpp_console={session}; Path=/; HttpOnly; SameSite=Strict{secure}; Max-Age={}",
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
    let page: usize = params
        .get("page")
        .and_then(|p| p.parse().ok())
        .unwrap_or(1)
        .max(1);
    let rows = state.with_manifest(|m| {
        let port = m
            .services
            .registry
            .as_ref()
            .and_then(|s| http::port_of(&s.bind))?;
        let mut path = format!("/items?limit=50&offset={}", (page - 1) * 50);
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
        let pages = count.div_ceil(50) as usize;
        let mut pager = String::new();
        if page > 1 || pages > 1 {
            let qs = |p: usize| {
                let mut q = format!("?page={p}");
                if !class.is_empty() {
                    q.push_str(&format!("&class={class}"));
                }
                if !register.is_empty() {
                    q.push_str(&format!("&register={register}"));
                }
                q
            };
            let prev = if page > 1 {
                format!(r#"<a href="/registry{}">&larr; newer</a>"#, qs(page - 1))
            } else {
                String::new()
            };
            let next = if page < pages {
                format!(r#"<a href="/registry{}">older &rarr;</a>"#, qs(page + 1))
            } else {
                String::new()
            };
            pager = format!(
                r#"<tr><td colspan="3">page {page} of {pages} · {prev} {next}</td></tr>"#
            );
        }
        Some(format!(
            r#"<p>{} item(s)</p><table><tr><th>Identifier</th><th>Class</th><th>Register</th></tr>{}</table>"#,
            count,
            [rows.join(""), pager].concat()
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

/// The branding editor form (pre-filled from the live manifest).
/// Writes through the ONE validated save path — the same
/// save_manifest the text editor uses.
fn branding_form(b: &unidpp_config::Branding) -> String {
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
struct BrandingForm {
    organization: String,
    product_name: String,
    logo: String,
    primary: String,
    accent: String,
    legal_url: String,
    contact_url: String,
}

/// POST /branding — apply the form to the manifest's branding block
/// through the validated save path; nothing else in the manifest is
/// touched (the model is loaded, mutated, re-serialized).
async fn branding_save(
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

fn non_empty(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

async fn branding_preview(State(state): State<Arc<AppState>>) -> Response {
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

#[derive(Deserialize, Default, Clone, serde::Serialize)]
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
// Trust (#140): what a verifier pins, what stands — facts from the
// trust service's own APIs, never a second brain.
// ---------------------------------------------------------------------------
async fn trust_page(State(state): State<Arc<AppState>>) -> Response {
    let body = match trust_render(&state).await {
        Ok(body) => body,
        Err(error) => format!(r#"<div class="error">{}</div>"#, esc(&error)),
    };
    page_for(&state, "Trust", "trust", body)
}

async fn trust_render(state: &Arc<AppState>) -> Result<String, String> {
    let port = state
        .with_manifest(|m| {
            m.services
                .trust
                .as_ref()
                .and_then(|s| http::port_of(&s.bind))
        })
        .ok_or("this deployment declares no trust service")?;

    let mut probes = http::get_all(&[(Some(port), "/keyring"), (Some(port), "/revocations")]).await;
    let keyring = probes[0]
        .take()
        .and_then(|r| r.json())
        .ok_or("the trust service is unreachable")?;
    let revocations = probes[1].take().and_then(|r| r.json());

    let mode = keyring.get("mode").and_then(|m| m.as_str()).unwrap_or("—");
    let mut roles = Vec::new();
    if let Some(map) = keyring.get("roles").and_then(|r| r.as_object()) {
        for (role, entry) in map {
            roles.push(format!(
                r#"<tr><td><code>{}</code></td><td>{}</td><td><code>{}</code></td><td style="word-break:break-all"><code>{}</code></td></tr>"#,
                esc(role),
                esc(entry.get("suite").and_then(|v| v.as_str()).unwrap_or("—")),
                esc(entry.get("key_id").and_then(|v| v.as_str()).unwrap_or("—")),
                esc(entry
                    .get("public_serialized")
                    .and_then(|v| v.as_str())
                    .unwrap_or("—")),
            ));
        }
    }
    roles.sort();

    let mut rows = Vec::new();
    if let Some(doc) = &revocations {
        for r in doc
            .get("revocations")
            .and_then(|v| v.as_array())
            .unwrap_or(&vec![])
        {
            let subject = r
                .get("subject")
                .and_then(|s| s.get("label"))
                .and_then(|v| v.as_str())
                .unwrap_or("—");
            let reason = r
                .get("reason")
                .and_then(|s| s.get("token"))
                .and_then(|v| v.as_str())
                .unwrap_or("—");
            let retro = r
                .get("reason")
                .and_then(|s| s.get("retroactive"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let window = r
                .get("window")
                .map(|w| {
                    let start = w.get("start").and_then(|v| v.as_str()).unwrap_or("—");
                    let end = w.get("end").and_then(|v| v.as_str()).unwrap_or("open");
                    format!("{start} .. {end}")
                })
                .unwrap_or_else(|| "—".to_string());
            let standing = r
                .get("standing_at_as_of")
                .and_then(|v| v.as_str())
                .unwrap_or("—");
            let quorum = r
                .get("quorum")
                .map(|q| match q.get("quorate").and_then(|v| v.as_bool()) {
                    Some(true) => format!(
                        "quorate ({} × {}, form {})",
                        q.get("threshold").and_then(|v| v.as_u64()).unwrap_or(0),
                        q.get("quorum").and_then(|v| v.as_str()).unwrap_or("—"),
                        q.get("form").and_then(|v| v.as_str()).unwrap_or("—"),
                    ),
                    _ => "not quorate".to_string(),
                })
                .unwrap_or_else(|| "—".to_string());
            let badge = match standing {
                "valid" => "ok",
                "void-ab-initio" | "suspended-from" => "bad",
                _ => "warn",
            };
            rows.push(format!(
                r#"<tr><td><code>{}</code></td><td>{}{}</td><td><code>{}</code></td><td><span class="badge {}">{}</span></td><td>{}</td></tr>"#,
                esc(subject),
                esc(reason),
                if retro { " · retroactive" } else { "" },
                esc(&window),
                badge,
                esc(standing),
                esc(&quorum),
            ));
        }
    }
    let revocations_html = if rows.is_empty() {
        r#"<p>No revocations in force.</p>"#.to_string()
    } else {
        format!(
            r#"<h2>Revocations in force</h2>
<table><tr><th>Subject</th><th>Reason</th><th>Window</th><th>Standing</th><th>Quorum</th></tr>{}</table>
<p class="note">Standing is read as of now; retroactive windows void
their span ab initio — query the trust API with <code>?at=</code> for
any other moment.</p>"#,
            rows.join("")
        )
    };

    Ok(format!(
        r#"<h1>{title}</h1>
<p class="note">The anchors a verifier pins and the revocations in
force — read live from the trust service ({mode} mode). The
serialized anchors are the exact <code>suite:hex</code> forms
<code>unidpp verify --anchor</code> parses.</p>
<h2>Keyring</h2>
<table><tr><th>Role</th><th>Suite</th><th>Key id</th><th>Anchor</th></tr>{roles}</table>
{revocations_html}"#,
        title = "Trust",
        roles = roles.join(""),
    ))
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

/// POST /backups/drill — run the restore rehearsal through the
/// operator script (session-gated; the script owns the logic).
async fn backups_drill(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
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
            r#"<div class="note">Drill GREEN — the restore path is proven.</div><pre>{}</pre>
<a href="/backups">← backups</a>"#,
            esc(&String::from_utf8_lossy(&output.stdout))
        ),
        Ok(output) => format!(
            r#"<div class="error">The drill failed — do not touch production
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
// ---------------------------------------------------------------------------

async fn declarations_page(
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

async fn declarations_render(
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

async fn coverage_page(
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

async fn coverage_render(
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

async fn carrier_page(
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

async fn carrier_render(state: &Arc<AppState>, passport: &str) -> Result<String, String> {
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
struct ProfileIntakeForm {
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

async fn profiles_page(State(state): State<Arc<AppState>>) -> Response {
    let body = match profiles_render(&state).await {
        Ok(body) => body,
        Err(error) => format!(r#"<div class="error">{}</div>"#, esc(&error)),
    };
    page_for(&state, "Profiles", "profiles", body)
}

async fn profiles_render(state: &Arc<AppState>) -> Result<String, String> {
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

async fn profiles_intake(
    State(state): State<Arc<AppState>>,
    Form(f): Form<ProfileIntakeForm>,
) -> Response {
    let body = match profiles_submit(&state, f).await {
        Ok(body) => body,
        Err(error) => format!(r#"<div class="error">{}</div>"#, esc(&error)),
    };
    page_for(&state, "Profiles", "profiles", body)
}

async fn profiles_submit(state: &Arc<AppState>, f: ProfileIntakeForm) -> Result<String, String> {
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
struct SnapshotIntakeForm {
    passport_id: String,
    state_hash: String,
    log_head: String,
    submitter: Option<String>,
    token: String,
}

async fn archival_page(State(state): State<Arc<AppState>>) -> Response {
    let body = match archival_render(&state).await {
        Ok(body) => body,
        Err(error) => format!(r#"<div class="error">{}</div>"#, esc(&error)),
    };
    page_for(&state, "Archival", "archival", body)
}

async fn archival_render(state: &Arc<AppState>) -> Result<String, String> {
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

async fn archival_intake(
    State(state): State<Arc<AppState>>,
    Form(f): Form<SnapshotIntakeForm>,
) -> Response {
    let body = match archival_submit(&state, f).await {
        Ok(body) => body,
        Err(error) => format!(r#"<div class="error">{}</div>"#, esc(&error)),
    };
    page_for(&state, "Archival", "archival", body)
}

async fn archival_submit(state: &Arc<AppState>, f: SnapshotIntakeForm) -> Result<String, String> {
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
        .route("/branding", get(branding_preview).post(branding_save))
        .route("/trust", get(trust_page))
        .route("/declarations", get(declarations_page))
        .route("/carrier", get(carrier_page))
        .route("/profiles", get(profiles_page).post(profiles_intake))
        .route("/archival", get(archival_page).post(archival_intake))
        .route("/coverage", get(coverage_page))
        .route("/egress", get(egress_page))
        .route("/tenants", get(tenants_page).post(tenants_create))
        .route("/backups", get(backups_page).post(backups_run))
        .route("/backups/drill", post(backups_drill))
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
            axum::extract::RawForm(serde_html_form::to_string(&form).unwrap().into()),
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
        let dup = tenants_create(
            axum::extract::State(state.clone()),
            headers,
            axum::extract::RawForm(serde_html_form::to_string(&form).unwrap().into()),
        )
        .await;
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
        let refused = tenants_create(
            axum::extract::State(state.clone()),
            h2,
            axum::extract::RawForm(serde_html_form::to_string(&bad).unwrap().into()),
        )
        .await;
        let body = response_into_string(refused).await;
        assert!(body.contains("#rrggbb"), "{body}");
    }

    #[tokio::test]
    async fn metrics_degrade_to_a_dash_when_services_are_down() {
        let state = state_with(&manifest_yaml());
        let cards = metrics_cards(&state).await;
        assert!(cards.contains("—"), "down services degrade: {cards}");
        assert!(cards.contains("Registry items"));
        assert!(cards.contains("Passports"));
        assert!(cards.contains("Log tree size"));
    }

    fn branding_form_of(organization: &str, primary: &str) -> BrandingForm {
        BrandingForm {
            organization: organization.to_string(),
            product_name: "Example DPP".to_string(),
            logo: String::new(),
            primary: primary.to_string(),
            accent: "#0e8345".to_string(),
            legal_url: String::new(),
            contact_url: String::new(),
        }
    }

    // -- The HTTP contract: the real router, driven end to end ----

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::util::ServiceExt;

    async fn body_of(response: axum::response::Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        String::from_utf8_lossy(&bytes).to_string()
    }

    fn request(method: &str, uri: &str, cookie: Option<&str>, form: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(cookie) = cookie {
            builder = builder.header("cookie", cookie);
        }
        if form.is_some() {
            builder = builder.header("content-type", "application/x-www-form-urlencoded");
        }
        builder
            .body(Body::from(form.unwrap_or("").to_string()))
            .expect("request")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_http_contract_login_gates_and_logout_revoke() {
        let state = state_with(&manifest_yaml());
        let app = router(state.clone());

        // Public pages render without a session — the two FW-5
        // journey surfaces included.
        for uri in [
            "/",
            "/trust",
            "/branding",
            "/registry",
            "/passports",
            "/declarations",
            "/carrier",
            "/profiles",
            "/archival",
            "/coverage",
        ] {
            let resp = app
                .clone()
                .oneshot(request("GET", uri, None, None))
                .await
                .expect("route");
            assert_eq!(resp.status(), StatusCode::OK, "{uri}");
        }

        // The FW-5 write surfaces degrade honestly when their service
        // is absent or unreachable — the refusal is stated, never blank.
        let resp = app
            .clone()
            .oneshot(request("GET", "/carrier", None, None))
            .await
            .expect("route");
        let body = body_of(resp).await;
        assert!(body.contains("declares no issuer service"), "{body}");
        let resp = app
            .clone()
            .oneshot(request("GET", "/archival", None, None))
            .await
            .expect("route");
        let body = body_of(resp).await;
        assert!(body.contains("declares no archive service"), "{body}");
        let resp = app
            .clone()
            .oneshot(request("GET", "/profiles", None, None))
            .await
            .expect("route");
        let body = body_of(resp).await;
        assert!(body.contains("unreachable"), "{body}");

        // Anonymous mutation: refused (the config save renders the
        // gated page, not a write).
        let resp = app
            .clone()
            .oneshot(request(
                "POST",
                "/config",
                None,
                Some("manifest=api_version%3A+unidpp.org%2Fv1"),
            ))
            .await
            .expect("route");
        let body = body_of(resp).await;
        assert!(body.contains("signed-in session"), "{body}");

        // Login: wrong token renders the refusal; the right token
        // redirects and sets the cookie.
        let wrong = app
            .clone()
            .oneshot(request("POST", "/login", None, Some("token=nope")))
            .await
            .expect("route");
        assert_eq!(wrong.status(), StatusCode::OK);
        assert!(wrong.headers().get("set-cookie").is_none());

        let right = app
            .clone()
            .oneshot(request("POST", "/login", None, Some("token=test-token")))
            .await
            .expect("route");
        assert_eq!(right.status(), StatusCode::SEE_OTHER);
        let cookie = right
            .headers()
            .get("set-cookie")
            .and_then(|v| v.to_str().ok())
            .and_then(|c| c.split(';').next())
            .expect("the session cookie")
            .to_string();
        assert!(cookie.starts_with("unidpp_console="), "{cookie}");

        // The session unlocks the gated mutation path (the branding
        // save reaches the handler and is validated by the model).
        let saved = app
            .clone()
            .oneshot(request(
                "POST",
                "/branding",
                Some(&cookie),
                Some("organization=Router+Test&product_name=P&logo=&primary=%231d4ed8&accent=%230e8345&legal_url=&contact_url="),
            ))
            .await
            .expect("route");
        let saved_body = body_of(saved).await;
        assert!(saved_body.contains("saved and validated"), "{saved_body}");
        assert_eq!(
            state.with_manifest(|m| m.branding.organization.clone()),
            "Router Test"
        );

        // Logout revokes server-side: the old cookie stops working.
        let out = app
            .clone()
            .oneshot(request("POST", "/logout", Some(&cookie), None))
            .await
            .expect("route");
        assert_eq!(out.status(), StatusCode::SEE_OTHER);
        let after = app
            .oneshot(request(
                "POST",
                "/config",
                Some(&cookie),
                Some("manifest=api_version%3A+unidpp.org%2Fv1"),
            ))
            .await
            .expect("route");
        let after_body = body_of(after).await;
        assert!(
            after_body.contains("signed-in session"),
            "the revoked cookie must not authenticate: {after_body}"
        );
    }

    #[tokio::test]
    async fn trust_page_degrades_honestly_without_a_trust_service() {
        let state = state_with(&manifest_yaml()); // no trust block
        let body = trust_render(&state).await.unwrap_err();
        assert!(body.contains("declares no trust service"), "{body}");
    }

    #[tokio::test]
    async fn zh_cn_manifest_renders_a_chinese_chrome() {
        let zh = manifest_yaml().replace("branding:\n", "branding:\n  locale: zh-CN\n");
        let state = state_with(&zh);
        let response = dashboard(axum::extract::State(state)).await;
        let body = response_into_string(response).await;
        assert!(body.contains("仪表盘"), "the nav renders Chinese: {body}");
        assert!(body.contains("注册表条目"), "the cards render Chinese");
        assert!(
            body.contains("仅回环") || body.contains("健康"),
            "the matrix badges"
        );
        // The en fallback: an en manifest keeps today's byte-stable chrome.
        let en = state_with(&manifest_yaml());
        let en_body = response_into_string(dashboard(axum::extract::State(en)).await).await;
        assert!(en_body.contains("Dashboard") && en_body.contains("Registry items"));

        // The login page speaks the locale too.
        let zh_state = state_with(&zh);
        let login = login_page(axum::extract::State(zh_state)).await;
        let login_body = response_into_string(login).await;
        assert!(login_body.contains("登录"), "{login_body}");
        assert!(login_body.contains("管理员令牌"), "{login_body}");
    }

    #[tokio::test]
    async fn branding_editor_changes_only_branding_and_validates() {
        let state = state_with(&manifest_yaml());

        // Anonymous: refused, nothing written.
        let denied = branding_save(
            axum::extract::State(state.clone()),
            HeaderMap::new(),
            Form(branding_form_of("Evil Corp", "#000000")),
        )
        .await;
        let denied_body = response_into_string(denied).await;
        assert!(denied_body.contains("signed-in session"), "{denied_body}");
        assert!(
            state
                .with_manifest(|m| m.branding.organization.clone())
                .contains("script"),
            "the manifest was not touched"
        );

        // Signed in, valid: branding changes, services untouched.
        let session = state.issue_session();
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            format!("unidpp_console={session}").parse().unwrap(),
        );
        let saved = branding_save(
            axum::extract::State(state.clone()),
            headers.clone(),
            Form(branding_form_of("Renamed Corp", "#1d4ed8")),
        )
        .await;
        let saved_body = response_into_string(saved).await;
        assert!(saved_body.contains("saved and validated"), "{saved_body}");
        assert_eq!(
            state.with_manifest(|m| m.branding.organization.clone()),
            "Renamed Corp"
        );
        assert_eq!(
            state.with_manifest(|m| m.branding.theme.primary.clone()),
            "#1d4ed8"
        );
        assert_eq!(
            state.with_manifest(|m| m.services.registry.as_ref().unwrap().bind.clone()),
            "127.0.0.1:1",
            "services untouched by a branding save"
        );

        // Invalid hex: rejected, nothing written.
        let refused = branding_save(
            axum::extract::State(state.clone()),
            headers,
            Form(branding_form_of("Renamed Corp", "not-a-color")),
        )
        .await;
        let refused_body = response_into_string(refused).await;
        assert!(refused_body.contains("Rejected"), "{refused_body}");
        assert_eq!(
            state.with_manifest(|m| m.branding.theme.primary.clone()),
            "#1d4ed8",
            "the invalid color did not land"
        );
    }

    #[tokio::test]
    async fn unreachable_services_cost_one_timeout_not_their_sum() {
        // A listener that accepts and holds every connection open:
        // each probe then pays the FULL read timeout. Four such
        // services cost serially >= 4x the timeout; concurrently ~one.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the holding listener");
        let hold_port = listener.local_addr().unwrap().port();
        let holder = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((sock, _)) = listener.accept().await {
                held.push(sock); // held open: never a response
            }
            held
        });
        let black_hole = format!("127.0.0.1:{hold_port}");
        let manifest = manifest_yaml().replace(
            "services:\n  registry:\n    bind: 127.0.0.1:1",
            format!(
                "services:\n  registry:\n    bind: {black_hole}\n  trust:\n    bind: {black_hole}\n  log:\n    bind: {black_hole}\n  issuer:\n    bind: {black_hole}"
            )
            .as_str(),
        );
        let state = state_with(&manifest);
        let started = std::time::Instant::now();
        let response = dashboard(axum::extract::State(state)).await;
        let body = response_into_string(response).await;
        let elapsed = started.elapsed();
        assert_eq!(body.matches("unreachable").count(), 4, "all four down");
        assert!(
            elapsed < std::time::Duration::from_secs(6),
            "probes must fan out concurrently (two fan-out rounds ~= 4s; \
             serial would be >= 16s), took {elapsed:?}"
        );
        holder.abort();
    }

    #[tokio::test]
    async fn session_cookie_is_secure_exactly_when_tls_fronted() {
        let login = |state: Arc<AppState>| async move {
            login_submit(
                axum::extract::State(state),
                Form(LoginForm {
                    token: "test-token".to_string(),
                }),
            )
            .await
        };
        // Loopback-only console: plain cookie (local HTTP keeps working).
        let plain = login(state_with(&manifest_yaml())).await;
        let cookie = plain
            .headers()
            .get("set-cookie")
            .and_then(|v| v.to_str().ok())
            .expect("a session cookie");
        assert!(
            cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"),
            "{cookie}"
        );
        assert!(
            !cookie.contains("Secure"),
            "loopback must not set Secure: {cookie}"
        );

        // TLS-fronted console (a declared public_url is the manifest
        // fact that an edge terminates TLS): Secure present.
        let with_public = manifest_yaml().replace(
            "services:\n  registry:",
            "services:\n  console:\n    bind: 127.0.0.1:9\n    public_url: https://console.unidpp.org\n  registry:",
        );
        let secure_login = login(state_with(&with_public)).await;
        let secure_cookie = secure_login
            .headers()
            .get("set-cookie")
            .and_then(|v| v.to_str().ok())
            .expect("a session cookie");
        assert!(secure_cookie.contains("Secure"), "{secure_cookie}");
    }

    #[tokio::test]
    async fn services_matrix_renders_declared_public_urls() {
        // No public_url: the registry row reads loopback-only.
        let state = state_with(&manifest_yaml());
        let response = dashboard(axum::extract::State(state.clone())).await;
        let body = response_into_string(response).await;
        assert!(body.contains("<th>Public</th>"), "{body}");
        assert!(body.contains("loopback"), "{body}");

        // A declared public URL renders as the link (and only as the
        // manifest says — the console invents nothing).
        let with_public = manifest_yaml().replace(
            "  registry:
    bind: 127.0.0.1:1",
            "  registry:
    bind: 127.0.0.1:1
    public_url: https://registry.unidpp.org",
        );
        let state2 = state_with(&with_public);
        let response2 = dashboard(axum::extract::State(state2)).await;
        let body2 = response_into_string(response2).await;
        assert!(
            body2.contains(r#"<a href="https://registry.unidpp.org">"#),
            "{body2}"
        );
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
