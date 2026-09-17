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
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use tokio::net::TcpListener;
use unidpp_config::{load as load_manifest, OperatorManifest};

mod html;
mod http;
mod i18n;
mod isolation;
mod journeys;
mod pages;
mod verify;

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
        isolation::confine_state_paths(self, &manifest)?;
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
        // The lookup key derives from the page's stable identifier
        // (its active key), never from a display string — a title
        // rename must never change what is looked up.
        let localized = i18n::t(&locale, &format!("page.{active}"));
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
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/.well-known/unidpp-service", get(service_identity))
        .route("/", get(pages::dashboard::dashboard))
        .route(
            "/login",
            get(pages::session::login_page).post(pages::session::login_submit),
        )
        .route("/logout", post(pages::session::logout))
        .route(
            "/config",
            get(pages::config::config_page).post(pages::config::config_save),
        )
        .route("/config/env", get(pages::config::config_env))
        .route("/registry", get(pages::registry::registry_browser))
        .route(
            "/passports",
            get(pages::passports::passports_page).post(verify::submit),
        )
        .route(
            "/branding",
            get(pages::branding::branding_preview).post(pages::branding::branding_save),
        )
        .route("/trust", get(pages::trust::trust_page))
        .route("/feedback", get(pages::feedback::feedback_page))
        .route("/declarations", get(journeys::declarations_page))
        .route("/carrier", get(journeys::carrier_page))
        .route(
            "/profiles",
            get(journeys::profiles_page).post(journeys::profiles_intake),
        )
        .route(
            "/archival",
            get(journeys::archival_page).post(journeys::archival_intake),
        )
        .route("/coverage", get(journeys::coverage_page))
        .route("/egress", get(pages::egress::egress_page))
        .route(
            "/tenants",
            get(pages::tenants::tenants_page).post(pages::tenants::tenants_create),
        )
        .route(
            "/backups",
            get(pages::backups::backups_page).post(pages::backups::backups_run),
        )
        .route("/backups/drill", post(pages::backups::backups_drill))
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
    use axum::extract::Form;

    /// The localized title derives from the page's IDENTIFIER, not
    /// its display string — a zh-CN manifest renders 配置 for /config
    /// (the bug: the key once derived from the English title, so a
    /// table rename silently dropped the localization to fallback).
    #[tokio::test]
    async fn the_localized_title_follows_the_active_key() {
        let yaml = manifest_yaml().replace(
            "  product_name: Example DPP",
            "  product_name: Example DPP\n  locale: zh-CN",
        );
        let state = state_with(&yaml);
        let response = pages::config::config_page(axum::extract::State(state.clone())).await;
        let body = body_of(response).await;
        assert!(
            body.contains("<title>配置"),
            "the zh-CN config title must render through page.<active>: first 200 chars: {}",
            &body[..body.len().min(200)]
        );
    }

    /// i18n integrity: every statically reachable lookup key
    /// resolves in the table, and every table key is reachable — a
    /// missed key renders blank on a page (the bug this test was
    /// born from: page.config and page.declarations were absent);
    /// a dead key is drift.
    #[test]
    fn every_i18n_key_resolves_and_none_is_dead() {
        let table: std::collections::BTreeSet<&'static str> =
            i18n::STRINGS.iter().map(|(k, _, _)| *k).collect();
        let sources = [
            include_str!("html.rs").to_string(),
            include_str!("verify.rs").to_string(),
            include_str!("journeys.rs").to_string(),
            std::fs::read_to_string("src/pages/dashboard.rs").unwrap(),
            std::fs::read_to_string("src/pages/session.rs").unwrap(),
            std::fs::read_to_string("src/pages/config.rs").unwrap(),
            std::fs::read_to_string("src/pages/registry.rs").unwrap(),
            std::fs::read_to_string("src/pages/passports.rs").unwrap(),
            std::fs::read_to_string("src/pages/branding.rs").unwrap(),
            std::fs::read_to_string("src/pages/tenants.rs").unwrap(),
            std::fs::read_to_string("src/pages/trust.rs").unwrap(),
            std::fs::read_to_string("src/pages/feedback.rs").unwrap(),
            std::fs::read_to_string("src/pages/backups.rs").unwrap(),
            std::fs::read_to_string("src/pages/egress.rs").unwrap(),
        ]
        .concat();

        // Reachability, two tiers:
        // 1. every string literal in the sources that matches a
        //    table key (call sites, loops, matches — any reference);
        // 2. the constructed families (nav.<item>, page.<active>)
        //    must exist — a constructed miss renders blank.
        let mut reachable: std::collections::BTreeSet<String> = Default::default();
        for key in &table {
            let needle = format!("\"{key}\"");
            if sources.contains(&needle) {
                reachable.insert((*key).to_string());
            }
        }
        for key in html::nav_keys() {
            reachable.insert(format!("nav.{key}"));
        }
        // The page actives derive from the page_for call sites
        // (every `page_for(&state, "…", "active"` — the second
        // string literal, the page's stable identifier), never from
        // a hand list: a new page joins the check by existing.
        for call in sources.split("page_for(").skip(1) {
            let mut rest = call;
            let mut active = None;
            for _ in 0..2 {
                let Some(q1) = rest.find('"') else { break };
                let after = &rest[q1 + 1..];
                let Some(q2) = after.find('"') else { break };
                active = Some(rest[q1 + 1..q1 + 1 + q2].to_string());
                rest = &rest[q1 + 1 + q2 + 1..];
            }
            if let Some(active) = active {
                if !active.is_empty() && active.chars().all(|c| c.is_ascii_lowercase() || c == '-')
                {
                    reachable.insert(format!("page.{active}"));
                }
            }
        }

        // The constructed families must resolve in the table — the
        // blank-render bug class.
        let unresolved: Vec<String> = reachable
            .iter()
            .filter(|k| k.starts_with("nav.") || k.starts_with("page."))
            .filter(|k| !table.contains(k.as_str()))
            .cloned()
            .collect();
        assert!(
            unresolved.is_empty(),
            "constructed lookup keys missing from the table (they render blank): {unresolved:?}"
        );
        // And nothing in the table is unreferenced — drift.
        let dead: Vec<&str> = table
            .iter()
            .filter(|k| {
                let owned = k.to_string();
                !reachable.contains(&owned)
            })
            .copied()
            .collect();
        assert!(
            dead.is_empty(),
            "table keys nothing looks up (drift): {dead:?}"
        );
    }

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
        let response = pages::dashboard::dashboard(axum::extract::State(state.clone())).await;
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
        let wrong = pages::session::login_submit(
            axum::extract::State(state.clone()),
            Form(pages::session::LoginForm {
                token: "nope".to_string(),
            }),
        )
        .await;
        assert_eq!(status_of(&wrong), StatusCode::OK); // the refusal page
        assert!(session_cookie_of(&wrong).is_none());

        let right = pages::session::login_submit(
            axum::extract::State(state.clone()),
            Form(pages::session::LoginForm {
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
        let denied = pages::config::config_save(
            axum::extract::State(state.clone()),
            HeaderMap::new(),
            Form(pages::config::ConfigForm {
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
        let rejected = pages::config::config_save(
            axum::extract::State(state.clone()),
            headers.clone(),
            Form(pages::config::ConfigForm { manifest: broken }),
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
        let saved = pages::config::config_save(
            axum::extract::State(state.clone()),
            headers,
            Form(pages::config::ConfigForm { manifest: valid }),
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
        let response = pages::config::config_page(axum::extract::State(state.clone())).await;
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
        let response = pages::egress::egress_page(axum::extract::State(state.clone())).await;
        let body = response_into_string(response).await;
        // The test manifest has no TSA: the log row is sealed.
        assert!(body.contains("sealed"), "{body}");
        // A deployment WITH a TSA shows it as the configured egress.
        let with_tsa = manifest_yaml().replace(
            "services:\n  registry:",
            "services:\n  log:\n    bind: 127.0.0.1:3\n    external_tsa_url: http://tsa.example\n  registry:",
        );
        let state2 = state_with(&with_tsa);
        let response2 = pages::egress::egress_page(axum::extract::State(state2)).await;
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
        let form = pages::tenants::TenantForm {
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
        let created = pages::tenants::tenants_create(
            axum::extract::State(state.clone()),
            headers.clone(),
            axum::extract::RawForm(serde_html_form::to_string(&form).unwrap().into()),
        )
        .await;
        let body = response_into_string(created).await;
        assert!(body.contains("created and validated"), "{body}");
        assert!(body.contains("tenants/up.sh wizard-test"));
        let written = std::fs::read_to_string(
            pages::tenants::tenants_dir(&state).join("wizard-test/unidpp-operator.yaml"),
        )
        .unwrap();
        load_manifest(&written).map_err(|e| e.to_string()).unwrap();
        assert!(written.contains("pack_suites: [ecdsa-p256, sm2]"));

        // Duplicate: refused.
        let dup = pages::tenants::tenants_create(
            axum::extract::State(state.clone()),
            headers,
            axum::extract::RawForm(serde_html_form::to_string(&form).unwrap().into()),
        )
        .await;
        let body = response_into_string(dup).await;
        assert!(body.contains("already exists"), "{body}");

        // Bad theme hex: the validator's message surfaces.
        let bad = pages::tenants::TenantForm {
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
        let refused = pages::tenants::tenants_create(
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
        let cards = pages::dashboard::metrics_cards(&state).await;
        assert!(cards.contains("—"), "down services degrade: {cards}");
        assert!(cards.contains("Registry items"));
        assert!(cards.contains("Passports"));
        assert!(cards.contains("Log tree size"));
    }

    fn branding_form_of(organization: &str, primary: &str) -> pages::branding::BrandingForm {
        pages::branding::BrandingForm {
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
        let body = pages::trust::trust_render(&state).await.unwrap_err();
        assert!(body.contains("declares no trust service"), "{body}");
    }

    #[tokio::test]
    async fn zh_cn_manifest_renders_a_chinese_chrome() {
        let zh = manifest_yaml().replace("branding:\n", "branding:\n  locale: zh-CN\n");
        let state = state_with(&zh);
        let response = pages::dashboard::dashboard(axum::extract::State(state)).await;
        let body = response_into_string(response).await;
        assert!(body.contains("仪表盘"), "the nav renders Chinese: {body}");
        assert!(body.contains("注册表条目"), "the cards render Chinese");
        assert!(
            body.contains("仅回环") || body.contains("健康"),
            "the matrix badges"
        );
        // The en fallback: an en manifest keeps today's byte-stable chrome.
        let en = state_with(&manifest_yaml());
        let en_body =
            response_into_string(pages::dashboard::dashboard(axum::extract::State(en)).await).await;
        assert!(en_body.contains("Dashboard") && en_body.contains("Registry items"));

        // The login page speaks the locale too.
        let zh_state = state_with(&zh);
        let login = pages::session::login_page(axum::extract::State(zh_state)).await;
        let login_body = response_into_string(login).await;
        assert!(login_body.contains("登录"), "{login_body}");
        assert!(login_body.contains("管理员令牌"), "{login_body}");
    }

    #[tokio::test]
    async fn branding_editor_changes_only_branding_and_validates() {
        let state = state_with(&manifest_yaml());

        // Anonymous: refused, nothing written.
        let denied = pages::branding::branding_save(
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
        let saved = pages::branding::branding_save(
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
        let refused = pages::branding::branding_save(
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
        let response = pages::dashboard::dashboard(axum::extract::State(state)).await;
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
            pages::session::login_submit(
                axum::extract::State(state),
                Form(pages::session::LoginForm {
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
        let response = pages::dashboard::dashboard(axum::extract::State(state.clone())).await;
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
        let response2 = pages::dashboard::dashboard(axum::extract::State(state2)).await;
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
