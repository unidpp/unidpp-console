//! SV-7: the tenant isolation suite (console route level).
//!
//! The rule under test: no cross-tenant read or write path exists —
//! journals, keys, secrets and surfaces isolated per tenant, and
//! tenant A's credentials refused against tenant B's resources.
//!
//! The suite drives the console black-box, through its HTTP surface
//! only: the credential is the session (issued by the login gate),
//! and the cross-tenant resource references are the state paths a
//! session holder can put in a saved manifest. Every refusal must
//! NAME the resource — the field and the path — and the live
//! manifest must be untouched after a refusal (the write is
//! refused, not partially applied).
//!
//! The model under test: whitelabeling is separate deployments.
//! Tenant `acme` is a console whose manifest lives under
//! `tenants/acme/`; the root console is one whose manifest does not.
//! The boundary the console enforces (SV-7's console half):
//! - a tenant console's saved state paths stay inside
//!   `tenants/<me>/`;
//! - the root console's saved state paths never enter `tenants/`
//!   (each tenant has its own console);
//! - absolute paths and traversal are refused for everyone;
//! - no mutation happens at all without the session credential.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::util::ServiceExt;
use unidpp_console::{router, AppState, Config};

fn state_under(root: &std::path::Path, rel_manifest: &str, yaml: &str) -> Arc<AppState> {
    let dir = root.join(rel_manifest).parent().unwrap().to_path_buf();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(root.join(rel_manifest), yaml).unwrap();
    Arc::new(
        AppState::new(Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            manifest_path: root.join(rel_manifest),
            admin_token: Some("tenant-admin-token".to_string()),
        })
        .unwrap(),
    )
}

fn tenant_yaml(me: &str) -> String {
    format!(
        r#"api_version: unidpp.org/v1
deployment:
  name: {me}
  profile: whitelabel
  base_url: https://dpp.{me}.example.org
branding:
  organization: {me} Corp
  product_name: {me} DPP
services:
  issuer:
    bind: 127.0.0.1:9396
    state_file: tenants/{me}/issuer-journal.jsonl
"#
    )
}

fn root_yaml() -> &'static str {
    r#"api_version: unidpp.org/v1
deployment:
  name: root
  profile: reference
  base_url: https://dpp.example.org
branding:
  organization: Root Corp
  product_name: UniDPP
services:
  registry:
    bind: 127.0.0.1:9398
    state_file: registry-journal.jsonl
"#
}

async fn body_of(response: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
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

fn urlencode_yaml(yaml: &str) -> String {
    yaml.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            b' ' => "+".to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// The session credential: issued by the login gate only for the
/// right token — the wrong credential never becomes a session.
async fn session_of(app: &axum::Router, token: &str) -> Option<String> {
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/login",
            None,
            Some(&format!("token={token}")),
        ))
        .await
        .expect("route");
    response
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .map(str::to_string)
}

// -------------------------------------------------------------------------
// The credential gate: tenant A's session is the credential; without
// it, no mutating surface writes anything.
// -------------------------------------------------------------------------

#[tokio::test]
async fn mutations_require_the_session_credential() {
    let root = std::env::temp_dir().join(format!("unidpp-sv7-gate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let state = state_under(&root, "unidpp-operator.yaml", root_yaml());
    let app = router(state.clone());

    for (method, uri, form) in [
        ("POST", "/config", Some("manifest=api_version%3A+unidpp.org%2Fv1")),
        ("POST", "/tenants", Some("name=globex&organization=G&product_name=G&profile=whitelabel&residency=eu&primary=%23000&accent=%23fff&base_port=9400&suites=ecdsa-p256&suites=ecdsa-p256")),
        ("POST", "/branding", Some("organization=X&product_name=Y&logo=&primary=%23000&accent=%23fff&legal_url=&contact_url=")),
    ] {
        let response = app
            .clone()
            .oneshot(request(method, uri, None, form))
            .await
            .expect("route");
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        let body = body_of(response).await;
        assert!(
            body.contains("requires a signed-in session") || body.contains("Sign in"),
            "{uri}: anonymous mutation must render the credential gate, got: {}",
            &body[..body.len().min(200)]
        );
    }
    // The live manifest is untouched by the anonymous attempts.
    let text = std::fs::read_to_string(root.join("unidpp-operator.yaml")).unwrap();
    assert!(text.contains("registry-journal.jsonl"));
    let _ = std::fs::remove_dir_all(&root);
}

// -------------------------------------------------------------------------
// The tenant-scoped console: cross-tenant references refused, the
// resource named, the live manifest untouched.
// -------------------------------------------------------------------------

#[tokio::test]
async fn tenant_credentials_are_refused_against_other_tenants_resources() {
    let root = std::env::temp_dir().join(format!("unidpp-sv7-acme-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let state = state_under(
        &root,
        "tenants/acme/unidpp-operator.yaml",
        &tenant_yaml("acme"),
    );
    let app = router(state.clone());
    let session = session_of(&app, "tenant-admin-token")
        .await
        .expect("session");
    let cookie = session;

    // The wrong credential never becomes a session.
    assert!(session_of(&app, "globex-admin-token").await.is_none());

    // The cross-tenant write path: acme's session saving a manifest
    // that points the issuer's journal at globex's subtree.
    let probe = tenant_yaml("acme").replace(
        "tenants/acme/issuer-journal.jsonl",
        "tenants/globex/issuer-journal.jsonl",
    );
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/config",
            Some(&cookie),
            Some(&format!("manifest={}", urlencode_yaml(&probe))),
        ))
        .await
        .expect("route");
    let body = body_of(response).await;
    assert!(
        body.contains("cross-tenant refusal"),
        "the refusal must state its class: {}",
        &body[..body.len().min(400)]
    );
    assert!(
        body.contains("services.issuer.state_file")
            && body.contains("tenants/globex/issuer-journal.jsonl"),
        "the refusal must name the resource (field and path): {}",
        &body[..body.len().min(400)]
    );
    assert!(body.contains("nothing was written"));

    // The live manifest is untouched: the refusal is not a partial
    // write.
    let live = std::fs::read_to_string(root.join("tenants/acme/unidpp-operator.yaml")).unwrap();
    assert!(
        live.contains("tenants/acme/issuer-journal.jsonl"),
        "the live manifest must still name acme's own journal"
    );

    let _ = std::fs::remove_dir_all(&root);
}

// -------------------------------------------------------------------------
// Escape attempts from the tenant console: traversal and absolute
// paths are refused for everyone; in-scope saves still work.
// -------------------------------------------------------------------------

#[tokio::test]
async fn traversal_and_absolute_paths_are_refused_and_in_scope_saves_work() {
    let root = std::env::temp_dir().join(format!("unidpp-sv7-esc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let state = state_under(
        &root,
        "tenants/acme/unidpp-operator.yaml",
        &tenant_yaml("acme"),
    );
    let app = router(state.clone());
    let session = session_of(&app, "tenant-admin-token")
        .await
        .expect("session");
    let cookie = session;

    for bad in [
        "../../globex/issuer-journal.jsonl",
        "/var/lib/globex/journal.jsonl",
    ] {
        let probe = tenant_yaml("acme").replace("tenants/acme/issuer-journal.jsonl", bad);
        let response = app
            .clone()
            .oneshot(request(
                "POST",
                "/config",
                Some(&cookie),
                Some(&format!("manifest={}", urlencode_yaml(&probe))),
            ))
            .await
            .expect("route");
        let body = body_of(response).await;
        assert!(
            body.contains("cross-tenant refusal") && body.contains(bad),
            "the escape `{bad}` must be refused with the path named: {}",
            &body[..body.len().min(400)]
        );
    }

    // The negative control: an in-scope save still works (the
    // confinement is a boundary, not a lockout).
    let fine = tenant_yaml("acme").replace(
        "tenants/acme/issuer-journal.jsonl",
        "tenants/acme/issuer-journal-v2.jsonl",
    );
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/config",
            Some(&cookie),
            Some(&format!("manifest={}", urlencode_yaml(&fine))),
        ))
        .await
        .expect("route");
    let body = body_of(response).await;
    assert!(
        body.contains("Saved and validated"),
        "an in-scope save must succeed: {}",
        &body[..body.len().min(400)]
    );
    let live = std::fs::read_to_string(root.join("tenants/acme/unidpp-operator.yaml")).unwrap();
    assert!(live.contains("issuer-journal-v2.jsonl"));

    let _ = std::fs::remove_dir_all(&root);
}

// -------------------------------------------------------------------------
// The root console: it may not reach into a tenant's subtree — each
// tenant has its own console — and its own in-root saves work.
// -------------------------------------------------------------------------

#[tokio::test]
async fn the_root_console_does_not_touch_tenant_state() {
    let root = std::env::temp_dir().join(format!("unidpp-sv7-root-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let state = state_under(&root, "unidpp-operator.yaml", root_yaml());
    let app = router(state.clone());
    let session = session_of(&app, "tenant-admin-token")
        .await
        .expect("session");
    let cookie = session;

    let probe = root_yaml().replace(
        "registry-journal.jsonl",
        "tenants/globex/registry-journal.jsonl",
    );
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/config",
            Some(&cookie),
            Some(&format!("manifest={}", urlencode_yaml(&probe))),
        ))
        .await
        .expect("route");
    let body = body_of(response).await;
    assert!(
        body.contains("cross-tenant refusal")
            && body.contains("tenants/globex/registry-journal.jsonl")
            && body.contains("tenants have their own consoles"),
        "the root console's probe of a tenant's journal must be refused with the resource named: {}",
        &body[..body.len().min(400)]
    );

    // In-root state remains fine for the root console.
    let fine = root_yaml().replace("registry-journal.jsonl", "run/registry-journal.jsonl");
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/config",
            Some(&cookie),
            Some(&format!("manifest={}", urlencode_yaml(&fine))),
        ))
        .await
        .expect("route");
    let body = body_of(response).await;
    assert!(body.contains("Saved and validated"));

    let _ = std::fs::remove_dir_all(&root);
}

// -------------------------------------------------------------------------
// The tenant-creation surface: names that would escape the tenants
// directory are refused before anything is written.
// -------------------------------------------------------------------------

#[tokio::test]
async fn tenant_creation_refuses_escaping_names() {
    let root = std::env::temp_dir().join(format!("unidpp-sv7-names-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let state = state_under(&root, "unidpp-operator.yaml", root_yaml());
    let app = router(state.clone());
    let session = session_of(&app, "tenant-admin-token")
        .await
        .expect("session");
    let cookie = session;

    for bad in ["../acme", "a/b", ".hidden", ""] {
        let response = app
            .clone()
            .oneshot(request(
                "POST",
                "/tenants",
                Some(&cookie),
                Some(&format!(
                    "name={}&organization=G&product_name=G&profile=whitelabel&residency=eu&primary=%23000&accent=%23fff&base_port=9500&suites=ecdsa-p256&suites=ecdsa-p256",
                    urlencode_yaml(bad)
                )),
            ))
            .await
            .expect("route");
        let body = body_of(response).await;
        assert!(
            body.contains("Not created"),
            "the escaping tenant name `{bad}` must be refused: {}",
            &body[..body.len().min(200)]
        );
    }
    // Nothing escaped into the tree.
    assert!(!root.join("acme").exists());
    assert!(!root.join("a").exists());

    let _ = std::fs::remove_dir_all(&root);
}
