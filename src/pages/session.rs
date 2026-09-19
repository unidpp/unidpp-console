//! The session surfaces: the login gate, its submission, logout.

use crate::i18n;
use crate::redirect;
use axum::extract::Form;
use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
#[allow(unused)]
use serde::Deserialize;

#[allow(unused)]
use crate::http;
#[allow(unused)]
use crate::verify;
use crate::{constant_time_eq, page_for, AppState, SESSION_LIFETIME};

/// The login page.
#[utoipa::path(
    get,
    path = "/login",
    tag = "console",
    responses(
        (status = 200, description = "The page, rendered against the deployment manifest", body = String, content_type = "text/html"),
        (status = 303, description = "The session gate redirects an unauthenticated browser to `/login`"),
    )
)]
pub(crate) async fn login_page(State(state): State<Arc<AppState>>) -> Response {
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
pub(crate) struct LoginForm {
    pub(crate) token: String,
}

/// Submit the login form.
#[utoipa::path(
    post,
    path = "/login",
    tag = "console",
    request_body(content = String, content_type = "application/x-www-form-urlencoded", description = "The login form: the admin token"),
    responses(
        (status = 303, description = "Authenticated: a redirect to the dashboard with the session issued"),
        (status = 200, description = "The form is re-rendered with its error stated", body = String, content_type = "text/html"),
    )
)]
pub(crate) async fn login_submit(
    State(state): State<Arc<AppState>>,
    Form(form): Form<LoginForm>,
) -> Response {
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

/// End the session.
#[utoipa::path(
    post,
    path = "/logout",
    tag = "console",
    responses(
        (status = 303, description = "A redirect to the login page, the session ended"),
    )
)]
pub(crate) async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
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
