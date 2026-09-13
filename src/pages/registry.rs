//! The registry browser: the item classes, paginated, served from the registry's own API.

use crate::futures_block;
use std::collections::HashMap;
use std::sync::Arc;

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

pub(crate) async fn registry_browser(
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
