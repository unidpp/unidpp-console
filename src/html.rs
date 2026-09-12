//! The branded page chrome and the one HTML-escaping helper every
//! interpolation goes through. The console renders operator-supplied
//! strings (organization names, item ids, passport ids) into an admin
//! surface — escaping is not optional.

use unidpp_config::{Branding, OperatorManifest};

mod i18n_labels {
    pub fn footer_deployment(locale: &str) -> String {
        crate::i18n::t(locale, "foot.deployment").to_string()
    }
}

/// Escape every interpolatable value (the anti-XSS chokepoint).
pub fn esc(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// The full page: branded chrome around `body`.
pub fn page(manifest: &OperatorManifest, title: &str, body: &str, nav_active: &str) -> String {
    let branding = &manifest.branding;
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · {}</title>
<style>{STYLESHEET}</style>
</head>
<body style="--primary:{primary};--accent:{accent}">
<header class="top">
  <div class="brand">{logo}{org}<span class="product">{product}</span></div>
  <nav>{nav}</nav>
</header>
<main>{body}</main>
<footer class="foot">
  <span>{profile} {deployment_label} · {name}</span>
  {footer_links}
</footer>
</body>
</html>"#,
        esc(&branding.product_name),
        primary = esc(&branding.theme.primary),
        accent = esc(&branding.theme.accent),
        logo = logo_html(branding),
        org = esc(&branding.organization),
        product = esc(&branding.product_name),
        nav = nav_html(nav_active, &branding.locale),
        profile = esc(manifest.deployment.profile.as_str()),
        deployment_label = esc(&i18n_labels::footer_deployment(&branding.locale)),
        name = esc(&manifest.deployment.name),
        footer_links = footer_html(branding),
    )
}

fn logo_html(branding: &Branding) -> String {
    match &branding.logo {
        Some(src) => {
            format!(r#"<img class="logo" src="{}" alt="">"#, esc(src))
        }
        None => String::new(),
    }
}

fn footer_html(branding: &Branding) -> String {
    let locale = &branding.locale;
    let mut links = Vec::new();
    if let Some(url) = &branding.footer.legal_url {
        links.push(format!(
            r#"<a href="{}">{}</a>"#,
            esc(url),
            crate::i18n::t(locale, "foot.legal")
        ));
    }
    if let Some(url) = &branding.footer.contact_url {
        links.push(format!(
            r#"<a href="{}">{}</a>"#,
            esc(url),
            crate::i18n::t(locale, "foot.contact")
        ));
    }
    if links.is_empty() {
        String::new()
    } else {
        format!(r#"<span class="links">{}</span>"#, links.join(" · "))
    }
}

fn nav_html(active: &str, locale: &str) -> String {
    const ITEMS: &[(&str, &str)] = &[
        ("dashboard", "/"),
        ("config", "/config"),
        ("registry", "/registry"),
        ("passports", "/passports"),
        ("declarations", "/declarations"),
        ("coverage", "/coverage"),
        ("carrier", "/carrier"),
        ("profiles", "/profiles"),
        ("archival", "/archival"),
        ("trust", "/trust"),
        ("branding", "/branding"),
    ];
    ITEMS
        .iter()
        .map(|(key, href)| {
            let label = crate::i18n::t(locale, &format!("nav.{key}"));
            if *key == active {
                format!(r#"<a class="active" href="{href}">{label}</a>"#)
            } else {
                format!(r#"<a href="{href}">{label}</a>"#)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

const STYLESHEET: &str = r#"
:root { --bg:#f5f6f8; --panel:#ffffff; --ink:#161616; --muted:#5c5c5c;
        --line:#d8d8d8; --ok:#0e8345; --bad:#b2213c; --warn:#a56a00; }
* { box-sizing: border-box; }
body { margin:0; font:15px/1.5 system-ui,-apple-system,sans-serif;
       background:var(--bg); color:var(--ink); }
.top { display:flex; justify-content:space-between; align-items:center;
       padding:.7rem 1.2rem; background:var(--panel);
       border-bottom:3px solid var(--primary); flex-wrap:wrap; gap:.6rem; }
.brand { display:flex; align-items:center; gap:.6rem; font-weight:700;
         font-size:1.05rem; }
.brand .product { color:var(--muted); font-weight:500; }
.logo { height:26px; }
nav { display:flex; gap:.2rem; flex-wrap:wrap; }
nav a { padding:.35rem .7rem; border-radius:6px; text-decoration:none;
        color:var(--ink); }
nav a:hover { background:var(--bg); }
nav a.active { background:var(--primary); color:#fff; }
main { max-width:1080px; margin:1.4rem auto; padding:0 1.2rem; }
h1 { font-size:1.35rem; margin:.2rem 0 1rem; }
h2 { font-size:1.02rem; margin:1.4rem 0 .5rem; color:var(--muted);
     text-transform:uppercase; letter-spacing:.04em; }
table { width:100%; border-collapse:collapse; background:var(--panel);
        border:1px solid var(--line); }
th, td { text-align:left; padding:.5rem .7rem;
         border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--muted); font-weight:600; font-size:.82rem; }
code, .mono { font-family:ui-monospace,Menlo,monospace; font-size:.85em; }
pre { background:#101418; color:#d7e0ea; padding:.9rem 1rem;
      border-radius:8px; overflow:auto; font-size:.8rem; }
form.inline { display:inline; }
input, textarea, select { font:inherit; padding:.45rem .6rem;
      border:1px solid var(--line); border-radius:6px; background:#fff; }
textarea { width:100%; min-height:22rem; font-family:ui-monospace,Menlo,monospace;
           font-size:.8rem; }
button { font:inherit; background:var(--primary); color:#fff; border:none;
         padding:.5rem 1rem; border-radius:6px; cursor:pointer; }
button.secondary { background:var(--panel); color:var(--ink);
                   border:1px solid var(--line); }
.badge { display:inline-block; padding:.1rem .5rem; border-radius:99px;
         font-size:.75rem; font-weight:600; }
.badge.ok { background:color-mix(in srgb, var(--ok) 14%, transparent);
            color:var(--ok); }
.badge.bad { background:color-mix(in srgb, var(--bad) 14%, transparent);
             color:var(--bad); }
.badge.warn { background:color-mix(in srgb, var(--warn) 16%, transparent);
              color:var(--warn); }
.grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(220px,1fr));
        gap:.8rem; }
.card { background:var(--panel); border:1px solid var(--line);
        border-radius:10px; padding:.9rem 1rem; }
.card .label { color:var(--muted); font-size:.78rem;
               text-transform:uppercase; letter-spacing:.05em; }
.card .value { font-size:1.25rem; font-weight:700; margin-top:.15rem; }
.note { background:color-mix(in srgb, var(--primary) 7%, transparent);
        border-left:3px solid var(--primary); padding:.6rem .9rem;
        border-radius:0 8px 8px 0; }
.error { background:color-mix(in srgb, var(--bad) 8%, transparent);
         border-left:3px solid var(--bad); padding:.6rem .9rem;
         border-radius:0 8px 8px 0; }
.foot { display:flex; justify-content:space-between; color:var(--muted);
        font-size:.8rem; padding:1rem 1.2rem 2rem; max-width:1080px;
        margin:0 auto; flex-wrap:wrap; gap:.5rem; }
.foot a { color:var(--muted); }
.swatches { display:flex; gap:.6rem; margin:.4rem 0; }
.swatch { width:84px; height:54px; border-radius:8px; display:grid;
          place-items:center; color:#fff; font-size:.72rem;
          font-family:ui-monospace,monospace; }
"#;
