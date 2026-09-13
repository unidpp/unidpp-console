//! The SV-7 isolation boundary (the console half): no cross-tenant
//! read or write path through the saved manifest.
//!
//! A saved manifest may not reference state outside this
//! deployment's scope: a console running from `tenants/<me>/`
//! confines its journals to that subtree; the root console confines
//! itself to non-tenant paths (each tenant has its own console);
//! absolute paths and traversal are refused outright, the resource
//! named. An auditor proving no cross-tenant path reads this file
//! and nothing else.

use std::path::Path;

use unidpp_config::OperatorManifest;

use crate::AppState;

/// Every state-path field of a manifest, as (field, value) pairs.
pub(crate) fn state_paths(manifest: &OperatorManifest) -> Vec<(&'static str, String)> {
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
pub(crate) fn tenant_scope(manifest_path: &Path) -> Option<String> {
    let parent = manifest_path.parent()?;
    let name = parent.file_name()?.to_str()?;
    if parent.parent()?.file_name()?.to_str()? == "tenants" {
        Some(format!("tenants/{name}/"))
    } else {
        None
    }
}

/// The SV-7 refusal: every state path stays inside the scope.
pub(crate) fn confine_state_paths(
    state: &AppState,
    manifest: &OperatorManifest,
) -> Result<(), String> {
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
