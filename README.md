# unidpp-console

The UniDPP admin console — one branded pane over a deployment. The
SaaS doctrine it embodies: **a deployment is data** (the
[operator manifest](../unidpp-config)), and **the console is a
surface, not a second brain** — every fact comes from a service's own
API or from the manifest; every capability is a call to an existing
endpoint. It adds no domain logic.

```
UNIDPP_CONSOLE_BIND=127.0.0.1:8389
UNIDPP_CONSOLE_MANIFEST=unidpp-operator.yaml
UNIDPP_CONSOLE_ADMIN_TOKEN=...        # unset = read-only dev mode
./target/debug/unidpp-console
```

| Page | What it does |
|---|---|
| `/` | Dashboard: deployment summary (name, profile, egress policy), per-service health |
| `/config` | The manifest as an editable YAML — validate on save (atomic write, nothing written on rejection), secrets stay `${VAR}` references, per-service rendered-environment preview |
| `/registry` | The registry's items, filtered by class/register |
| `/passports` | The issuer's audit trail, document lookup, and inline pack verification through the CLI's own pipeline against the issuer's published anchors |
| `/branding` | The whitelabel preview: organization, product name, theme swatches, chrome |

Auth: an admin token (env) buys a session (constant-time compare,
8-hour cookie); mutations require the session; without a token the
console is read-only by construction. Every interpolated string goes
through one escaping helper — it is an admin surface.
