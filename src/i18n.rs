//! The console's chrome strings, per locale. A new language is a
//! table entry plus `unidpp_config::SUPPORTED_LOCALES` — not a code
//! change (OCP at the string level). Unknown keys render as
//! themselves (loud in every test); unknown locales fall back to en.

/// (key, en, zh-CN)
pub const STRINGS: &[(&str, &str, &str)] = &[
    // nav
    ("nav.dashboard", "Dashboard", "仪表盘"),
    ("nav.config", "Configuration", "配置"),
    ("nav.registry", "Registry", "注册表"),
    ("nav.passports", "Passports", "护照"),
    ("nav.branding", "Branding", "品牌设定"),
    ("nav.trust", "Trust", "信任"),
    // footer / chrome
    ("foot.deployment", "deployment", "部署"),
    ("foot.legal", "legal", "法律"),
    ("foot.contact", "contact", "联系"),
    // login
    ("login.title", "Sign in", "登录"),
    ("login.hint", "the admin token", "管理员令牌"),
    ("login.button", "Sign in", "登录"),
    // dashboard cards
    ("card.deployment", "Deployment", "部署"),
    ("card.profile", "Profile", "部署模式"),
    ("card.base_url", "Base URL", "基础地址"),
    ("card.egress", "Egress policy", "出站策略"),
    ("card.registry_items", "Registry items", "注册表条目"),
    ("card.untded", "UNTDED data elements", "UNTDED 数据元"),
    ("card.passports", "Passports", "护照"),
    ("card.log_tree", "Log tree size", "日志树大小"),
    // services matrix
    ("mx.service", "Service", "服务"),
    ("mx.bind", "Bind", "监听地址"),
    ("mx.role", "Role", "角色"),
    ("mx.public", "Public", "公网地址"),
    ("mx.health", "Health", "健康"),
    ("mx.version", "Version", "版本"),
    ("mx.healthy", "healthy", "健康"),
    ("mx.loopback", "loopback", "仅回环"),
    ("mx.unreachable", "unreachable", "不可达"),
    ("mx.no_bind", "no bind", "无监听"),
    // page titles (page_for maps its known titles through these)
    ("page.dashboard", "Dashboard", "仪表盘"),
    ("page.configuration", "Configuration", "配置"),
    ("page.registry", "Registry", "注册表"),
    ("page.passports", "Passports", "护照"),
    ("page.branding", "Branding", "品牌设定"),
    ("page.backups", "Backups", "备份"),
    ("page.tenants", "Tenants", "租户"),
    ("page.trust", "Trust", "信任"),
    ("page.egress", "Egress", "出站"),
    // common buttons
    ("btn.backup", "Back up this deployment", "备份整个部署"),
    ("btn.drill", "Run a restore drill", "运行恢复演练"),
    ("btn.save_branding", "Save branding", "保存品牌设定"),
    ("btn.verify", "Verify", "验证"),
    ("btn.lookup", "Look up", "查询"),
];

/// The localized string for `key` under `locale` (the manifest's
/// `branding.locale`); en is the fallback for unknown locales,
/// the key itself for unknown keys.
pub fn t(locale: &str, key: &str) -> &'static str {
    for (k, en, zh) in STRINGS {
        if *k == key {
            return if locale == "zh-CN" { zh } else { en };
        }
    }
    // Fell through the table: unknown keys render empty — visibly
    // broken, caught by the chrome tests, never a silent fallback.
    ""
}
