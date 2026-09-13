//! The console's surfaces, one module per page family. The core
//! (state, sessions, the router) lives in the crate root; a new
//! surface is a module here plus its route.

pub(crate) mod backups;
pub(crate) mod branding;
pub(crate) mod config;
pub(crate) mod dashboard;
pub(crate) mod egress;
pub(crate) mod passports;
pub(crate) mod registry;
pub(crate) mod session;
pub(crate) mod tenants;
pub(crate) mod trust;
