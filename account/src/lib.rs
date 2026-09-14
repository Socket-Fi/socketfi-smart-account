#![no_std]

soroban_sdk::contractmeta!(
    key = "source_repo",
    val = "github:Socket-Fi/socketfi-smart-account"
);

// Soroban generates ABI wrappers outside the impl; scope this exception to the
// entrypoint module so the existing contract argument lists remain compatible.
#[allow(clippy::too_many_arguments)]
mod account;
mod account_trait;
mod auth;
mod guardians;
mod migrate;
mod session_policy;
mod signer_management;
mod states;
mod validation;

#[cfg(test)]
mod rpid_tests;
