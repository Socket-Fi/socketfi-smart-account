#![no_std]

soroban_sdk::contractmeta!(
    key = "source_repo",
    val = "github:Socket-Fi/socketfi-smart-account"
);
mod account_factory;
// Soroban generates ABI wrappers outside the impl; scope this exception to the
// entrypoint module so the existing contract argument lists remain compatible.
#[allow(clippy::too_many_arguments)]
mod contract;
mod contract_trait;
mod data;

#[cfg(test)]
mod rpid_tests;

#[cfg(test)]
mod creation_tests;
