use crate::states::{read_factory, read_installed_wasm_hash};

use soroban_sdk::{contractclient, BytesN, Env};

#[allow(dead_code)]
#[contractclient(name = "AccountFactoryClient")]
pub trait AccountFactory {
    fn get_latest_account_wasm(e: Env) -> BytesN<32>;
}

pub fn read_migration_required(env: &Env) -> (bool, Option<BytesN<32>>) {
    let installed_wasm: BytesN<32> = read_installed_wasm_hash(env).unwrap();

    let factory = read_factory(env).unwrap();

    let latest_wasm: BytesN<32> =
        AccountFactoryClient::new(env, &factory).get_latest_account_wasm();

    if installed_wasm == latest_wasm {
        (false, None)
    } else {
        (true, Some(latest_wasm))
    }
}
