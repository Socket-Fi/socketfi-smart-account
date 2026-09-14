use crate::account_factory::{write_create_account, write_rpid_hash};
use socketfi_shared::{
    account_error::AccountError,
    key_types::{EvmSignature, PasskeySignature},
};
use soroban_sdk::{
    contract, contractimpl, testutils::Address as _, Address, Bytes, BytesN, Env, String, Vec,
};

#[contract]
struct FactoryStorageHost;
#[contractimpl]
impl FactoryStorageHost {
    pub fn ping() {}
}

fn prepare(env: &Env, kind: u8) -> Result<Address, AccountError> {
    write_create_account(
        env,
        BytesN::from_array(env, &[7; 32]),
        if kind == 0 {
            Some(BytesN::from_array(env, &[0; 65]))
        } else {
            None
        },
        if kind == 0 {
            Some(PasskeySignature {
                signature: BytesN::from_array(env, &[0; 64]),
                client_data_json: Bytes::new(env),
                authenticator_data: Bytes::new(env),
            })
        } else {
            None
        },
        if kind == 1 {
            Some(BytesN::from_array(env, &[0; 32]))
        } else {
            None
        },
        if kind == 1 {
            Some(Address::generate(env))
        } else {
            None
        },
        if kind == 2 {
            Some(BytesN::from_array(env, &[0; 20]))
        } else {
            None
        },
        if kind == 2 {
            Some(EvmSignature {
                signature: BytesN::from_array(env, &[0; 64]),
                recovery_id: 0,
            })
        } else {
            None
        },
        Vec::new(env),
        Vec::new(env),
    )
}

#[test]
fn factory_requires_its_own_rpid_for_every_signer_before_deployment() {
    let env = Env::default();
    // Only the Stellar authorization is mocked; deployment and RP lookup are real.
    env.mock_all_auths();
    for kind in [0, 1, 2] {
        let host = env.register(FactoryStorageHost, ());
        env.as_contract(&host, || {
            assert_eq!(prepare(&env, kind), Err(AccountError::RpidNotFound));
            write_rpid_hash(&env, &String::from_str(&env, "socket.fi"));
            // With RP configuration present, creation advances to the WASM check.
            assert_eq!(
                prepare(&env, kind),
                Err(AccountError::AccountVersionNotFound)
            );
        });
    }
}
