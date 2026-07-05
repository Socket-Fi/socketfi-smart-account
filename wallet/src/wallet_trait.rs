use soroban_sdk::{Address, BytesN, Env, Vec};

use socketfi_shared::{
    key_types::{BlsKeyWithPoP, PasskeySignature},
    wallet_error::WalletError,
};

pub trait WalletTrait {
    // initialization
    fn __constructor(
        env: Env,
        challenge: BytesN<32>,
        passkey: BytesN<65>,
        passkey_sig: PasskeySignature,
        rpid_hash: BytesN<32>,
        bls_keys_pop: Vec<BlsKeyWithPoP>,
        guardians: Vec<Address>,
    ) -> Result<(), WalletError>;

    // Account management
    fn rotate_passkey(
        env: Env,
        new_passkey: BytesN<65>,
        new_passkey_pop_sig: PasskeySignature,
    ) -> Result<(), WalletError>;

    fn recover_account(
        env: Env,
        new_passkey: BytesN<65>,
        new_passkey_pop_sig: PasskeySignature,
        agg_bls_sig: BytesN<192>,
    ) -> Result<(), WalletError>;

    // Emergency controls
    fn pause(env: Env, guardian: Address) -> Result<(), WalletError>;
    fn approve_unpause(env: Env, guardian: Address) -> Result<(), WalletError>;
    fn unpause(env: Env) -> Result<(), WalletError>;

    // Guardian management
    fn add_guardian(env: Env, guardian: Address) -> Result<(), WalletError>;
    fn schedule_guardian_removal(env: Env, guardian: Address) -> Result<(), WalletError>;
    fn finalize_guardian_removal(env: Env, guardian: Address) -> Result<(), WalletError>;

    // views
    fn is_paused(env: Env) -> bool;
    fn get_passkey(env: Env) -> Option<BytesN<65>>;
}
