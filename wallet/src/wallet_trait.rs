use socketfi_webauthn::{
    key_types::{BlsKeyWithPoP, PasskeySignature},
    wallet_error::WalletError,
};
use soroban_sdk::{Address, BytesN, Env, Map, String, Symbol, Val, Vec};

pub trait WalletTrait {
    // initialization
    fn __constructor(
        env: Env,
        challenge: BytesN<32>,
        passkey: BytesN<65>,
        passkey_sig: PasskeySignature,
        rpid_hash: BytesN<32>,
        bls_keys_pop: Vec<BlsKeyWithPoP>,
        registry: Address,
        social_router: Address,
        fee_manager: Address,
        factory: Address,
    ) -> Result<(), WalletError>;

    // owner/account settings
    fn set_external_wallet(
        env: Env,
        external_wallet: Address,
        passkey_sig: Option<PasskeySignature>,
        valid_until_ledger: u32,
    ) -> Result<(), WalletError>;

    fn set_asset_limit(
        env: Env,
        asset: Address,
        limit: i128,
        passkey_sig: Option<PasskeySignature>,
        valid_until_ledger: u32,
    ) -> Result<(), WalletError>;

    // asset actions
    fn deposit(env: Env, from: Address, asset: Address, amount: i128) -> Result<(), WalletError>;

    fn withdraw(
        env: Env,
        to: Address,
        asset: Address,
        amount: i128,
        passkey_sig: Option<PasskeySignature>,
        valid_until_ledger: u32,
    ) -> Result<(), WalletError>;

    fn approve(
        env: Env,
        asset: Address,
        spender: Address,
        amount: i128,
        passkey_sig: Option<PasskeySignature>,
        valid_until_ledger: u32,
    ) -> Result<(), WalletError>;

    fn spend(
        env: Env,
        asset: Address,
        spender: Address,
        amount: i128,
        to: Address,
    ) -> Result<(), WalletError>;

    // contract interaction
    fn dapp_invoker(
        env: Env,
        contract_id: Address,
        func: Symbol,
        args: Option<Vec<Val>>,
        auth_vec: Option<Vec<Map<String, Val>>>,
        passkey_sig: Option<PasskeySignature>,
        valid_until_ledger: u32,
    ) -> Result<(), WalletError>;

    // views
    fn get_passkey(env: Env) -> Option<BytesN<65>>;
    fn get_allowance(env: Env, asset: Address, spender: Address) -> i128;
    fn get_limit(env: Env, asset: Address) -> Option<i128>;

    fn get_tx_payload(
        env: Env,
        func: String,
        args: Vec<Val>,
        valid_until_ledger: u32,
    ) -> Result<BytesN<32>, WalletError>;
    fn get_balance(env: Env, asset: Address) -> i128;
    fn get_owner(env: Env) -> Option<Address>;
    fn get_registry(env: Env) -> Option<Address>;
    fn get_fee_manager(env: Env) -> Option<Address>;
    fn get_social_router(env: Env) -> Option<Address>;
    fn get_factory(env: Env) -> Option<Address>;
    fn sync_protocol_dependencies(
        env: Env,
        passkey_sig: Option<PasskeySignature>,
        valid_until_ledger: u32,
    ) -> Result<(), WalletError>;

    // upgrade
    fn upgrade(
        env: Env,
        passkey_sig: Option<PasskeySignature>,
        valid_until_ledger: u32,
    ) -> Result<(), WalletError>;
}
