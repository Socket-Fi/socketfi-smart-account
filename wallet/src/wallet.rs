use crate::{
    auth::{compute_tx_nonce, increment_nonce, owner_require_auth},
    constructor::init_constructor,
    fee_handler::handle_transaction_fee,
    invocation_auth::{dapp_invoke_auth, validate_limit},
    state::{is_initialized, read_owner, read_passkey, write_owner},
    wallet_creation_validation::{validate_verify_bls_key_set_pop, verify_passkey_pop},
    wallet_trait::WalletTrait,
};
use socketfi_access::access::{
    read_factory, read_fee_manager, read_registry, read_social_router, write_fee_manager,
    write_registry, write_social_router,
};
use socketfi_shared::{
    constants::PRECISION,
    dependencies_types::ProtocolDependencies,
    events,
    tokens::{
        read_allowance, read_balance, read_limit, send_asset, spend_asset, take_asset,
        write_approve, write_limit,
    },
};
use socketfi_webauthn::{
    key_types::{BlsKeyWithPoP, PasskeySignature},
    wallet_error::WalletError,
};
use soroban_sdk::{
    contract, contractimpl, token, vec, Address, BytesN, Env, IntoVal, Map, String, Symbol, Val,
    Vec,
};

#[contract]
pub struct Wallet;

#[contractimpl]
impl WalletTrait for Wallet {
    // ---------------------------------------------------------------------
    // Initialization
    // ---------------------------------------------------------------------
    /// Initialize wallet state and linked contract addresses.
    ///
    /// Auth:
    /// - Intended to run once during wallet deployment/creation.
    ///
    /// Effects:
    /// - Stores access keys and linked contract references.
    /// - Marks the wallet as initialized.
    ///
    /// Notes:
    /// - Reverts if initialization was already completed.
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
    ) -> Result<(), WalletError> {
        if is_initialized(&env) {
            return Err(WalletError::AlreadyInitialized);
        }

        verify_passkey_pop(
            &env,
            challenge.clone(),
            passkey.clone(),
            passkey_sig,
            rpid_hash.clone(),
        )?;

        let bls_agg = validate_verify_bls_key_set_pop(&env, challenge, bls_keys_pop)?;

        init_constructor(
            env,
            passkey,
            rpid_hash,
            bls_agg,
            registry,
            social_router,
            fee_manager,
            factory,
        )?;

        Ok(())
    }

    // ---------------------------------------------------------------------
    // owner settings
    // ---------------------------------------------------------------------

    /// Set or replace the linked external owner wallet.
    ///
    /// Auth:
    /// - Requires owner authorization through the wallet bls auth flow.
    ///
    /// Effects:
    /// - Updates the stored external owner address.
    ///
    /// Notes:
    /// - Payload includes the new address and nonce to prevent replay.
    fn set_external_wallet(
        env: Env,
        external_wallet: Address,
        passkey_sig: Option<PasskeySignature>,
        valid_until_ledger: u32,
    ) -> Result<(), WalletError> {
        let args: Vec<Val> = vec![&env, external_wallet.clone().to_val()];
        let challenge = compute_tx_nonce(
            &env,
            String::from_str(&env, "set_external_wallet"),
            args,
            valid_until_ledger,
        )?;

        owner_require_auth(env.clone(), challenge, passkey_sig)?;
        write_owner(&env, &external_wallet);
        increment_nonce(&env);

        Ok(())
    }

    /// Set a asset-specific spend limit.

    /// Auth:
    /// - Requires owner authorization through the wallet auth flow.
    ///
    /// Effects:
    /// - Stores a per-asset limit override.
    ///
    /// Notes:
    /// - Rejects negative values.
    /// - Payload includes asset, limit, and nonce to prevent replay.
    fn set_asset_limit(
        env: Env,
        asset: Address,
        limit: i128,
        passkey_sig: Option<PasskeySignature>,
        valid_until_ledger: u32,
    ) -> Result<(), WalletError> {
        if limit < 0 {
            return Err(WalletError::InvalidLimit);
        }

        let args: Vec<Val> = vec![&env, asset.clone().into_val(&env), limit.into_val(&env)];
        let challenge = compute_tx_nonce(
            &env,
            String::from_str(&env, "set_limit"),
            args,
            valid_until_ledger,
        )?;

        let token = token::Client::new(&env, &asset);
        let decimals = token.decimals();
        let token_precision = 10_i128
            .checked_pow(decimals)
            .ok_or(WalletError::InvalidAmount)?;

        let normalized_limit = limit
            .checked_mul(token_precision)
            .ok_or(WalletError::InvalidAmount)?
            / PRECISION;

        owner_require_auth(env.clone(), challenge, passkey_sig)?;

        write_limit(&env, asset, normalized_limit);
        increment_nonce(&env);
        Ok(())
    }

    // ---------------------------------------------------------------------
    // Asset actions
    // ---------------------------------------------------------------------

    /// Deposit asset into the wallet.
    ///
    /// Auth:
    /// - Requires authorization from the source address.
    ///
    /// Effects:
    /// - Pulls asset from the source address into wallet-controlled balance.
    ///
    /// Notes:
    /// - Rejects non-positive amounts.
    /// -`take_asset` transfers funds into the current contract context.
    fn deposit(env: Env, from: Address, asset: Address, amount: i128) -> Result<(), WalletError> {
        from.require_auth();

        if amount <= 0 {
            return Err(WalletError::InvalidAmount);
        }

        take_asset(&env, &from, &asset, amount);
        Ok(())
    }

    /// Withdraw asset from the wallet to a recipient.
    ///
    /// Auth:
    /// - Requires owner authorization through the wallet auth flow.
    ///
    /// Effects:
    /// - Quotes and handles protocol transaction fees before withdrawal.
    /// - Transfers the requested asset amount from the wallet to the recipient.
    ///
    /// Notes:
    /// - Rejects non-positive amounts.
    /// - Enforces the configured asset spend limit before withdrawal.
    fn withdraw(
        env: Env,
        to: Address,
        asset: Address,
        amount: i128,
        passkey_sig: Option<PasskeySignature>,
        valid_until_ledger: u32,
    ) -> Result<(), WalletError> {
        if amount <= 0 {
            return Err(WalletError::InvalidAmount);
        }

        if let Some(limit) = read_limit(&env, asset.clone()) {
            if amount > limit {
                return Err(WalletError::ExceedMaxAllowance);
            }
        }

        let args: Vec<Val> = vec![
            &env,
            to.clone().into_val(&env),
            asset.clone().into_val(&env),
            amount.into_val(&env),
        ];
        let challenge = compute_tx_nonce(
            &env,
            String::from_str(&env, "withdraw"),
            args,
            valid_until_ledger,
        )?;
        owner_require_auth(env.clone(), challenge, passkey_sig.clone())?;

        handle_transaction_fee(&env, asset.clone(), amount, &passkey_sig)?;

        send_asset(&env, &to, &asset, amount);
        increment_nonce(&env);
        Ok(())
    }

    /// Approve a spender to use wallet-held asset up to a given amount.
    ///
    /// Auth:
    /// - Requires owner authorization through the wallet auth flow.
    ///
    /// Effects:
    /// - Writes or updates spender allowance for the specified asset.
    ///
    /// Notes:
    /// - Rejects negative amounts.
    /// - Enforces the configured asset spend limit.

    fn approve(
        env: Env,
        asset: Address,
        spender: Address,
        amount: i128,
        passkey_sig: Option<PasskeySignature>,
        valid_until_ledger: u32,
    ) -> Result<(), WalletError> {
        if amount < 0 {
            return Err(WalletError::InvalidAmount);
        }

        if let Some(limit) = read_limit(&env, asset.clone()) {
            if amount > limit {
                return Err(WalletError::ExceedMaxAllowance);
            }
        }

        let cur_allowance = read_allowance(&env, &asset, &spender);

        // Enforce zero-reset:
        // non-zero -> non-zero is not allowed directly.
        // User must first set allowance to 0, then set the new value.
        if cur_allowance > 0 && amount > 0 {
            return Err(WalletError::AllowanceMustBeReset);
        }

        let args: Vec<Val> = vec![
            &env,
            asset.clone().into_val(&env),
            spender.clone().into_val(&env),
            amount.into_val(&env),
        ];

        let challenge = compute_tx_nonce(
            &env,
            String::from_str(&env, "approve"),
            args,
            valid_until_ledger,
        )?;

        owner_require_auth(env.clone(), challenge, passkey_sig.clone())?;

        handle_transaction_fee(&env, asset.clone(), amount, &passkey_sig)?;

        write_approve(&env, &asset, &spender, &amount);

        increment_nonce(&env);

        Ok(())
    }

    /// Spend wallet-held asset using spender authorization and stored allowance.
    ///
    /// Auth:
    /// - Requires direct authorization from the spender address.
    ///
    /// Effects:
    /// - Consumes allowance and transfers asset to the recipient.
    ///
    /// Notes:
    /// - Rejects non-positive amounts.
    /// -`spend_asset` validates allowance, reduces it correctly,
    ///   and transfers from wallet-controlled balance.
    fn spend(
        env: Env,
        asset: Address,
        spender: Address,
        amount: i128,
        to: Address,
    ) -> Result<(), WalletError> {
        spender.require_auth();

        if amount <= 0 {
            return Err(WalletError::InvalidAmount);
        }

        spend_asset(&env, &spender, &asset, amount, &to);
        Ok(())
    }

    // ---------------------------------------------------------------------
    // contract/dapp interaction
    // ---------------------------------------------------------------------

    /// Invoke an external contract/dapp through the wallet.
    ///
    /// Auth:
    /// - Requires owner authorization through the wallet auth flow.
    ///
    /// Effects:
    /// - Validates top-level token operations against configured spend limits.
    /// - Optionally validates and registers deep auth entries.
    /// - Performs an external contract call with the provided function and args.
    ///
    /// Notes:
    /// - Payload binds owner authorization to the target contract, function,
    ///   args, and optional deep auth payload.
    /// - Deep auth entries are authorized only after owner auth succeeds.
    fn dapp_invoker(
        env: Env,
        contract_id: Address,
        func: Symbol,
        args: Option<Vec<Val>>,
        auth_vec: Option<Vec<Map<String, Val>>>,
        passkey_sig: Option<PasskeySignature>,
        valid_until_ledger: u32,
    ) -> Result<(), WalletError> {
        // Validate the top-level call in case the wallet is directly invoking
        // a gated token operation such as transfer, approve, or burn.
        if let Some(a) = args.clone() {
            validate_limit(&env, contract_id.clone(), func.clone(), a)?;
        }

        // Build the signed payload from the exact invocation intent.
        //
        // This binds the owner authorization to:
        // - target contract
        // - target function
        // - top-level args
        // - optional deep auth entries
        let mut a_args: Vec<Val> = vec![
            &env,
            contract_id.clone().into_val(&env),
            func.clone().into_val(&env),
        ];

        if let Some(a) = args.clone() {
            a_args.push_back(a.into_val(&env));
        }

        if let Some(p) = auth_vec.clone() {
            a_args.push_back(p.into_val(&env));
        }

        let challenge = compute_tx_nonce(
            &env,
            String::from_str(&env, "dapp_invoker"),
            a_args,
            valid_until_ledger,
        )?;

        // Verify wallet owner/passkey authorization before granting any
        // current-contract deep auth.
        owner_require_auth(env.clone(), challenge, passkey_sig)?;

        // Validate and register deep auth entries after owner auth succeeds.
        //
        // dapp_invoke_auth also validates nested token operations such as
        // transfer, approve, or burn inside the provided auth vector.
        if let Some(p) = auth_vec {
            dapp_invoke_auth(&env, p)?;
        }

        let invoke_args = args.unwrap_or(vec![&env]);

        let _res: Val = env.invoke_contract(&contract_id, &func, invoke_args);
        increment_nonce(&env);

        Ok(())
    }

    /// Return the stored passkey, if configured.
    ///
    /// Effects:
    /// - Reads passkey state from storage.
    ///
    /// Notes:
    /// - Read-only helper.
    fn get_passkey(env: Env) -> Option<BytesN<65>> {
        read_passkey(&env)
    }

    /// Return current allowance for a spender on a asset.
    ///
    /// Effects:
    /// - Reads allowance state from storage.
    ///
    /// Notes:
    /// - Read-only helper.
    fn get_allowance(env: Env, asset: Address, spender: Address) -> i128 {
        read_allowance(&env, &asset, &spender)
    }

    /// Returns the configured spend limit for an asset.
    ///
    /// Audit note:
    /// Returning `Option<i128>` avoids overloading sentinel values (e.g. `0`)
    /// and makes the semantics explicit:
    /// - `Some(limit)` → enforce the configured limit
    /// - `None` → no asset-specific limit configured
    fn get_limit(env: Env, asset: Address) -> Option<i128> {
        read_limit(&env, asset)
    }

    /// Compute the authorization payload hash for a function call.
    ///
    /// Effects:
    /// - Returns the payload derived from function name, args, and nonce.
    ///
    /// Notes:
    /// - Read-only helper for off-chain signing flows.
    /// - Reviewers should confirm payload construction matches verification logic.
    fn get_tx_payload(
        env: Env,
        func: String,
        args: Vec<Val>,
        valid_until_ledger: u32,
    ) -> Result<BytesN<32>, WalletError> {
        compute_tx_nonce(&env, func, args, valid_until_ledger)
    }

    /// Return wallet balance for the specified asset.
    ///
    /// Effects:
    /// - Reads asset balance associated with the wallet.
    ///
    /// Notes:
    /// - Read-only helper.
    fn get_balance(env: Env, asset: Address) -> i128 {
        read_balance(&env, &asset)
    }

    /// Return the linked external owner wallet, if set.
    ///
    /// Effects:
    /// - Reads owner state from storage.
    ///
    /// Notes:
    /// - Read-only helper.
    fn get_owner(env: Env) -> Option<Address> {
        read_owner(&env)
    }

    /// Return the configured registry contract address, if set.
    ///
    /// Effects:
    /// - Reads registry reference from storage.
    ///
    /// Notes:
    /// - Read-only helper.
    fn get_registry(env: Env) -> Option<Address> {
        read_registry(&env)
    }

    /// Return the configured fee manager contract address, if set.
    ///
    /// Effects:
    /// - Reads fee manager reference from storage.
    ///
    /// Notes:
    /// - Read-only helper.
    fn get_fee_manager(env: Env) -> Option<Address> {
        read_fee_manager(&env)
    }

    /// Return the configured social router contract address, if set.
    ///
    /// Effects:
    /// - Reads social router reference from storage.
    ///
    /// Notes:
    /// - Read-only helper.
    fn get_social_router(env: Env) -> Option<Address> {
        read_social_router(&env)
    }

    /// Return the configured factory contract address, if set.
    ///
    /// Effects:
    /// - Reads factory reference from storage.
    ///
    /// Notes:
    /// - Read-only helper.
    fn get_factory(env: Env) -> Option<Address> {
        read_factory(&env)
    }

    /// Synchronizes wallet protocol dependencies from the currently configured factory.
    ///
    /// SECURITY:
    /// - Dependencies are not accepted from caller input.
    /// - Reads approved protocol addresses directly from the trusted factory.
    /// - Keeps existing wallets aligned with current protocol configuration.
    /// - Synchronization is authenticated and nonce protected.
    /// - Updates only local dependency references and does not modify factory state.
    fn sync_protocol_dependencies(
        env: Env,
        passkey_sig: Option<PasskeySignature>,
        valid_until_ledger: u32,
    ) -> Result<(), WalletError> {
        let factory = read_factory(&env).ok_or(WalletError::FactoryNotFound)?;

        let challenge = compute_tx_nonce(
            &env,
            String::from_str(&env, "sync_protocol_dependencies"),
            vec![&env],
            valid_until_ledger,
        )?;

        owner_require_auth(env.clone(), challenge, passkey_sig)?;

        let dependencies: ProtocolDependencies = env.invoke_contract(
            &factory,
            &Symbol::new(&env, "get_protocol_dependencies"),
            vec![&env],
        );

        let old_registry = read_registry(&env).ok_or(WalletError::RegistryNotFound)?;
        let old_fee_manager = read_fee_manager(&env).ok_or(WalletError::FeeManagerNotFound)?;
        let old_social_router =
            read_social_router(&env).ok_or(WalletError::SocialRouterNotFound)?;

        write_registry(&env, &dependencies.registry);
        write_social_router(&env, &dependencies.social_router);
        write_fee_manager(&env, &dependencies.fee_manager);

        events::SyncProtocolDependenciesEvent {
            wallet: env.current_contract_address(),

            old_registry,
            old_fee_manager,
            old_social_router,
            new_registry: dependencies.registry,
            new_fee_manager: dependencies.fee_manager,
            new_social_router: dependencies.social_router,
        }
        .publish(&env);

        increment_nonce(&env);
        Ok(())
    }

    // ---------------------------------------------------------------------
    // Contract upgrade
    // ---------------------------------------------------------------------

    /// Upgrade the current contract to the latest factory-approved wasm.
    ///
    /// Auth:
    /// - Requires owner authorization through the wallet auth flow.
    ///
    /// Effects:
    /// - Retrieves the approved wallet wasm hash from the factory.
    /// - Replaces the currently deployed contract code with that version.
    ///
    /// Notes:
    /// - Authorization payload is bound to the target wasm hash.
    /// - Replay protection is enforced through the wallet authorization flow.
    fn upgrade(
        env: Env,
        passkey_sig: Option<PasskeySignature>,
        valid_until_ledger: u32,
    ) -> Result<(), WalletError> {
        // Load the factory address that controls the approved wallet wasm version.
        let factory = read_factory(&env).ok_or(WalletError::FactoryNotFound)?;

        // Fetch the currently approved wallet wasm hash from the factory.
        let wasm: BytesN<32> = env
            .invoke_contract::<Option<BytesN<32>>>(
                &factory,
                &Symbol::new(&env, "get_wallet_wasm_hash"),
                vec![&env],
            )
            .ok_or(WalletError::WalletVersionNotFound)?;

        // Bind owner authorization to this specific upgrade action and wasm hash.
        let args: Vec<Val> = vec![&env, wasm.clone().into_val(&env)];
        let challenge = compute_tx_nonce(
            &env,
            String::from_str(&env, "upgrade"),
            args,
            valid_until_ledger,
        )?;

        owner_require_auth(env.clone(), challenge, passkey_sig)?;

        // Upgrade this wallet to the factory-approved wasm.
        env.deployer().update_current_contract_wasm(wasm);
        increment_nonce(&env);

        Ok(())
    }
}
