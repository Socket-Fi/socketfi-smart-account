use soroban_sdk::{
    auth::{Context, ContractContext},
    contracttype,
    crypto::Hash,
    xdr::ToXdr,
    Address, Bytes, BytesN, Env, Symbol, TryIntoVal, Vec,
};

use socketfi_shared::{
    account_error::AccountError,
    constants::{
        APPROVE_FN, BURN_FN, MAX_CONTEXTS, MAX_PERMISSIONS, MAX_RECIPIENTS,
        MAX_SESSION_LIFETIME_LEDGERS, MAX_SPEND_LIMITS, SESSION_ID_DOMAIN, SESSION_POP_DOMAIN,
        SESSION_VERSION, TRANSFER_FN,
    },
    key_types::{EvmSignature, PasskeySignature, StellarSignature},
};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionDataKey {
    Epoch,
    Policy(BytesN<32>),
}

#[contracttype]
#[derive(Clone)]
pub enum AccountAuth {
    Passkey(PasskeySignature),
    Stellar(StellarSignature),
    Evm(EvmSignature),
    Session(SessionAuthorization),
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionAuthorization {
    pub policy_id: BytesN<32>,
    pub signature: BytesN<64>,
}

/// Allows exactly one Soroban contract function.
/// Arguments remain dynamic and are committed by the signed Soroban auth payload.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolPermission {
    pub contract: Address,
    pub function: Symbol,
}

/// Input form. Mutable accounting is intentionally excluded.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetSpendLimitInput {
    pub asset: Address,
    pub recipients: Vec<Address>,
    pub max_per_call: i128,
    pub max_total: i128,
}

/// Stored form with contract-controlled accounting.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetSpendLimit {
    pub asset: Address,
    pub recipients: Vec<Address>,
    pub max_per_call: i128,
    pub max_total: i128,
    pub spent: i128,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionPolicyInput {
    pub salt: BytesN<32>,
    pub delegate: BytesN<32>, // raw Ed25519 public key
    pub valid_after_ledger: u32,
    pub expires_at_ledger: u32,
    pub max_uses: Option<u32>,
    pub permissions: Vec<ProtocolPermission>,
    pub spend_limits: Vec<AssetSpendLimitInput>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionPolicy {
    pub version: u32,
    pub policy_id: BytesN<32>,
    pub delegate: BytesN<32>,
    pub valid_after_ledger: u32,
    pub expires_at_ledger: u32,
    pub epoch: u64,
    pub max_uses: Option<u32>,
    pub uses: u32,
    pub permissions: Vec<ProtocolPermission>,
    pub spend_limits: Vec<AssetSpendLimit>,
}

pub fn read_session_epoch(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get(&SessionDataKey::Epoch)
        .unwrap_or(0)
}

pub fn increment_session_epoch(env: &Env) -> Result<u64, AccountError> {
    let next = read_session_epoch(env)
        .checked_add(1)
        .ok_or(AccountError::ArithmeticOverflow)?;

    env.storage().instance().set(&SessionDataKey::Epoch, &next);

    Ok(next)
}

pub fn read_session(env: &Env, policy_id: &BytesN<32>) -> Option<SessionPolicy> {
    env.storage()
        .temporary()
        .get(&SessionDataKey::Policy(policy_id.clone()))
}

pub fn remove_session(env: &Env, policy_id: &BytesN<32>) -> bool {
    let key = SessionDataKey::Policy(policy_id.clone());

    if !env.storage().temporary().has(&key) {
        return false;
    }

    env.storage().temporary().remove(&key);
    true
}

fn session_exists(env: &Env, policy_id: &BytesN<32>) -> bool {
    env.storage()
        .temporary()
        .has(&SessionDataKey::Policy(policy_id.clone()))
}

fn write_session(env: &Env, policy: &SessionPolicy) {
    let key = SessionDataKey::Policy(policy.policy_id.clone());
    env.storage().temporary().set(&key, policy);

    // TTL is cleanup only. Authorization always checks the absolute expiry.
    let remaining = policy
        .expires_at_ledger
        .saturating_sub(env.ledger().sequence());

    if remaining > 0 {
        let ttl = remaining.saturating_add(1);
        env.storage().temporary().extend_ttl(&key, ttl, ttl);
    }
}

pub fn derive_policy_id(env: &Env, input: &SessionPolicyInput) -> BytesN<32> {
    let mut payload = Bytes::from_slice(env, SESSION_ID_DOMAIN);
    payload.append(&env.current_contract_address().to_xdr(env));
    payload.append(&input.to_xdr(env));
    env.crypto().sha256(&payload).into()
}

pub fn build_delegate_pop_challenge(env: &Env, input: &SessionPolicyInput) -> BytesN<32> {
    let mut payload = Bytes::from_slice(env, SESSION_POP_DOMAIN);
    payload.append(&env.current_contract_address().to_xdr(env));
    payload.append(&input.to_xdr(env));
    env.crypto().sha256(&payload).into()
}

fn verify_delegate_pop(env: &Env, input: &SessionPolicyInput, pop: &BytesN<64>) {
    let challenge = build_delegate_pop_challenge(env, input);
    env.crypto()
        .ed25519_verify(&input.delegate, &challenge.into(), pop);
}

fn contains_recipient(recipients: &Vec<Address>, recipient: &Address) -> bool {
    for value in recipients.iter() {
        if value == *recipient {
            return true;
        }
    }
    false
}

fn permission_exists(
    permissions: &Vec<ProtocolPermission>,
    contract: &Address,
    function: &Symbol,
) -> bool {
    for permission in permissions.iter() {
        if permission.contract == *contract && permission.function == *function {
            return true;
        }
    }
    false
}

fn is_limited_asset(spend_limits: &Vec<AssetSpendLimit>, contract: &Address) -> bool {
    for limit in spend_limits.iter() {
        if limit.asset == *contract {
            return true;
        }
    }
    false
}

fn validate_permissions(env: &Env, input: &SessionPolicyInput) -> Result<(), AccountError> {
    let account = env.current_contract_address();

    for permission in input.permissions.iter() {
        if permission.contract == account {
            return Err(AccountError::SessionUnauthorized);
        }

        // Never delegate open-ended asset authority or destructive asset calls.
        if permission.function == APPROVE_FN || permission.function == BURN_FN {
            return Err(AccountError::InvalidSessionPolicy);
        }
    }

    // Reject duplicate contract/function permissions.
    for i in 0..input.permissions.len() {
        let left = input.permissions.get_unchecked(i);
        for j in (i + 1)..input.permissions.len() {
            let right = input.permissions.get_unchecked(j);
            if left == right {
                return Err(AccountError::InvalidSessionPolicy);
            }
        }
    }

    Ok(())
}

fn validate_spend_limits(env: &Env, input: &SessionPolicyInput) -> Result<(), AccountError> {
    let account = env.current_contract_address();

    for limit in input.spend_limits.iter() {
        if limit.asset == account
            || limit.recipients.is_empty()
            || limit.recipients.len() > MAX_RECIPIENTS
            || limit.max_per_call <= 0
            || limit.max_total <= 0
            || limit.max_per_call > limit.max_total
        {
            return Err(AccountError::InvalidSessionPolicy);
        }
    }

    // Keep v1 deterministic: only one spend-limit record per asset.
    for i in 0..input.spend_limits.len() {
        let left = input.spend_limits.get_unchecked(i);
        for j in (i + 1)..input.spend_limits.len() {
            let right = input.spend_limits.get_unchecked(j);
            if left.asset == right.asset {
                return Err(AccountError::InvalidSessionPolicy);
            }
        }
    }

    Ok(())
}

pub fn validate_new_session_policy(
    env: &Env,
    input: &SessionPolicyInput,
) -> Result<BytesN<32>, AccountError> {
    let current = env.ledger().sequence();

    if input.permissions.len() > MAX_PERMISSIONS {
        return Err(AccountError::InvalidSessionPolicy);
    }

    if input.spend_limits.len() > MAX_SPEND_LIMITS {
        return Err(AccountError::InvalidSessionPolicy);
    }

    if input.permissions.is_empty() && input.spend_limits.is_empty() {
        return Err(AccountError::InvalidSessionPolicy);
    }

    if input.expires_at_ledger <= current || input.expires_at_ledger <= input.valid_after_ledger {
        return Err(AccountError::InvalidSessionPolicy);
    }

    let lifetime = input
        .expires_at_ledger
        .checked_sub(input.valid_after_ledger)
        .ok_or(AccountError::InvalidSessionPolicy)?;

    if lifetime > MAX_SESSION_LIFETIME_LEDGERS {
        return Err(AccountError::InvalidSessionPolicy);
    }

    if matches!(input.max_uses, Some(0)) {
        return Err(AccountError::InvalidSessionPolicy);
    }

    validate_permissions(env, input)?;
    validate_spend_limits(env, input)?;

    let policy_id = derive_policy_id(env, input);

    if session_exists(env, &policy_id) {
        return Err(AccountError::SessionAlreadyExists);
    }

    Ok(policy_id)
}

// pub fn validate_new_session_policy(
//     env: &Env,
//     input: &SessionPolicyInput,
// ) -> Result<BytesN<32>, AccountError> {
//     let current = env.ledger().sequence();

//     if input.permissions.is_empty() || input.permissions.len() > MAX_PERMISSIONS {
//         return Err(AccountError::InvalidSessionPolicy);
//     }

//     if input.spend_limits.len() > MAX_SPEND_LIMITS {
//         return Err(AccountError::InvalidSessionPolicy);
//     }

//     // Allow sessions whose start ledger is already reached.
//     // Only reject sessions that are already expired or whose
//     // expiry does not come after their declared start.
//     if input.expires_at_ledger <= current || input.expires_at_ledger <= input.valid_after_ledger {
//         return Err(AccountError::InvalidSessionPolicy);
//     }

//     let lifetime = input
//         .expires_at_ledger
//         .checked_sub(input.valid_after_ledger)
//         .ok_or(AccountError::InvalidSessionPolicy)?;

//     if lifetime > MAX_SESSION_LIFETIME_LEDGERS {
//         return Err(AccountError::InvalidSessionPolicy);
//     }

//     if matches!(input.max_uses, Some(0)) {
//         return Err(AccountError::InvalidSessionPolicy);
//     }

//     validate_permissions(env, input)?;
//     validate_spend_limits(env, input)?;

//     let policy_id = derive_policy_id(env, input);

//     if session_exists(env, &policy_id) {
//         return Err(AccountError::SessionAlreadyExists);
//     }

//     Ok(policy_id)
// }

/// Call only after `env.current_contract_address().require_auth()` succeeds.
pub fn create_session_policy(
    env: &Env,
    input: SessionPolicyInput,
    delegate_pop: BytesN<64>,
) -> Result<BytesN<32>, AccountError> {
    let policy_id = validate_new_session_policy(env, &input)?;
    verify_delegate_pop(env, &input, &delegate_pop);

    let mut stored_limits = Vec::new(env);
    for limit in input.spend_limits.iter() {
        stored_limits.push_back(AssetSpendLimit {
            asset: limit.asset,
            recipients: limit.recipients,
            max_per_call: limit.max_per_call,
            max_total: limit.max_total,
            spent: 0,
        });
    }

    let policy = SessionPolicy {
        version: SESSION_VERSION,
        policy_id: policy_id.clone(),
        delegate: input.delegate,
        valid_after_ledger: input.valid_after_ledger,
        expires_at_ledger: input.expires_at_ledger,
        epoch: read_session_epoch(env),
        max_uses: input.max_uses,
        uses: 0,
        permissions: input.permissions,
        spend_limits: stored_limits,
    };

    write_session(env, &policy);

    // env.events().publish(
    //     (symbol_short!("sess_new"), policy_id.clone()),
    //     (
    //         policy.delegate,
    //         policy.valid_after_ledger,
    //         policy.expires_at_ledger,
    //         policy.max_uses,
    //     ),
    // );

    Ok(policy_id)
}

fn validate_session_lifetime(env: &Env, policy: &SessionPolicy) -> Result<(), AccountError> {
    if policy.version != SESSION_VERSION {
        return Err(AccountError::InvalidSessionPolicy);
    }

    let current = env.ledger().sequence();

    if current < policy.valid_after_ledger {
        return Err(AccountError::SessionUnavailable);
    }

    if current > policy.expires_at_ledger {
        return Err(AccountError::SessionUnavailable);
    }

    if policy.epoch != read_session_epoch(env) {
        return Err(AccountError::SessionRevoked);
    }

    if let Some(max_uses) = policy.max_uses {
        if policy.uses >= max_uses {
            return Err(AccountError::SessionUnavailable);
        }
    }

    Ok(())
}

fn authorize_transfer(
    env: &Env,
    account: &Address,
    context: &ContractContext,
    policy: &mut SessionPolicy,
) -> Result<(), AccountError> {
    if context.args.len() != 3 {
        return Err(AccountError::InvalidSessionPolicy);
    }

    let from: Address = context
        .args
        .get(0)
        .ok_or(AccountError::InvalidSessionPolicy)?
        .try_into_val(env)
        .map_err(|_| AccountError::InvalidSessionPolicy)?;

    let to: Address = context
        .args
        .get(1)
        .ok_or(AccountError::InvalidSessionPolicy)?
        .try_into_val(env)
        .map_err(|_| AccountError::InvalidSessionPolicy)?;

    let amount: i128 = context
        .args
        .get(2)
        .ok_or(AccountError::InvalidSessionPolicy)?
        .try_into_val(env)
        .map_err(|_| AccountError::InvalidSessionPolicy)?;

    if from != *account || amount <= 0 {
        return Err(AccountError::InvalidSessionPolicy);
    }

    for index in 0..policy.spend_limits.len() {
        let mut limit = policy.spend_limits.get_unchecked(index);

        if limit.asset != context.contract || !contains_recipient(&limit.recipients, &to) {
            continue;
        }

        if amount > limit.max_per_call {
            return Err(AccountError::SessionLimitExceeded);
        }

        let next = limit
            .spent
            .checked_add(amount)
            .ok_or(AccountError::ArithmeticOverflow)?;

        if next > limit.max_total {
            return Err(AccountError::SessionLimitExceeded);
        }

        limit.spent = next;
        policy.spend_limits.set(index, limit);
        return Ok(());
    }

    Err(AccountError::SessionUnauthorized)
}

fn authorize_contexts(
    env: &Env,
    policy: &mut SessionPolicy,
    contexts: Vec<Context>,
) -> Result<(), AccountError> {
    if contexts.is_empty() || contexts.len() > MAX_CONTEXTS {
        return Err(AccountError::InvalidSessionPolicy);
    }

    let account = env.current_contract_address();

    for context in contexts.iter() {
        let contract_context = match context {
            Context::Contract(value) => value,

            Context::CreateContractHostFn(_) | Context::CreateContractWithCtorHostFn(_) => {
                return Err(AccountError::SessionUnauthorized);
            }
        };

        // A session may never manage the account contract itself.
        if contract_context.contract == account {
            return Err(AccountError::SessionUnauthorized);
        }

        // Never permit delegated allowance or destructive asset calls.
        if contract_context.fn_name == APPROVE_FN || contract_context.fn_name == BURN_FN {
            return Err(AccountError::SessionUnauthorized);
        }

        // Treat transfer as an asset transfer only when the exact
        // token contract has an explicitly configured spend limit.
        let limited_asset_transfer = contract_context.fn_name == TRANSFER_FN
            && is_limited_asset(&policy.spend_limits, &contract_context.contract);

        if limited_asset_transfer {
            authorize_transfer(env, &account, &contract_context, policy)?;

            continue;
        }

        // Non-transfer calls must match an explicit protocol permission.
        if !permission_exists(
            &policy.permissions,
            &contract_context.contract,
            &contract_context.fn_name,
        ) {
            return Err(AccountError::SessionUnauthorized);
        }
    }

    Ok(())
}

pub fn authorize_session(
    env: &Env,
    signature_payload: &Hash<32>,
    authorization: SessionAuthorization,
    contexts: Vec<Context>,
) -> Result<(), AccountError> {
    let mut policy =
        read_session(env, &authorization.policy_id).ok_or(AccountError::SessionNotFound)?;

    validate_session_lifetime(env, &policy)?;

    // Delegate signs the exact Soroban authorization payload.
    env.crypto().ed25519_verify(
        &policy.delegate,
        &signature_payload.clone().into(),
        &authorization.signature,
    );

    authorize_contexts(env, &mut policy, contexts)?;

    policy.uses = policy
        .uses
        .checked_add(1)
        .ok_or(AccountError::ArithmeticOverflow)?;

    write_session(env, &policy);
    Ok(())
}
