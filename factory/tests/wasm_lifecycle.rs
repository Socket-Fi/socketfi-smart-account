//! Local Soroban-host execution of both release WASMs; no RPC or deployment.
use k256::ecdsa::SigningKey as EvmKey;
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey as PasskeyKey};
use socketfi_shared::{
    account_error::AccountError,
    bls::g1_group_gen_point,
    constants::{ADD_BINDING_DOMAIN, DST, ETH_PERSONAL_SIGN_PREFIX_32},
    key_types::{
        AccountSigner, AuthBindings, BindingChangeResult, BlsKeyWithPoP, EvmSignature,
        OwnerSignature, PasskeyAccountSigner, PasskeySignature,
    },
    webauthn_helper::base64url_encode_no_pad,
};
use soroban_sdk::{
    crypto::bls12_381::{Fr, G1Affine},
    testutils::{Address as _, Ledger},
    xdr::ToXdr,
    Address, Bytes, BytesN, Env, IntoVal, String, Symbol, Val, Vec, U256,
};

fn evm_address(env: &Env, key: &EvmKey) -> BytesN<20> {
    let public = key.verifying_key().to_encoded_point(false);
    let hash = env
        .crypto()
        .keccak256(&Bytes::from_slice(env, &public.as_bytes()[1..]));
    BytesN::from_array(env, &hash.to_array()[12..].try_into().unwrap())
}

fn evm_sign(env: &Env, key: &EvmKey, payload: &BytesN<32>) -> EvmSignature {
    let mut message = Bytes::from_slice(env, ETH_PERSONAL_SIGN_PREFIX_32);
    message.append(&payload.clone().into());
    let hash = env.crypto().keccak256(&message);
    let (signature, recovery_id) = key.sign_prehash_recoverable(&hash.to_array()).unwrap();
    EvmSignature {
        signature: BytesN::from_array(env, &signature.to_bytes().into()),
        recovery_id: recovery_id.to_byte() as u32,
    }
}

fn passkey_public(env: &Env, key: &PasskeyKey) -> BytesN<65> {
    BytesN::from_array(
        env,
        &key.verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .unwrap(),
    )
}

fn passkey_sign(
    env: &Env,
    key: &PasskeyKey,
    hash: &BytesN<32>,
    rp: &BytesN<32>,
) -> PasskeySignature {
    let mut client = Bytes::from_slice(env, b"{\"type\":\"webauthn.get\",\"challenge\":\"");
    client.append(&base64url_encode_no_pad(env, &hash.clone().into()));
    client.append(&Bytes::from_slice(
        env,
        b"\",\"origin\":\"https://socket.fi\"}",
    ));
    let mut authenticator_data: Bytes = rp.clone().into();
    authenticator_data.append(&Bytes::from_slice(env, &[0x05, 0, 0, 0, 0]));
    let mut message = authenticator_data.clone();
    message.extend_from_array(&env.crypto().sha256(&client).to_array());
    let signature: Signature = key
        .sign_prehash(&env.crypto().sha256(&message).to_array())
        .unwrap();
    let signature = signature.normalize_s().unwrap_or(signature);
    PasskeySignature {
        signature: BytesN::from_array(env, &signature.to_bytes().into()),
        client_data_json: client,
        authenticator_data,
    }
}

fn bls_public_keys(env: &Env) -> Vec<BytesN<96>> {
    let bls = env.crypto().bls12_381();
    let generator = -G1Affine::from_bytes(g1_group_gen_point(env));
    let mut keys = Vec::new(env);
    for scalar in [1, 2] {
        keys.push_back(
            bls.g1_mul(&generator, &Fr::from_u256(U256::from_u32(env, scalar)))
                .to_bytes(),
        );
    }
    keys
}

fn bls_proofs(env: &Env, challenge: &BytesN<32>) -> Vec<BlsKeyWithPoP> {
    let bls = env.crypto().bls12_381();
    let message = bls.hash_to_g2(
        &challenge.clone().into(),
        &Bytes::from_slice(env, DST.as_bytes()),
    );
    let keys = bls_public_keys(env);
    let mut proofs = Vec::new(env);
    for (index, scalar) in [1, 2].iter().enumerate() {
        proofs.push_back(BlsKeyWithPoP {
            key: keys.get_unchecked(index as u32),
            sig: bls
                .g2_mul(&message, &Fr::from_u256(U256::from_u32(env, *scalar)))
                .to_bytes(),
        });
    }
    proofs
}

fn load_wasm(name: &str) -> std::vec::Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../target/wasm32v1-none/release")
        .join(format!("{name}.wasm"));
    std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "Build release WASMs with `make build` first: {}: {error}",
            path.display()
        )
    })
}

fn register_factory(env: &Env) -> Address {
    let factory_wasm = load_wasm("socketfi_factory");
    let factory_hash = env.deployer().upload_contract_wasm(factory_wasm.as_slice());
    let account_hash = env
        .deployer()
        .upload_contract_wasm(load_wasm("socketfi_account").as_slice());
    let admin = Address::generate(env);
    let voters = Vec::from_array(
        env,
        [
            admin.clone(),
            Address::generate(env),
            Address::generate(env),
        ],
    );
    env.register(
        factory_wasm.as_slice(),
        (
            admin,
            String::from_str(env, "socket.fi"),
            Symbol::new(env, "TESTNET"),
            factory_hash,
            account_hash,
            voters,
        ),
    )
}

fn create_evm_account(env: &Env, factory: &Address, owner: &EvmKey) -> Address {
    let nonce = BytesN::from_array(env, &[11; 32]);
    let network = Symbol::new(env, "TESTNET");
    let expiry = env.ledger().sequence() + 120;
    let address = evm_address(env, owner);
    let challenge: BytesN<32> = env.invoke_contract(
        factory,
        &Symbol::new(env, "get_pop_challenge"),
        (
            None::<BytesN<65>>,
            None::<BytesN<32>>,
            Some(address.clone()),
            bls_public_keys(env),
            nonce.clone(),
            network.clone(),
            Vec::<Address>::new(env),
            expiry,
        )
            .into_val(env),
    );
    let args: Vec<Val> = (
        None::<BytesN<65>>,
        None::<PasskeySignature>,
        None::<BytesN<32>>,
        None::<Address>,
        Some(address),
        Some(evm_sign(env, owner, &challenge)),
        bls_proofs(env, &challenge),
        nonce.clone(),
        network,
        Vec::<Address>::new(env),
        expiry,
    )
        .into_val(env);
    let create = Symbol::new(env, "create_account");

    let mut tampered = args.clone();
    tampered.set(10, (expiry - 1).into_val(env));
    assert!(env
        .try_invoke_contract::<Address, AccountError>(factory, &create, tampered)
        .is_err());

    let account: Address = env.invoke_contract(factory, &create, args.clone());
    assert_eq!(
        env.try_invoke_contract::<Address, AccountError>(factory, &create, args),
        Err(Ok(AccountError::NonceAlreadyUsed))
    );
    let registered: bool = env.invoke_contract(
        factory,
        &Symbol::new(env, "is_registered_account"),
        (account.clone(),).into_val(env),
    );
    assert!(registered);
    account
}

fn add_passkey_challenge(
    env: &Env,
    account: &Address,
    public_key: &BytesN<65>,
    live_until_ledger: u32,
) -> BytesN<32> {
    let mut commitment = Bytes::from_slice(env, &[0]);
    commitment.append(&public_key.clone().into());
    let commitment_hash: BytesN<32> = env.crypto().sha256(&commitment).into();

    let mut payload = Bytes::from_slice(env, ADD_BINDING_DOMAIN);
    payload.append(&env.ledger().network_id().into());
    payload.append(&account.to_xdr(env));
    payload.push_back(0); // Passkey target.
    payload.push_back(0); // No current binding.
    payload.append(&Bytes::from_slice(env, &[0; 32]));
    payload.push_back(1); // Replacement is present.
    payload.append(&commitment_hash.into());
    payload.append(&Bytes::from_slice(env, &0u64.to_be_bytes()));
    payload.append(&Bytes::from_slice(env, &live_until_ledger.to_be_bytes()));
    env.crypto().sha256(&payload).into()
}

#[test]
#[ignore = "build both release WASMs first with make build"]
fn factory_creation_and_multi_binding_lifecycle() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    env.ledger().with_mut(|ledger| {
        ledger.sequence_number = 1;
        ledger.network_id = [42; 32];
    });
    let factory = register_factory(&env);
    let owner = EvmKey::from_slice(&[1; 32]).unwrap();
    let attacker = EvmKey::from_slice(&[2; 32]).unwrap();
    let passkey = PasskeyKey::from_slice(&[3; 32]).unwrap();
    let account = create_evm_account(&env, &factory, &owner);
    let rp: BytesN<32> = env
        .crypto()
        .sha256(&Bytes::from_slice(&env, b"socket.fi"))
        .into();

    let before: AuthBindings =
        env.invoke_contract(&account, &Symbol::new(&env, "get_bindings"), Vec::new(&env));
    assert_eq!(before.evm, Some(evm_address(&env, &owner)));
    assert!(before.passkey.is_none());

    let expiry = 50;
    let public_key = passkey_public(&env, &passkey);
    let challenge = add_passkey_challenge(&env, &account, &public_key, expiry);
    let signer = AccountSigner::Passkey(PasskeyAccountSigner {
        public_key: public_key.clone(),
        pop_signature: passkey_sign(&env, &passkey, &challenge, &rp),
    });
    let bad_approvals = Vec::from_array(
        &env,
        [OwnerSignature::Evm(evm_sign(&env, &attacker, &challenge))],
    );
    assert!(env
        .try_invoke_contract::<BindingChangeResult, AccountError>(
            &account,
            &Symbol::new(&env, "add_binding"),
            (&signer, bad_approvals, expiry).into_val(&env),
        )
        .is_err());

    let approvals = Vec::from_array(
        &env,
        [OwnerSignature::Evm(evm_sign(&env, &owner, &challenge))],
    );
    let result: BindingChangeResult = env.invoke_contract(
        &account,
        &Symbol::new(&env, "add_binding"),
        (&signer, approvals, expiry).into_val(&env),
    );
    assert_eq!(result.auth_config_nonce, 1);
    assert_eq!(result.session_epoch, 0);

    let after: AuthBindings =
        env.invoke_contract(&account, &Symbol::new(&env, "get_bindings"), Vec::new(&env));
    assert_eq!(after.evm, Some(evm_address(&env, &owner)));
    assert_eq!(after.passkey, Some(public_key));
}

#[test]
#[ignore = "build both release WASMs first with make build"]
fn creation_challenge_expires_and_is_network_bound() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    env.ledger().set_sequence_number(1_000);
    let factory = register_factory(&env);
    let nonce = BytesN::from_array(&env, &[22; 32]);
    let key = PasskeyKey::from_slice(&[4; 32]).unwrap();
    let args = (
        Some(passkey_public(&env, &key)),
        None::<BytesN<32>>,
        None::<BytesN<20>>,
        bls_public_keys(&env),
        nonce,
        Symbol::new(&env, "TESTNET"),
        Vec::<Address>::new(&env),
        1_120u32,
    )
        .into_val(&env);
    let challenge: BytesN<32> =
        env.invoke_contract(&factory, &Symbol::new(&env, "get_pop_challenge"), args);
    assert_ne!(challenge, BytesN::from_array(&env, &[0; 32]));

    env.ledger().set_sequence_number(1_121);
    let expired = (
        Some(passkey_public(&env, &key)),
        None::<BytesN<32>>,
        None::<BytesN<20>>,
        bls_public_keys(&env),
        BytesN::from_array(&env, &[23; 32]),
        Symbol::new(&env, "TESTNET"),
        Vec::<Address>::new(&env),
        1_120u32,
    )
        .into_val(&env);
    assert_eq!(
        env.try_invoke_contract::<BytesN<32>, AccountError>(
            &factory,
            &Symbol::new(&env, "get_pop_challenge"),
            expired,
        ),
        Err(Ok(AccountError::CreationProofExpired))
    );
}
