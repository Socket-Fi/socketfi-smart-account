//! Local Soroban-host execution of both release WASMs; no RPC or deployment.
use k256::ecdsa::SigningKey as EvmKey;
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey as PasskeyKey};
use socketfi_shared::{
    account_error::AccountError,
    bls::g1_group_gen_point,
    constants::{DST, ETH_PERSONAL_SIGN_PREFIX_32, ROTATION_DOMAIN},
    key_types::{
        AccountCommitment, AccountSigner, BlsKeyWithPoP, EvmSignature, PasskeyAccountSigner,
        PasskeySignature,
    },
    webauthn_helper::base64url_encode_no_pad,
};
use soroban_sdk::{
    contracttype,
    crypto::bls12_381::{Fr, G1Affine},
    testutils::{Address as _, Ledger},
    xdr::{self, ToXdr, WriteXdr},
    Address, Bytes, BytesN, Env, IntoVal, String, Symbol, TryFromVal, Val, Vec, U256,
};

#[contracttype]
#[derive(Clone)]
enum OwnerAuth {
    Evm(EvmSignature),
    Passkey(PasskeySignature),
}

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
    let (sig, recovery_id) = key.sign_prehash_recoverable(&hash.to_array()).unwrap();
    EvmSignature {
        signature: BytesN::from_array(env, &sig.to_bytes().into()),
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
    let mut auth: Bytes = rp.clone().into();
    auth.append(&Bytes::from_slice(env, &[0x05, 0, 0, 0, 0]));
    let mut message = auth.clone();
    message.extend_from_array(&env.crypto().sha256(&client).to_array());
    let sig: Signature = key
        .sign_prehash(&env.crypto().sha256(&message).to_array())
        .unwrap();
    let sig = sig.normalize_s().unwrap_or(sig);
    PasskeySignature {
        signature: BytesN::from_array(env, &sig.to_bytes().into()),
        client_data_json: client,
        authenticator_data: auth,
    }
}

fn bls_proofs(env: &Env, challenge: &BytesN<32>) -> Vec<BlsKeyWithPoP> {
    let bls = env.crypto().bls12_381();
    let generator = -G1Affine::from_bytes(g1_group_gen_point(env));
    let message = bls.hash_to_g2(
        &challenge.clone().into(),
        &Bytes::from_slice(env, DST.as_bytes()),
    );
    let mut proofs = Vec::new(env);
    for scalar in [1, 2] {
        let scalar = Fr::from_u256(U256::from_u32(env, scalar));
        proofs.push_back(BlsKeyWithPoP {
            key: bls.g1_mul(&generator, &scalar).to_bytes(),
            sig: bls.g2_mul(&message, &scalar).to_bytes(),
        });
    }
    proofs
}

fn load_wasm(name: &str) -> std::vec::Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../target/wasm32v1-none/release")
        .join(format!("{name}.wasm"));
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "Build release WASMs with `make build` first: {}: {e}",
            path.display()
        )
    })
}

fn create_evm_account(env: &Env, key: &EvmKey) -> (Address, BytesN<32>) {
    let wasm_hash = env
        .deployer()
        .upload_contract_wasm(load_wasm("socketfi_account").as_slice());
    let admin = Address::generate(env);
    let rp = String::from_str(env, "socket.fi");
    let factory = env.register(
        load_wasm("socketfi_factory").as_slice(),
        (admin, rp, wasm_hash),
    );
    let nonce = BytesN::from_array(env, &[11; 32]);
    let network = Symbol::new(env, "TESTNET");
    let challenge: BytesN<32> = env.invoke_contract(
        &factory,
        &Symbol::new(env, "get_pop_challenge"),
        (&nonce, &network).into_val(env),
    );
    let address: Address = env.invoke_contract(
        &factory,
        &Symbol::new(env, "create_account"),
        (
            None::<BytesN<65>>,
            None::<PasskeySignature>,
            None::<BytesN<32>>,
            None::<Address>,
            Some(evm_address(env, key)),
            Some(evm_sign(env, key, &challenge)),
            bls_proofs(env, &challenge),
            nonce,
            network,
            Vec::<Address>::new(env),
        )
            .into_val(env),
    );
    let rp_hash = env
        .crypto()
        .sha256(&Bytes::from_slice(env, b"socket.fi"))
        .into();
    (address, rp_hash)
}

fn rotation_signer(
    env: &Env,
    account: &Address,
    key: &PasskeyKey,
    rp: &BytesN<32>,
    expiry: u32,
) -> AccountSigner {
    let public_key = passkey_public(env, key);
    let mut payload = Bytes::from_slice(env, ROTATION_DOMAIN);
    payload.append(&env.ledger().network_id().to_xdr(env));
    payload.append(&account.to_xdr(env));
    payload.append(&expiry.to_xdr(env));
    payload.append(&AccountCommitment::Passkey(public_key.clone()).to_xdr(env));
    let challenge = env.crypto().sha256(&payload).into();
    AccountSigner::Passkey(PasskeyAccountSigner {
        public_key,
        pop_signature: passkey_sign(env, key, &challenge, rp),
    })
}

fn authorize(
    env: &Env,
    account: &Address,
    function: &str,
    args: &Vec<Val>,
    nonce: i64,
    sign: impl FnOnce(&BytesN<32>) -> OwnerAuth,
) -> xdr::SorobanAuthorizationEntry {
    let invocation = xdr::SorobanAuthorizedInvocation {
        function: xdr::SorobanAuthorizedFunction::ContractFn(xdr::InvokeContractArgs {
            contract_address: account.into(),
            function_name: function.try_into().unwrap(),
            args: args
                .iter()
                .map(|v| xdr::ScVal::try_from_val(env, &v).unwrap())
                .collect::<std::vec::Vec<_>>()
                .try_into()
                .unwrap(),
        }),
        sub_invocations: Default::default(),
    };
    let expiry = 100;
    let preimage =
        xdr::HashIdPreimage::SorobanAuthorization(xdr::HashIdPreimageSorobanAuthorization {
            network_id: xdr::Hash(env.ledger().network_id().to_array()),
            nonce,
            signature_expiration_ledger: expiry,
            invocation: invocation.clone(),
        });
    let hash = env
        .crypto()
        .sha256(&Bytes::from_slice(
            env,
            &preimage.to_xdr(xdr::Limits::none()).unwrap(),
        ))
        .into();
    let sig: Val = sign(&hash).into_val(env);
    let entry = xdr::SorobanAuthorizationEntry {
        credentials: xdr::SorobanCredentials::Address(xdr::SorobanAddressCredentials {
            address: account.into(),
            nonce,
            signature_expiration_ledger: expiry,
            signature: xdr::ScVal::try_from_val(env, &sig).unwrap(),
        }),
        root_invocation: invocation,
    };
    env.set_auths(std::slice::from_ref(&entry));
    entry
}

#[test]
#[ignore = "build both release WASMs first with make build"]
fn factory_evm_creation_and_authenticated_passkey_rotation() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    env.ledger().with_mut(|ledger| {
        ledger.sequence_number = 1;
        ledger.network_id = [42; 32];
    });
    // Fixed public test keys only; no auth mocking in this test.
    let owner = EvmKey::from_slice(&[1; 32]).unwrap();
    let attacker = EvmKey::from_slice(&[2; 32]).unwrap();
    let passkey = PasskeyKey::from_slice(&[3; 32]).unwrap();
    let (account, rp) = create_evm_account(&env, &owner);
    let get_passkey = || {
        env.invoke_contract::<Option<BytesN<65>>>(
            &account,
            &Symbol::new(&env, "get_passkey"),
            Vec::new(&env),
        )
    };
    assert!(get_passkey().is_none());
    let expiry = 50u32;

    let wrong_rp = BytesN::from_array(&env, &[8; 32]);
    let bad_signer = rotation_signer(&env, &account, &passkey, &wrong_rp, expiry);
    let bad_args = (&bad_signer, expiry).into_val(&env);
    authorize(&env, &account, "rotate_account", &bad_args, 1, |hash| {
        OwnerAuth::Evm(evm_sign(&env, &owner, hash))
    });
    assert_eq!(
        env.try_invoke_contract::<u64, AccountError>(
            &account,
            &Symbol::new(&env, "rotate_account"),
            bad_args
        ),
        Err(Ok(AccountError::InvalidRpIdHash))
    );
    assert!(get_passkey().is_none());

    let signer = rotation_signer(&env, &account, &passkey, &rp, expiry);
    let args: Vec<Val> = (&signer, expiry).into_val(&env);
    authorize(&env, &account, "rotate_account", &args, 2, |hash| {
        OwnerAuth::Evm(evm_sign(&env, &attacker, hash))
    });
    assert!(env
        .try_invoke_contract::<u64, AccountError>(
            &account,
            &Symbol::new(&env, "rotate_account"),
            args.clone()
        )
        .is_err());
    assert!(get_passkey().is_none());

    let authorization = authorize(&env, &account, "rotate_account", &args, 3, |hash| {
        OwnerAuth::Evm(evm_sign(&env, &owner, hash))
    });
    let epoch: u64 =
        env.invoke_contract(&account, &Symbol::new(&env, "rotate_account"), args.clone());
    assert_eq!(epoch, 1);
    assert_eq!(get_passkey(), Some(passkey_public(&env, &passkey)));

    env.set_auths(&[authorization]);
    assert!(env
        .try_invoke_contract::<u64, AccountError>(
            &account,
            &Symbol::new(&env, "rotate_account"),
            args
        )
        .is_err());

    let action = "revoke_all_sessions";
    let empty = Vec::new(&env);
    authorize(&env, &account, action, &empty, 4, |hash| {
        OwnerAuth::Evm(evm_sign(&env, &owner, hash))
    });
    assert!(env
        .try_invoke_contract::<u64, AccountError>(
            &account,
            &Symbol::new(&env, action),
            empty.clone()
        )
        .is_err());

    authorize(&env, &account, action, &empty, 5, |hash| {
        OwnerAuth::Passkey(passkey_sign(&env, &passkey, hash, &rp))
    });
    let next_epoch: u64 = env.invoke_contract(&account, &Symbol::new(&env, action), empty);
    assert_eq!(next_epoch, 2);
}
