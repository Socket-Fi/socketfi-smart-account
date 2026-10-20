use crate::{
    account::Account,
    account_trait::AccountTrait,
    guardians::write_paused,
    signer_management::{binding_challenge, binding_commitment, binding_exists},
};
use ed25519_dalek::{Signer as _, SigningKey as StellarKey};
use k256::ecdsa::SigningKey as EvmKey;
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey as PasskeyKey};
use socketfi_shared::{
    account_error::AccountError,
    bls::g1_group_gen_point,
    constants::{
        ADD_BINDING_DOMAIN, BLS_RECOVER_BINDING_DOMAIN, DST, ETH_PERSONAL_SIGN_PREFIX_32,
        PEER_RECOVER_BINDING_DOMAIN, REMOVE_BINDING_DOMAIN, ROTATE_BINDING_DOMAIN,
    },
    key_types::{
        AccountCommitment, AccountSigner, BindingType, BlsKeyWithPoP, BlsSignature,
        EvmAccountSigner, EvmSignature, OwnerSignature, PasskeyAccountSigner, PasskeySignature,
        StellarAccountSigner, StellarSignature,
    },
    webauthn_helper::base64url_encode_no_pad,
};
use soroban_sdk::{
    contract, contractimpl,
    crypto::bls12_381::{Fr, G1Affine},
    testutils::{Address as _, Ledger},
    Address, Bytes, BytesN, Env, String, Symbol, Vec, U256,
};

#[contract]
struct Host;
#[contractimpl]
impl Host {
    pub fn ping() {}
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
        key.verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .unwrap(),
    )
}

fn passkey_sign(
    env: &Env,
    key: &PasskeyKey,
    challenge: &BytesN<32>,
    rp: &BytesN<32>,
) -> PasskeySignature {
    let mut client = Bytes::from_slice(env, b"{\"type\":\"webauthn.get\",\"challenge\":\"");
    client.append(&base64url_encode_no_pad(env, &challenge.clone().into()));
    client.append(&Bytes::from_slice(
        env,
        b"\",\"origin\":\"https://socket.fi\"}",
    ));
    let mut auth: Bytes = rp.clone().into();
    auth.append(&Bytes::from_slice(env, &[0x05, 0, 0, 0, 0]));
    let mut message = auth.clone();
    message.extend_from_array(&env.crypto().sha256(&client).to_array());
    let signature: Signature = key
        .sign_prehash(&env.crypto().sha256(&message).to_array())
        .unwrap();
    let signature = signature.normalize_s().unwrap_or(signature);
    PasskeySignature {
        signature: BytesN::from_array(env, &signature.to_bytes().into()),
        client_data_json: client,
        authenticator_data: auth,
    }
}

fn stellar_address(env: &Env, key: &StellarKey) -> Address {
    let encoded = stellar_strkey::ed25519::PublicKey(key.verifying_key().to_bytes()).to_string();
    Address::from_string(&String::from_str(env, &encoded))
}

fn stellar_sign(env: &Env, key: &StellarKey, challenge: &BytesN<32>) -> StellarSignature {
    StellarSignature {
        signature: BytesN::from_array(env, &key.sign(&challenge.to_array()).to_bytes()),
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

fn bls_signature(env: &Env, challenge: &BytesN<32>) -> BlsSignature {
    let bls = env.crypto().bls12_381();
    let message = bls.hash_to_g2(
        &challenge.clone().into(),
        &Bytes::from_slice(env, DST.as_bytes()),
    );
    let aggregate_scalar = Fr::from_u256(U256::from_u32(env, 3));
    BlsSignature {
        signature: bls.g2_mul(&message, &aggregate_scalar).to_bytes(),
    }
}

fn initialize_passkey(env: &Env, passkey: &PasskeyKey) -> (Address, BytesN<32>) {
    env.ledger().set_sequence_number(100);
    let host = env.register(Host, ());
    let challenge = BytesN::from_array(env, &[7; 32]);
    let rp: BytesN<32> = env
        .crypto()
        .sha256(&Bytes::from_slice(env, b"socket.fi"))
        .into();
    env.as_contract(&host, || {
        Account::__constructor(
            env.clone(),
            challenge.clone(),
            Some(passkey_public(env, passkey)),
            Some(passkey_sign(env, passkey, &challenge, &rp)),
            Some(rp.clone()),
            None,
            None,
            None,
            None,
            bls_proofs(env, &challenge),
            Vec::new(env),
            BytesN::from_array(env, &[9; 32]),
            Address::generate(env),
        )
        .unwrap();
    });
    (host, rp)
}

fn get_challenge(
    env: Env,
    operation: Symbol,
    passkey: Option<BytesN<65>>,
    stellar: Option<BytesN<32>>,
    evm: Option<BytesN<20>>,
    live_until_ledger: u32,
) -> Result<BytesN<32>, AccountError> {
    let configured =
        u32::from(passkey.is_some()) + u32::from(stellar.is_some()) + u32::from(evm.is_some());
    if configured != 1 {
        return Err(AccountError::InvalidConfig);
    }
    let commitment = if let Some(value) = passkey {
        AccountCommitment::Passkey(value)
    } else if let Some(value) = stellar {
        AccountCommitment::Stellar(value)
    } else if let Some(value) = evm {
        AccountCommitment::Evm(value)
    } else {
        return Err(AccountError::InvalidConfig);
    };
    let target = match &commitment {
        AccountCommitment::Passkey(_) => BindingType::Passkey,
        AccountCommitment::Stellar(_) => BindingType::Stellar,
        AccountCommitment::Evm(_) => BindingType::Evm,
    };
    let (domain, current, replacement) = if operation == Symbol::new(&env, "add") {
        if binding_exists(&env, &target) {
            return Err(AccountError::BindingAlreadyExists);
        }
        (ADD_BINDING_DOMAIN, None, Some(commitment))
    } else if operation == Symbol::new(&env, "remove") {
        let current = binding_commitment(&env, &target).ok_or(AccountError::BindingNotFound)?;
        (REMOVE_BINDING_DOMAIN, Some(current), None)
    } else if operation == Symbol::new(&env, "peer_recover") {
        (
            PEER_RECOVER_BINDING_DOMAIN,
            binding_commitment(&env, &target),
            Some(commitment),
        )
    } else if operation == Symbol::new(&env, "bls_recover") {
        (
            BLS_RECOVER_BINDING_DOMAIN,
            binding_commitment(&env, &target),
            Some(commitment),
        )
    } else {
        (
            ROTATE_BINDING_DOMAIN,
            binding_commitment(&env, &target),
            Some(commitment),
        )
    };
    Ok(binding_challenge(
        &env,
        domain,
        target,
        current,
        replacement,
        live_until_ledger,
    ))
}

#[test]
fn binding_lifecycle_enforces_distinct_approvals_and_preserves_other_bindings() {
    let env = Env::default();
    let passkey = PasskeyKey::from_slice(&[1; 32]).unwrap();
    let (host, rp) = initialize_passkey(&env, &passkey);
    let evm = EvmKey::from_slice(&[2; 32]).unwrap();
    let expiry = 150;

    env.as_contract(&host, || {
        let challenge = get_challenge(
            env.clone(),
            Symbol::new(&env, "add"),
            None,
            None,
            Some(evm_address(&env, &evm)),
            expiry,
        )
        .unwrap();
        let signer = AccountSigner::Evm(EvmAccountSigner {
            address: evm_address(&env, &evm),
            pop_signature: evm_sign(&env, &evm, &challenge),
        });
        let approvals = Vec::from_array(
            &env,
            [OwnerSignature::Passkey(passkey_sign(
                &env, &passkey, &challenge, &rp,
            ))],
        );
        let result = Account::add_binding(env.clone(), signer, approvals, expiry).unwrap();
        assert_eq!(result.auth_config_nonce, 1);
        assert_eq!(result.session_epoch, 0);
        assert_eq!(
            Account::get_bindings(env.clone()).evm,
            Some(evm_address(&env, &evm))
        );
        assert_eq!(
            get_challenge(
                env.clone(),
                Symbol::new(&env, "add"),
                None,
                None,
                Some(evm_address(&env, &evm)),
                expiry,
            ),
            Err(AccountError::BindingAlreadyExists)
        );

        let remove_challenge = get_challenge(
            env.clone(),
            Symbol::new(&env, "remove"),
            None,
            None,
            Some(evm_address(&env, &evm)),
            expiry,
        )
        .unwrap();
        assert_eq!(
            Account::remove_binding(
                env.clone(),
                BindingType::Evm,
                OwnerSignature::Passkey(passkey_sign(&env, &passkey, &remove_challenge, &rp,)),
                expiry,
            ),
            Err(AccountError::InvalidApprovalSet)
        );
        let result = Account::remove_binding(
            env.clone(),
            BindingType::Evm,
            OwnerSignature::Evm(evm_sign(&env, &evm, &remove_challenge)),
            expiry,
        )
        .unwrap();
        assert_eq!(result.auth_config_nonce, 2);
        assert_eq!(result.session_epoch, 1);
        assert!(Account::get_bindings(env.clone()).evm.is_none());
        assert!(Account::get_bindings(env.clone()).passkey.is_some());
        assert_eq!(
            Account::remove_binding(
                env.clone(),
                BindingType::Passkey,
                OwnerSignature::Passkey(passkey_sign(&env, &passkey, &remove_challenge, &rp)),
                expiry,
            ),
            Err(AccountError::LastBindingRemoval)
        );
    });
}

#[test]
fn rotation_requires_the_target_binding_and_preserves_other_bindings() {
    let env = Env::default();
    let passkey = PasskeyKey::from_slice(&[1; 32]).unwrap();
    let replacement = PasskeyKey::from_slice(&[6; 32]).unwrap();
    let (host, rp) = initialize_passkey(&env, &passkey);
    let evm = EvmKey::from_slice(&[2; 32]).unwrap();
    let expiry = 150;

    env.as_contract(&host, || {
        let add_challenge = get_challenge(
            env.clone(),
            Symbol::new(&env, "add"),
            None,
            None,
            Some(evm_address(&env, &evm)),
            expiry,
        )
        .unwrap();
        Account::add_binding(
            env.clone(),
            AccountSigner::Evm(EvmAccountSigner {
                address: evm_address(&env, &evm),
                pop_signature: evm_sign(&env, &evm, &add_challenge),
            }),
            Vec::from_array(
                &env,
                [OwnerSignature::Passkey(passkey_sign(
                    &env,
                    &passkey,
                    &add_challenge,
                    &rp,
                ))],
            ),
            expiry,
        )
        .unwrap();

        let replacement_public = passkey_public(&env, &replacement);
        let rotate_challenge = get_challenge(
            env.clone(),
            Symbol::new(&env, "rotate"),
            Some(replacement_public.clone()),
            None,
            None,
            expiry,
        )
        .unwrap();
        let replacement_signer = AccountSigner::Passkey(PasskeyAccountSigner {
            public_key: replacement_public.clone(),
            pop_signature: passkey_sign(&env, &replacement, &rotate_challenge, &rp),
        });

        write_paused(&env, true);
        assert_eq!(
            Account::rotate_binding(
                env.clone(),
                replacement_signer.clone(),
                OwnerSignature::Passkey(passkey_sign(&env, &passkey, &rotate_challenge, &rp,)),
                expiry,
            ),
            Err(AccountError::AccountPaused)
        );
        write_paused(&env, false);

        assert_eq!(
            Account::rotate_binding(
                env.clone(),
                replacement_signer.clone(),
                OwnerSignature::Evm(evm_sign(&env, &evm, &rotate_challenge)),
                expiry,
            ),
            Err(AccountError::InvalidApprovalSet)
        );

        let result = Account::rotate_binding(
            env.clone(),
            replacement_signer,
            OwnerSignature::Passkey(passkey_sign(&env, &passkey, &rotate_challenge, &rp)),
            expiry,
        )
        .unwrap();
        let bindings = Account::get_bindings(env.clone());
        assert_eq!(bindings.passkey, Some(replacement_public));
        assert_eq!(bindings.evm, Some(evm_address(&env, &evm)));
        assert_eq!(result.auth_config_nonce, 2);
        assert_eq!(result.session_epoch, 1);
    });
}

#[test]
fn peer_and_bls_recovery_replace_only_the_target_binding() {
    let env = Env::default();
    let passkey = PasskeyKey::from_slice(&[1; 32]).unwrap();
    let (host, rp) = initialize_passkey(&env, &passkey);
    let evm = EvmKey::from_slice(&[2; 32]).unwrap();
    let stellar = StellarKey::from_bytes(&[3; 32]);
    let expiry = 150;

    env.as_contract(&host, || {
        let evm_challenge = get_challenge(
            env.clone(),
            Symbol::new(&env, "add"),
            None,
            None,
            Some(evm_address(&env, &evm)),
            expiry,
        )
        .unwrap();
        Account::add_binding(
            env.clone(),
            AccountSigner::Evm(EvmAccountSigner {
                address: evm_address(&env, &evm),
                pop_signature: evm_sign(&env, &evm, &evm_challenge),
            }),
            Vec::from_array(
                &env,
                [OwnerSignature::Passkey(passkey_sign(
                    &env,
                    &passkey,
                    &evm_challenge,
                    &rp,
                ))],
            ),
            expiry,
        )
        .unwrap();

        let stellar_public = BytesN::from_array(&env, &stellar.verifying_key().to_bytes());
        let stellar_challenge = get_challenge(
            env.clone(),
            Symbol::new(&env, "add"),
            None,
            Some(stellar_public.clone()),
            None,
            expiry,
        )
        .unwrap();
        let stellar_signer = AccountSigner::Stellar(StellarAccountSigner {
            public_key: stellar_public.clone(),
            address: stellar_address(&env, &stellar),
            pop_signature: stellar_sign(&env, &stellar, &stellar_challenge),
        });
        assert_eq!(
            Account::add_binding(
                env.clone(),
                stellar_signer.clone(),
                Vec::from_array(
                    &env,
                    [OwnerSignature::Passkey(passkey_sign(
                        &env,
                        &passkey,
                        &stellar_challenge,
                        &rp,
                    ))],
                ),
                expiry,
            ),
            Err(AccountError::InsufficientBindingApprovals)
        );
        assert_eq!(
            Account::add_binding(
                env.clone(),
                stellar_signer.clone(),
                Vec::from_array(
                    &env,
                    [
                        OwnerSignature::Passkey(passkey_sign(
                            &env,
                            &passkey,
                            &stellar_challenge,
                            &rp,
                        )),
                        OwnerSignature::Passkey(passkey_sign(
                            &env,
                            &passkey,
                            &stellar_challenge,
                            &rp,
                        )),
                    ],
                ),
                expiry,
            ),
            Err(AccountError::DuplicateApproval)
        );
        Account::add_binding(
            env.clone(),
            stellar_signer,
            Vec::from_array(
                &env,
                [
                    OwnerSignature::Passkey(passkey_sign(&env, &passkey, &stellar_challenge, &rp)),
                    OwnerSignature::Evm(evm_sign(&env, &evm, &stellar_challenge)),
                ],
            ),
            expiry,
        )
        .unwrap();

        let replacement = EvmKey::from_slice(&[4; 32]).unwrap();
        let peer_challenge = get_challenge(
            env.clone(),
            Symbol::new(&env, "peer_recover"),
            None,
            None,
            Some(evm_address(&env, &replacement)),
            expiry,
        )
        .unwrap();
        let before = Account::get_bindings(env.clone());
        Account::recover_binding_with_bindings(
            env.clone(),
            AccountSigner::Evm(EvmAccountSigner {
                address: evm_address(&env, &replacement),
                pop_signature: evm_sign(&env, &replacement, &peer_challenge),
            }),
            Vec::from_array(
                &env,
                [
                    OwnerSignature::Passkey(passkey_sign(&env, &passkey, &peer_challenge, &rp)),
                    OwnerSignature::Stellar(stellar_sign(&env, &stellar, &peer_challenge)),
                ],
            ),
            expiry,
        )
        .unwrap();
        let after_peer = Account::get_bindings(env.clone());
        assert_eq!(after_peer.passkey, before.passkey);
        assert_eq!(after_peer.stellar, before.stellar);
        assert_eq!(after_peer.evm, Some(evm_address(&env, &replacement)));

        let final_evm = EvmKey::from_slice(&[5; 32]).unwrap();
        let bls_challenge = get_challenge(
            env.clone(),
            Symbol::new(&env, "bls_recover"),
            None,
            None,
            Some(evm_address(&env, &final_evm)),
            expiry,
        )
        .unwrap();
        Account::recover_binding_bls(
            env.clone(),
            AccountSigner::Evm(EvmAccountSigner {
                address: evm_address(&env, &final_evm),
                pop_signature: evm_sign(&env, &final_evm, &bls_challenge),
            }),
            bls_signature(&env, &bls_challenge),
            expiry,
        )
        .unwrap();
        let after_bls = Account::get_bindings(env.clone());
        assert_eq!(after_bls.passkey, before.passkey);
        assert_eq!(after_bls.stellar, before.stellar);
        assert_eq!(after_bls.evm, Some(evm_address(&env, &final_evm)));
        assert_eq!(Account::get_auth_config_nonce(env.clone()), 4);
        assert_eq!(Account::get_session_epoch(env.clone()), 2);
    });
}
