use soroban_sdk::{xdr::ToXdr, Bytes, BytesN, Env};

use socketfi_shared::key_types::{AccountCommitment, AccountSigner};

pub fn resolve_signer(signer: &AccountSigner) -> AccountCommitment {
    match signer {
        AccountSigner::Passkey(input) => AccountCommitment::Passkey(input.public_key.clone()),

        AccountSigner::Stellar(input) => AccountCommitment::Stellar(input.public_key.clone()),

        AccountSigner::Evm(input) => AccountCommitment::Evm(input.address.clone()),
    }
}

pub fn signer_challenge(
    env: &Env,
    live_until_ledger: u32,
    commitment: &AccountCommitment,
    domain: &[u8],
) -> BytesN<32> {
    let mut payload = Bytes::from_slice(env, domain);

    payload.append(&env.ledger().network_id().to_xdr(env));
    payload.append(&env.current_contract_address().to_xdr(env));
    payload.append(&live_until_ledger.to_xdr(env));
    payload.append(&commitment.to_xdr(env));

    env.crypto().sha256(&payload).into()
}
