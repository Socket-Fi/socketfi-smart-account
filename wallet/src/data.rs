use soroban_sdk::contracttype;

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    FactoryContract,
    Owner,
    AggregatedBlsKey,
    Passkey,
    Nonce,
    RpidHash,
    RPID,
}
