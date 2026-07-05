use crate::states::DataKey;
use socketfi_shared::{
    constants::{GUARDIAN_REMOVAL_DELAY_LEDGERS, MAX_GUARDIANS},
    key_types::GuardianInfo,
    wallet_error::WalletError,
};
use soroban_sdk::{Address, Env, Vec};

pub fn read_guardians(env: &Env) -> Vec<GuardianInfo> {
    env.storage()
        .instance()
        .get(&DataKey::Guardians)
        .unwrap_or(Vec::new(env))
}

pub fn write_guardians(env: &Env, guardians: Vec<Address>) {
    let mut guardian_infos = Vec::new(env);

    for guardian in guardians.iter() {
        guardian_infos.push_back(GuardianInfo {
            address: guardian,
            removal_time: None,
        });
    }

    env.storage()
        .instance()
        .set(&DataKey::Guardians, &guardian_infos);
}

pub fn is_paused(env: &Env) -> bool {
    env.storage()
        .instance()
        .get(&DataKey::Paused)
        .unwrap_or(false)
}

pub fn write_paused(env: &Env, paused: bool) {
    env.storage().instance().set(&DataKey::Paused, &paused);
}

pub fn is_unpause_approved(env: &Env) -> bool {
    env.storage()
        .instance()
        .get(&DataKey::UnpauseApproved)
        .unwrap_or(false)
}

pub fn write_unpause_approved(env: &Env, approved: bool) {
    env.storage()
        .instance()
        .set(&DataKey::UnpauseApproved, &approved);
}

pub fn guardian_can_pause(env: &Env, guardian: &Address) -> bool {
    let guardians = read_guardians(env);
    let now = env.ledger().sequence();

    for g in guardians.iter() {
        if g.address != *guardian {
            continue;
        }

        match g.removal_time {
            None => return true,
            Some(removal_time) => return now < removal_time,
        }
    }

    false
}

pub fn guardian_can_approve_unpause(env: &Env, guardian: &Address) -> bool {
    let guardians = read_guardians(env);

    for g in guardians.iter() {
        if g.address == *guardian && g.removal_time.is_none() {
            return true;
        }
    }

    false
}

pub fn validate_guardians(guardians: &Vec<Address>) -> Result<(), WalletError> {
    if guardians.len() > MAX_GUARDIANS {
        return Err(WalletError::MaxGuardiansExceeded);
    }

    for i in 0..guardians.len() {
        let g1 = guardians.get(i).unwrap();

        for j in (i + 1)..guardians.len() {
            let g2 = guardians.get(j).unwrap();

            if g1 == g2 {
                return Err(WalletError::DuplicateGuardian);
            }
        }
    }

    Ok(())
}

pub fn write_guardian_infos(env: &Env, guardians: Vec<GuardianInfo>) {
    env.storage()
        .instance()
        .set(&DataKey::Guardians, &guardians);
}

pub fn schedule_remove_guardian(env: &Env, guardian: Address) -> Result<(), WalletError> {
    if is_paused(env) {
        return Err(WalletError::WalletPaused);
    }

    let mut guardians = read_guardians(env);
    let removal_time = env.ledger().sequence() + GUARDIAN_REMOVAL_DELAY_LEDGERS;

    for i in 0..guardians.len() {
        let mut g = guardians.get(i).unwrap();

        if g.address == guardian {
            if g.removal_time.is_some() {
                return Err(WalletError::RemovalAlreadyScheduled);
            }

            g.removal_time = Some(removal_time);
            guardians.set(i, g);
            write_guardian_infos(env, guardians);
            return Ok(());
        }
    }

    Err(WalletError::GuardianNotFound)
}

pub fn finalize_remove_guardian(env: &Env, guardian: Address) -> Result<(), WalletError> {
    let mut guardians = read_guardians(env);
    let now = env.ledger().sequence();

    for i in 0..guardians.len() {
        let g = guardians.get(i).unwrap();

        if g.address != guardian {
            continue;
        }

        let removal_time = match g.removal_time {
            Some(time) => time,
            None => return Err(WalletError::RemovalNotScheduled),
        };

        if now < removal_time {
            return Err(WalletError::GuardianRemovalDelayNotElapsed);
        }

        guardians.remove(i);
        write_guardian_infos(env, guardians);

        return Ok(());
    }

    // Already removed (or never existed).
    Ok(())
}

pub fn add_new_guardian(env: &Env, guardian: Address) -> Result<(), WalletError> {
    if is_paused(env) {
        return Err(WalletError::WalletPaused);
    }

    let mut guardians = read_guardians(env);

    for g in guardians.iter() {
        if g.address == guardian {
            return Err(WalletError::DuplicateGuardian);
        }
    }

    if guardians.len() + 1 > MAX_GUARDIANS {
        return Err(WalletError::MaxGuardiansExceeded);
    }

    guardians.push_back(GuardianInfo {
        address: guardian,
        removal_time: None,
    });

    write_guardian_infos(env, guardians);

    Ok(())
}
