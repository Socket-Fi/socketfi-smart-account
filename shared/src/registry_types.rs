use crate::registry_errors::RegistryError;
use soroban_sdk::{contracttype, BytesN, String};

/// - No validation is performed here
#[derive(Clone)]
#[contracttype]
pub struct ValidatorSignature {
    pub validator: BytesN<32>,
    pub signature: BytesN<64>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SocialPlatform {
    X,
    Discord,
    Telegram,
    Email,
    Tiktok,
    Sms,
}

impl SocialPlatform {
    pub fn is_platform_supported(s: String) -> Result<Self, RegistryError> {
        let e = s.env();

        if s == String::from_str(&e, "x") {
            return Ok(Self::X);
        }
        if s == String::from_str(&e, "discord") {
            return Ok(Self::Discord);
        }
        if s == String::from_str(&e, "telegram") {
            return Ok(Self::Telegram);
        }
        if s == String::from_str(&e, "email") {
            return Ok(Self::Email);
        }
        if s == String::from_str(&e, "tiktok") {
            return Ok(Self::Tiktok);
        }
        if s == String::from_str(&e, "sms") {
            return Ok(Self::Sms);
        }

        Err(RegistryError::PlatformNotSupported)
    }

    /// Returns the canonical string representation of the platform.
    ///
    /// NOTE:
    /// - Always returns lowercase string
    /// - Matches exactly the expected input for `is_platform_supported`
    ///
    /// IMPORTANT:
    /// - This ensures consistency across:
    ///     - storage keys
    ///     - hashing / message signing
    ///     - off-chain integrations
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::X => "x",
            Self::Discord => "discord",
            Self::Telegram => "telegram",
            Self::Email => "email",
            Self::Tiktok => "tiktok",
            Self::Sms => "sms",
        }
    }
}
