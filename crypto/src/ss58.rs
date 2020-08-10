use crate::error::InvalidSs58;
use sp_core::crypto::Ss58Codec;
use std::str::FromStr;
use substrate_subxt::system::System;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ss58<T: System>(pub T::AccountId);

impl<T: System> FromStr for Ss58<T>
where
    T::AccountId: Ss58Codec,
{
    type Err = InvalidSs58;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        Ok(Self(
            <T::AccountId as Ss58Codec>::from_string(string).map_err(InvalidSs58)?,
        ))
    }
}
