//! CAIP-10 `account_id`: `namespace ":" reference ":" address`.

use std::fmt;
use std::str::FromStr;

use crate::{Error, Field};

/// A parsed CAIP-10 `account_id` (CAIP-2 chain id + account address).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AccountId {
    namespace: String,
    reference: String,
    address: String,
}

impl AccountId {
    /// Validate and build an `account_id`.
    ///
    /// `namespace` is CAIP-2 `[-a-z0-9]{3,8}`; `reference` is
    /// `[-_a-zA-Z0-9]{1,32}`; `address` is `[-.%a-zA-Z0-9]{1,128}`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidField`] [`Field::ChainId`] for a bad
    /// namespace/reference, [`Field::Address`] for a bad address.
    pub fn new(
        namespace: impl Into<String>,
        reference: impl Into<String>,
        address: impl Into<String>,
    ) -> Result<Self, Error> {
        let namespace = namespace.into();
        let reference = reference.into();
        let address = address.into();
        if !(3..=8).contains(&namespace.len())
            || !namespace
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(Error::field(Field::ChainId, "bad CAIP-2 namespace"));
        }
        if !(1..=32).contains(&reference.len())
            || !reference
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err(Error::field(Field::ChainId, "bad CAIP-2 reference"));
        }
        if !(1..=128).contains(&address.len())
            || !address
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'%'))
        {
            return Err(Error::field(Field::Address, "bad CAIP-10 address"));
        }
        Ok(Self {
            namespace,
            reference,
            address,
        })
    }

    /// CAIP-2 namespace (e.g. `"eip155"`).
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// CAIP-2 reference (e.g. `"1"`).
    #[must_use]
    pub fn reference(&self) -> &str {
        &self.reference
    }

    /// Account address.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.namespace, self.reference, self.address)
    }
}

impl FromStr for AccountId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.splitn(3, ':');
        let bad = || Error::field(Field::ChainId, "expected namespace:reference:address");
        let namespace = parts.next().ok_or_else(bad)?;
        let reference = parts.next().ok_or_else(bad)?;
        let address = parts.next().ok_or_else(bad)?;
        Self::new(namespace, reference, address)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for AccountId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for AccountId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}
