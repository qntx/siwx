//! Chain namespace abstraction: parsing, formatting, and signature
//! verification for one CAIP-2 namespace.

use std::future::Future;
use std::pin::Pin;

use crate::{AccountId, Error, Expect, Message};

/// Boxed `Send` future used by [`Namespace::verify`].
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A chain namespace profile: which CAIP-2 namespace it claims, how to map a
/// [`Message`] to a [`AccountId`], and how to verify its signatures.
pub trait Namespace: Send + Sync {
    /// CAIP-2 namespace, e.g. `"eip155"` / `"solana"`.
    fn namespace(&self) -> &'static str;

    /// Preamble label, e.g. `"Ethereum"` / `"Solana"`.
    fn label(&self) -> &'static str;

    /// Map `message` to a [`AccountId`], applying the namespace's
    /// address and chain-id rules.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidField`] for a bad [`crate::Field::Address`] /
    /// [`crate::Field::ChainId`].
    fn account(&self, message: &Message) -> Result<AccountId, Error>;

    /// Render `message` to this namespace's signing text.
    ///
    /// # Errors
    ///
    /// Propagates [`Self::account`] errors.
    fn format(&self, message: &Message) -> Result<String, Error>;

    /// Parse `signed` bytes into a [`Message`], requiring the preamble label
    /// to equal [`Self::label`].
    ///
    /// # Errors
    ///
    /// [`Error::Mismatch`] [`crate::Field::Label`] on a foreign label, plus parse
    /// errors.
    fn parse(&self, signed: &[u8]) -> Result<Message, Error>;

    /// Verify `signature` over the exact `signed` bytes.
    ///
    /// # Errors
    ///
    /// [`Error::VerificationFailed`] when crypto rejects the signature;
    /// [`Error::InvalidSignature`] for malformed signature bytes.
    fn verify<'a>(
        &'a self,
        message: &'a Message,
        signed: &'a [u8],
        signature: &'a [u8],
    ) -> BoxFuture<'a, Result<(), Error>>;
}

/// Successful [`authenticate`]: the parsed message plus its CAIP-10 identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authenticated {
    message: Message,
    account: AccountId,
}

impl Authenticated {
    /// The authenticated message.
    #[must_use]
    pub const fn message(&self) -> &Message {
        &self.message
    }

    /// The authenticated CAIP-10 `account_id`.
    #[must_use]
    pub const fn account(&self) -> &AccountId {
        &self.account
    }

    /// Consume into the message.
    #[must_use]
    pub fn into_message(self) -> Message {
        self.message
    }
}

/// Full backend login flow: parse → [`Expect::check`] → account → verify.
///
/// `signed` must be the exact bytes the wallet signed; `expect` binds the
/// server-issued domain/nonce and time policy.
///
/// # Errors
///
/// First failing step's [`Error`].
pub async fn authenticate(
    namespace: &dyn Namespace,
    signed: &[u8],
    signature: &[u8],
    expect: &Expect,
) -> Result<Authenticated, Error> {
    let message = namespace.parse(signed)?;
    expect.check(&message)?;
    let account = namespace.account(&message)?;
    namespace.verify(&message, signed, signature).await?;
    Ok(Authenticated { message, account })
}
