#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
pub mod codec;
pub mod hasher;
#[cfg(feature = "std")]
pub mod trie;

#[cfg(feature = "std")]
pub use codec::Multicodec;
#[cfg(feature = "std")]
pub use hasher::Multihash;
pub use tiny_cid::Cid;
