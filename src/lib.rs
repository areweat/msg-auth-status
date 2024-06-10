#![warn(
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]
#![allow(clippy::single_match, rustdoc::bare_urls)]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![doc = include_str!("../README.md")]

#[cfg(all(feature = "alloc", not(feature = "std")))]
extern crate alloc;

//---------------------------------------------------------
// Re-exports on external types we may use
//---------------------------------------------------------

#[cfg(feature = "mail_parser")]
pub mod mail_parser {
    //! Re-export of the used external mail_parser
    pub use mail_parser::{HeaderValue, Message, MessageParser};
}

//---------------------------------------------------------
// Traits
//---------------------------------------------------------

pub mod traits;

//---------------------------------------------------------
// Error types
//---------------------------------------------------------

pub mod error;

//---------------------------------------------------------
// Authentication-Results & DKIM-Signature etc. pub types
//---------------------------------------------------------

pub mod auth;
pub mod auth_results;
pub mod dkim;
pub mod iprev;
pub mod spf;

//--------------------------------------------------------
// Parsing implementations with type conversions
//--------------------------------------------------------

mod parser;

//--------------------------------------------------------
// Allocating Public convenience API
//--------------------------------------------------------

#[cfg(any(feature = "alloc", feature = "std"))]
pub mod alloc_yes;

//--------------------------------------------------------
// Non-Allocating Public convenience API
//--------------------------------------------------------

#[cfg(feature = "static")]
pub mod alloc_no;
