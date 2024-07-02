//! Allocating variants of AuthenticationResults, DkimSignatures & ReturnPathVerifier

mod auth_results;
mod dkim_signatures;
mod verifier;

//-----------------------------------
// Re-export under alloc_yes
//-----------------------------------

#[doc(inline)]
pub use auth_results::*;

#[doc(inline)]
pub use dkim_signatures::*;

#[doc(inline)]
pub use verifier::*;
