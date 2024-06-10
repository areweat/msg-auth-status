//! Allocating variants of AuthenticationResults and DkimSignatures

mod auth_results;
mod dkim_signatures;

//-----------------------------------
// Re-export under alloc
//-----------------------------------

#[doc(inline)]
pub use auth_results::*;

#[doc(inline)]
pub use dkim_signatures::*;
