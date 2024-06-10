//! Allocating variants of AuthenticationResults and DkimSignatures

mod auth_results;
mod dkim_signatures;

//-----------------------------------
// Re-export under alloc
//-----------------------------------

pub use auth_results::*;
pub use dkim_signatures::*;
