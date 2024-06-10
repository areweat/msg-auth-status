//! WIP - Traits beginnings not done yet
//!
//! Idea of these traits is to enable non-allocated version
//! of parsing results without any sort of Vec and generalise
//! the implementation between allocating and non-allocating

/// Implement this to denote it's a DKIM Verifier containing result set
#[allow(unused_variables, dead_code)]
pub(crate) trait ResultsVerifier {
    fn return_path_atleast_one_dkim_pass(&self, selector: &str) -> bool;
}

#[allow(unused_variables, dead_code)]
pub(crate) trait ResultVerifier {
    fn return_path_dkim_pass(&self, selector: &str) -> bool;
}

/// Tie-in Controller for consumers
#[allow(dead_code)]
pub(crate) trait ResultsHandler {}

/// Receive DkimResults for consumers
#[allow(dead_code)]
pub(crate) trait DkimResultsHandler {}

/// Receive SpfResults for consumers
#[allow(dead_code)]
pub(crate) trait SpfResultsHandler {}

/// Receive AuthResults for consumers
#[allow(dead_code)]
pub(crate) trait AuthResultsHandler {}

/// Receive IpRevResults for consumers
#[allow(dead_code)]
pub(crate) trait IpRevResultsHandler {}

/// Receive Comments for consumers
#[allow(dead_code)]
pub(crate) trait CommentsHandler {}
