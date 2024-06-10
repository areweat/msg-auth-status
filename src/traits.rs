//! WIP - Traits beginnings not done yet
//!
//! Idea of these traits is to enable non-allocated version
//! of parsing results without any sort of Vec and generalise
//! the implementation between allocating and non-allocating

/// Tie-in Controller
pub trait ResultsHandler {}

/// Receive DkimResults
pub trait DkimResultsHandler {}

/// Receive SpfResults
pub trait SpfResultsHandler {}

/// Receive AuthResults
pub trait AuthResultsHandler {}

/// Receive IpRevResults
pub trait IpRevResultsHandler {}

/// Receive Comments
pub trait CommentsHandler {}
