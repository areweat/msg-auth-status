//! Traits

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
