//! Public errors

/// Errors relating to parsing Authentication-Results Header
#[derive(Clone, Debug, PartialEq)]
pub enum AuthResultsError {
    /// Unknown parsing error
    Parse,
    /// Host parsing error
    ParseHost(String),
    /// Bug
    ParsePtypeBugGating,
    /// Bug
    ParsePtypeBugInvalidProperty,
    /// Bug
    ParsePtypeBugPropertyGating,
    /// Invalid ptype Encountered
    ParsePtypeInvalidPtype,
    /// Invalid dkim method Result Code
    InvalidDkimResult(String),
    /// Invalid spf method Result Code
    InvalidSpfResult(String),
    /// Invalid iprev method Result Code
    InvalidIpRevResult(String),
    /// Was not a valid ptype/property per IANA and strict validation was used
    InvalidProperty,
    /// Invalid auth method Result code
    InvalidSmtpAuthResult(String),
    /// Invalid stage in result
    InvalidResultStage,
    /// Invalid version - Only 1 allowed
    InvalidVersion,
    /// No associated version found when required
    NoAssociatedVersion,
    /// No associated policy found when defined
    NoAssociatedPolicy,
    /// No assicited reason found when defined
    NoAssociatedReason,
    /// No hostname found that is required
    NoHostname,
    /// Err
    ParsePtypeNoMethodResult,
    /// Bug property keys not implemented for ptype
    PropertiesNotImplemented,
    /// Bug property values not implemented for ptype
    PropertyValuesNotImplemented,
    /// Run-away auth method property key
    RunAwayAuthPropertyKey,
    /// Run-away auth method property value
    RunAwayAuthPropertyValue,
    /// Run-away comment
    RunAwayComment,
    /// Run-away dkim method property key
    RunAwayDkimPropertyKey,
    /// Run-away dkim method property value
    RunAwayDkimPropertyValue,
    /// Run-away iprev method property key
    RunAwayIpRevPropertyKey,
    /// Run-away iprev method property value
    RunAwayIpRevPropertyValue,
    /// Run-away spf method property key
    RunAwaySpfPropertyKey,
    /// Run-away spf method property value
    RunAwaySpfPropertyValue,
    /// Unexpected forward slash
    UnexpectedForwardSlash,
    /// Bug
    ParseCurrentPushNotImplemented,
}
