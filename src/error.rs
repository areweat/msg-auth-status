//! Public errors

/// Parsing Detail relating to an Error
#[derive(Clone, Debug, PartialEq)]
pub struct ParsingDetail<'hdr> {
    /// Component
    pub component: &'static str,
    /// Span start
    pub span_start: usize,
    /// Span end
    pub span_end: usize,
    /// Source
    pub source: &'hdr str,
    /// Clipped span
    pub clipped_span: &'hdr str,
    /// Clipped remaining
    pub clipped_remaining: &'hdr str,
}

/// Errors relating to parsing Authentication-Results Header
#[derive(Clone, Debug, PartialEq)]
pub enum AuthResultsError<'hdr> {
    /// Could not find the ending for unknown method block beginning from
    RunawayUnknownMethod(usize),
    /// Detailed with ParsingDetail
    ParsingDetailed(ParsingDetail<'hdr>),
    /// No header
    NoHeader,
    /// Unknown parsing error
    Parse,
    /// Comment parsing error
    ParseComment(CommentError<'hdr>),
    /// Host parsing error
    ParseHost(String),
    /// Bug
    ParsePtypeBugGating,
    /// Bug
    ParsePtypeBugInvalidProperty,
    /// Bug
    ParsePtypeBugPropertyGating,
    /// Invalid associated ptype Encountered
    ParsePtypeInvalidAssociatedPtype(ParsingDetail<'hdr>),
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

/// DKIM-Signature header parsing Errors
#[derive(Debug)]
pub enum DkimSignatureError<'hdr> {
    /// Detailed with ParsingDetail
    ParsingDetailed(ParsingDetail<'hdr>),
    /// No tags found at all
    NoTagFound,
    /// Encountered unexpected Equal '=' character when a tag was expected
    UnexpectedEqual,
    /// Error (from lexer) trying to parse value - Unmatched
    ParseValueUnmatch,
    /// Error (from parse conversion) trying to parse a valid value on tag
    ParseValueInvalid(DkimTagValueError),
    /// Missign Required v=
    MissingVersion,
    /// Msising Required a=
    MissingAlgorithm,
    /// Msising Required b=
    MissingSignature,
    /// Missing Required bh=
    MissingBodyHash,
    /// Missing Required d=
    MissingResponsibleSdid,
    /// Msising Required h=
    MissingSignedHeaderFields,
    /// Missing Required s=
    MissingSelector,
}

/// Currently no error - may change in future
#[derive(Debug, PartialEq)]
pub enum DkimAlgorithmError {}

/// Currently infallible may be changed in the future
#[derive(Clone, Debug, PartialEq)]
pub enum DkimCanonicalizationError {}

/// Currently infallible, may change in the future
#[derive(Debug, PartialEq)]
pub enum DkimTimestampError {}

/// Currently infallible, may change in the future
#[derive(Debug, PartialEq)]
pub enum DkimVersionError {}

// Currently no errors - may change in the future
//#[derive(Clone, Debug, PartialEq)]
//pub enum DkimHeaderError {}

/// DKIM Header tags values parsing error
#[derive(Debug, PartialEq)]
pub enum DkimTagValueError {
    /// Tag value must appear only once per tag
    Duplicate,
    /// DKIM Timestamp parsing error
    Timestamp(DkimTimestampError),
    /// DKIM Canonizalition parsing error
    Canonicalization(DkimCanonicalizationError),
    /// DKIM Algorithm parsing error
    Algorithm(DkimAlgorithmError),
    /// DKIM Version parsing error
    Version(DkimVersionError),
}

impl<'hdr> From<DkimTagValueError> for DkimSignatureError<'hdr> {
    fn from(e: DkimTagValueError) -> Self {
        Self::ParseValueInvalid(e)
    }
}

impl From<DkimTimestampError> for DkimTagValueError {
    fn from(e: DkimTimestampError) -> Self {
        Self::Timestamp(e)
    }
}

impl From<DkimCanonicalizationError> for DkimTagValueError {
    fn from(e: DkimCanonicalizationError) -> Self {
        Self::Canonicalization(e)
    }
}

impl From<DkimAlgorithmError> for DkimTagValueError {
    fn from(e: DkimAlgorithmError) -> Self {
        Self::Algorithm(e)
    }
}

impl From<DkimVersionError> for DkimTagValueError {
    fn from(e: DkimVersionError) -> Self {
        Self::Version(e)
    }
}

/// Comment errors
#[derive(Clone, Debug, PartialEq)]
pub enum CommentError<'hdr> {
    /// None found
    RunAway,
    /// Detailed with ParsingDetail
    ParsingDetailed(ParsingDetail<'hdr>),
}

/// Quoted value parsing error
#[derive(Clone, Debug, PartialEq)]
pub enum QuotedError<'hdr> {
    /// Bug
    Bug,
    /// None found
    RunAway,
    /// Detailed with ParsingDetail    
    ParsingDetailed(ParsingDetail<'hdr>),
}

/// Addr-Spec parsing errors
#[derive(Clone, Debug, PartialEq)]
pub enum AddrSpecError<'hdr> {
    /// Local part not found
    NoAssociatedLocalPart,
    /// Domain not found
    NoAssociatedDomain,
    /// None found
    NoAssociatedAddrSpec,
    /// Detailed with ParsingDetail
    ParsingDetailed(ParsingDetail<'hdr>),
    /// Parsing failed at comment
    ParseComment(CommentError<'hdr>),
    /// Parsing display name failed
    ParseDisplayName(QuotedError<'hdr>),
}

/// Return-Path verifier errors
#[derive(Debug, PartialEq)]
pub enum ReturnPathVerifierError<'hdr> {
    /// Bug encountered with attempted verify - selector didn't match error / success
    BugSelectorFalse,
    /// Encountered multiple Return-Path headers
    MultipleNotAllowed,
    /// Return-Path header not present
    NoHeader,
    /// Invalid Return Path
    InvalidHeader(AddrSpecError<'hdr>),
}
