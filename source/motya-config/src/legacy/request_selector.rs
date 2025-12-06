use std::io::Write;

use http::uri::PathAndQuery;
use pingora::protocols::l4::socket::SocketAddr;

pub struct SessionInfo<'a> {
    pub client_addr: Option<&'a SocketAddr>,
    pub path: &'a PathAndQuery
}

pub struct ContextInfo<'a> {
    pub selector_buf: &'a mut Vec<u8>
}


/// A function used to determine the "key" to use for the selection process.
///
/// The function may choose an existing series of bytes, or may format into
/// the MotyaContext.selector_buf field, using `write!` or similar formatting
/// options.
///
/// TODO: Should I just do `Cow<'a, [u8]>` instead of providing a buffer? The intent is
/// to avoid allocations on every select (reusing and growing one instead), but this might
/// have "weird" mem-leaky characteristics
pub type RequestSelector = for<'a> fn(&'a mut ContextInfo, &'a SessionInfo) -> &'a [u8];

/// Null selector, useful when using "Random" or "RoundRobin" selection and this key is not used
///
/// Performs no formatting
pub fn null_selector<'a>(_ctxt: &'a mut ContextInfo, _ses: &'a SessionInfo) -> &'a [u8] {
    &[]
}

/// Basic selector that looks at ONLY the URI of the request as the input key
///
/// Peforms no formatting
pub fn uri_path_selector<'a>(_ctxt: &'a mut ContextInfo, ses: &'a SessionInfo) -> &'a [u8] {
    ses.path.path().as_bytes()
}

/// Selector that uses the source address (if available) and the URI of the request as the input key
///
/// Performs formatting into the selector buf
pub fn source_addr_and_uri_path_selector<'a>(
    ctxt: &'a mut ContextInfo,
    ses: &'a SessionInfo,
) -> &'a [u8] {
    write!(
        &mut ctxt.selector_buf,
        "{:?}:{}",
        ses.client_addr,
        ses.path.path(),
    )
    .expect("Formatting into a Vec<u8> should never fail");

    ctxt.selector_buf.as_slice()
}
