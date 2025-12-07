use std::collections::BTreeMap;

use pingora::{Error, Result};

/// Helper function that extracts the value of a given key.
///
/// Returns an error if the key does not exist
pub fn extract_val(key: &str, map: &mut BTreeMap<String, String>) -> Result<String> {
    map.remove(key).ok_or_else(|| {
        // TODO: better "Error" creation
        tracing::error!("Missing key: '{key}'");
        Error::new_str("Missing configuration field!")
    })
}

/// Helper function to make sure the map is empty
///
/// This is used to reject unknown configuration keys
pub fn ensure_empty(map: &BTreeMap<String, String>) -> Result<()> {
    if !map.is_empty() {
        let keys = map.keys().map(String::as_str).collect::<Vec<&str>>();
        let all_keys = keys.join(", ");
        tracing::error!("Extra keys found: '{all_keys}'");
        Err(Error::new_str("Extra settings found!"))
    } else {
        Ok(())
    }
}
