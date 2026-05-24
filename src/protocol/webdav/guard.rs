use dav_server::davpath::DavPath;
use std::path::Component;

/// Reject any access to the vault's metadata file or hidden entries.
/// Checks every path component so that nested forms like `/sub/dspv.meta` are also blocked.
pub fn is_forbidden(path: &DavPath) -> bool {
    path.as_rel_ospath().components().any(|c| {
        if let Component::Normal(s) = c {
            let name = s.to_string_lossy();
            name == "dspv.meta" || name.starts_with('.')
        } else {
            false
        }
    })
}
