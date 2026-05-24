pub mod errors;
mod file;
mod fs;
mod guard;
mod metadata;

// Only `WebDavFS` needs to be reachable from outside this module — the file
// handle and dir-entry types are returned as `Box<dyn DavFile>` / `Box<dyn
// DavDirEntry>` trait objects, so callers never name them.
pub use fs::WebDavFS;

#[cfg(test)]
mod tests;
