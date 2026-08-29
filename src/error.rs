use thiserror::Error;

#[derive(Error, Debug)]
pub enum YouModError {
    #[error("Wand/WeMod installation not found")]
    WandNotFound,

    #[error("app.asar not found at {0}")]
    AsarNotFound(String),

    #[error("Patch '{name}': code pattern not found in any candidate file. This Wand version may not be supported.")]
    PatchNotMatched { name: String },

    #[error("Patch '{name}': expected single match, found {count} matches. Wand version may have changed.")]
    PatchMultipleMatches { name: String, count: usize },

    #[error("ASAR operation '{op}' failed: {source}")]
    AsarOp { op: &'static str, source: anyhow::Error },

    #[error("I/O error on {path}: {source}")]
    Io { path: String, source: std::io::Error },

    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, YouModError>;
