//! VM image management.

use crate::error::HostdError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmImage {
    pub name: String,
    pub path: PathBuf,
    pub size_bytes: u64,
}

/// List available VM images in the image directory.
pub fn list_images(image_dir: &Path) -> Result<Vec<VmImage>, HostdError> {
    let mut images = Vec::new();

    let entries = std::fs::read_dir(image_dir).map_err(|e| {
        HostdError::ImageNotFound(format!("cannot read image dir {}: {e}", image_dir.display()))
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| HostdError::Other(e.into()))?;
        let path = entry.path();

        if path.extension().and_then(|e| e.to_str()) == Some("qcow2") {
            let metadata = std::fs::metadata(&path).map_err(|e| HostdError::Other(e.into()))?;
            images.push(VmImage {
                name: path
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
                path,
                size_bytes: metadata.len(),
            });
        }
    }

    Ok(images)
}
