//! LZMA pre-filters. BCJ (branch/call/jump) filters rewrite machine code so
//! LZMA compresses executables better (like 7-Zip / WinRAR). The .xz container
//! records the chosen filter, so extraction reverses it automatically — the
//! choice only affects the compressor.

use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use walkdir::WalkDir;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Filter {
    None,
    X86,
    Arm,
    ArmThumb,
    PowerPc,
    Ia64,
    Sparc,
    /// Detect executables and pick a BCJ filter, else None.
    Auto,
}

impl Filter {
    pub fn parse(s: &str) -> Option<Filter> {
        Some(match s.to_ascii_lowercase().as_str() {
            "none" => Filter::None,
            "x86" => Filter::X86,
            "arm" => Filter::Arm,
            "armthumb" | "arm-thumb" => Filter::ArmThumb,
            "powerpc" | "ppc" => Filter::PowerPc,
            "ia64" => Filter::Ia64,
            "sparc" => Filter::Sparc,
            "auto" => Filter::Auto,
            _ => return None,
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            Filter::None => "none",
            Filter::X86 => "x86",
            Filter::Arm => "arm",
            Filter::ArmThumb => "arm-thumb",
            Filter::PowerPc => "powerpc",
            Filter::Ia64 => "ia64",
            Filter::Sparc => "sparc",
            Filter::Auto => "auto",
        }
    }
    pub(crate) fn apply(self, f: &mut xz2::stream::Filters) {
        match self {
            Filter::X86 => { f.x86(); }
            Filter::Arm => { f.arm(); }
            Filter::ArmThumb => { f.arm_thumb(); }
            Filter::PowerPc => { f.powerpc(); }
            Filter::Ia64 => { f.ia64(); }
            Filter::Sparc => { f.sparc(); }
            Filter::None | Filter::Auto => {}
        }
    }
}

/// Peek at the first bytes of the inputs for PE (`MZ`) / ELF magic.
pub(crate) fn sniff_executable(inputs: &[PathBuf]) -> bool {
    let mut checked = 0;
    for p in inputs {
        let files: Vec<PathBuf> = if p.is_dir() {
            WalkDir::new(p).into_iter().flatten()
                .filter(|e| e.file_type().is_file())
                .map(|e| e.into_path())
                .collect()
        } else {
            vec![p.clone()]
        };
        for f in files {
            if checked >= 256 {
                return false; // bounded sniff; don't scan huge trees
            }
            checked += 1;
            if let Ok(mut fh) = File::open(&f) {
                let mut magic = [0u8; 4];
                if fh.read_exact(&mut magic).is_ok()
                    && (&magic[..2] == b"MZ" || magic == [0x7F, b'E', b'L', b'F'])
                {
                    return true;
                }
            }
        }
    }
    false
}
