//! `bench`: compress the inputs with several level/filter presets to a temp
//! file and report the resulting sizes, so the tradeoffs are visible.

use anyhow::Result;
use std::fs;
use std::path::PathBuf;

use crate::archive::{compress, Format};
use crate::crypto::Cipher;
use crate::filters::Filter;

pub struct BenchRow {
    pub label: String,
    pub size: u64,
    pub filter: Filter,
}

pub fn bench(inputs: &[PathBuf], threads: u32) -> Result<(u64, Vec<BenchRow>)> {
    let tmp = std::env::temp_dir().join(format!("zed_bench_{}", std::process::id()));
    fs::create_dir_all(&tmp)?;
    let out = tmp.join("b.zed");
    let presets: &[(&str, u32, Filter)] = &[
        ("store (l0)", 0, Filter::None),
        ("fast (l3)", 3, Filter::Auto),
        ("max (l9)", 9, Filter::None),
        ("max+filter (l9, auto)", 9, Filter::Auto),
    ];
    let mut rows = Vec::new();
    let mut original = 0;
    for (label, level, filter) in presets {
        let (orig, size, used) =
            compress(inputs, &out, *level, None, None, Cipher::Rabbit, *filter, threads, Format::Zed)?;
        original = orig;
        rows.push(BenchRow { label: (*label).to_string(), size, filter: used });
        let _ = fs::remove_file(&out);
    }
    let _ = fs::remove_dir_all(&tmp);
    Ok((original, rows))
}
