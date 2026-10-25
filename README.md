# ZedCompress (Rust)

A sleek file/folder compressor with authenticated encryption, recovery records
and multithreading. The flagship `.zed` format is a **solid tar → LZMA
(preset 9 | EXTREME) → optional encryption**. Also reads/writes `.zip` and
`.tar.xz`.

## Source layout

| file | responsibility |
|---|---|
| `src/rabbit.rs` | Rabbit stream cipher (RFC 4503) |
| `src/crypto.rs` | cipher selection, PBKDF2 KDF, keystream trait, RFC self-check |
| `src/filters.rs` | BCJ pre-filters + executable sniffing |
| `src/format.rs` | the `.zed` container + shared `xz_writer` |
| `src/archive.rs` | format dispatch + public compress/extract/list/verify |
| `src/recovery.rs` | Reed-Solomon recovery records (protect/repair) |
| `src/bench.rs` | compression-preset benchmark |
| `src/native.rs` | FFI to the C + ASM routines (safe wrappers) |
| `src/native/crc32.c` | **C** — IEEE CRC-32 for recovery-shard checksums |
| `src/native/rabbit.S` | **x86-64 ASM** — Rabbit `next_state` (keystream kernel) |
| `src/native/chacha.S` | **x86-64 ASM** — ChaCha20 block function |
| `src/native/aes_ctr.S` | **x86-64 ASM** — AES-256-CTR keystream (AES-NI) |
| `src/native/sha256.S` | **x86-64 ASM** — SHA-256 block (scalar; HMAC + PBKDF2 core) |
| `src/native/sha256_ni.S` | **x86-64 ASM** — SHA-256 block via the SHA-NI extension |
| `src/native/crc32.S` | **x86-64 ASM** — CRC-32 hot loop (table owned by C) |
| `src/native/xor.S` | **x86-64 ASM** — SSE2 SIMD XOR (baseline keystream apply) |
| `src/native/xor_avx2.cpp` | **C++** — AVX2 SIMD XOR (used when the CPU supports it) |
| `src/sha.rs` / `src/chacha.rs` / `src/aes.rs` | Rust wrappers over the asm crypto cores |

### Runtime-selected ASM backends

Several primitives have more than one implementation, chosen at runtime by CPU
capability (via `is_x86_feature_detected!`), always with a safe fallback:

| primitive | fast backend | fallback |
|---|---|---|
| keystream XOR | AVX2 (C++) | SSE2 (asm) |
| AES-256-CTR | AES-NI (asm) | `aes`/`ctr` crates (software) |
| SHA-256 | SHA-NI (asm) | scalar (asm) |
| Rabbit / ChaCha20 / CRC-32 | assembly | — (asm is baseline) |
| `src/lib.rs` | module glue, re-exports, self-test |
| `src/main.rs` | CLI (`zed`) |
| `src/bin/gui.rs` | GUI (`zed-gui`, feature `gui`) |

The C, C++ and assembly are compiled by `build.rs` (via the `cc` crate / gcc)
into static libraries linked into the crate — so the project is built from
**Rust, C, C++ and x86-64 assembly**. The whole cryptographic core is assembly:
the Rabbit cipher kernel (`rabbit.S`) and SHA-256 block compression (`sha256.S`,
the engine behind HMAC and PBKDF2 — so every encrypted archive derives its keys
and computes its MAC in hand-written asm). The keystream XOR is runtime-dispatched
between an **AVX2** path (C++) and an **SSE2** path (asm); C handles the recovery
checksums; Rust is the application shell (CLI, GUI, archive/format/recovery logic,
and the thin HMAC/PBKDF2 wrappers). A C/C++ compiler (gcc, already needed for the
GNU Rust toolchain) is required to build.

> Scope note: the computational/crypto kernels are assembly; the application
> shell stays Rust on purpose. Rewriting file I/O, argument parsing, the GUI and
> the LZMA/tar plumbing in assembly would be far more bug-prone and no faster —
> so "mainly assembly" applies to the engine, not the whole program.

## Build

Needs the Rust toolchain (GNU on Windows, reusing MinGW gcc).

```bash
cargo build --release                               # CLI  -> target/release/zed
cargo build --release --features gui --bin zed-gui  # GUI  -> target/release/zed-gui
```

## CLI

```bash
zed c out.zed myfolder file.txt           # compress (level 9 default)
zed c out.zed data -e -c rabbit           # encrypt; prompts for password (hidden, confirmed)
zed c out.zed data -p "pw" -c chacha20    # encrypt with password on argv (scripting)
zed c out.zed data -e --keyfile k         # password + key file (both required)
zed c out.zed data -T 0                   # use all CPU cores (multithreaded)
zed x out.zed ./restore                   # extract (prompts if encrypted)
zed l out.zed                             # list contents
zed v out.zed                             # verify integrity / MAC
zed protect out.zed -r 15                 # add 15% recovery records (out.zed.rvz)
zed repair out.zed                        # repair a damaged archive from its records
zed bench data                            # compare level/filter presets
zed selftest                              # RFC vectors + roundtrip + tamper + recovery
zed c out.zip data                        # .zip / .tar.xz also supported
```

## Recovery records (`protect` / `repair`)

Like WinRAR's recovery records: `protect` writes a `<archive>.rvz` sidecar with
Reed-Solomon parity. If the archive is later damaged (bit-rot, a bad sector),
`repair` detects the corrupted blocks by CRC and rebuilds them — as long as the
damage stays within the chosen redundancy. Works on any file, not just `.zed`.

## Multithreading

`-T N` compresses with N threads (`-T 0` = all cores) by splitting the LZMA
stream into blocks. Default is 1 thread for the best ratio; more threads trade a
little ratio for a lot of speed on large inputs.

- Level `0` = store (no compression); `1`–`9` = LZMA.
- `--filter` adds a BCJ pre-filter that improves compression of machine code
  (like 7-Zip/WinRAR): `auto` (default — detects PE/ELF and applies `x86`),
  `none`, `x86`, `arm`, `arm-thumb`, `powerpc`, `ia64`, `sparc`. The `.xz`
  container records the filter, so extraction reverses it automatically.
- `-e/--encrypt` prompts for the password with hidden input and confirmation
  (safer than `-p`, which is visible in the process list and shell history).
  Extract/list/verify auto-prompt when the archive is encrypted.
- Compress refuses to overwrite an existing file unless you pass `-f/--force`.

## Encryption

- Ciphers: **Rabbit** (default, RFC 4503), **ChaCha20** (RFC 8439), **AES-256-CTR**.
- Construction: **encrypt-then-MAC** with HMAC-SHA256. The tag is verified
  *before* any data is decrypted, so a wrong password or a tampered file is
  rejected up front.
- Key derivation: **PBKDF2-HMAC-SHA256** (200k iterations, random salt), with an
  optional key file folded in (both then required).
- Ciphers are verified against their official RFC test vectors in `zed selftest`.

## Honest limits

- **1 GB → 12 KB is impossible for general data** (pigeonhole principle). Huge
  ratios only occur on *redundant* data (zeros, duplicates); random or
  already-compressed data barely shrinks, and encrypted data will not compress
  at all. ZedCompress always compresses *then* encrypts, and reports the real
  ratio.
- These ciphers (Rabbit hand-written; ChaCha20/AES from RustCrypto) are correct
  and sound, but not a formally audited, side-channel-hardened deployment. For
  high-stakes adversarial use, prefer a vetted AEAD (e.g. AES-256-GCM).
- `.zed` encryption is `.zed`-only; `.zip`/`.tar.xz` are unencrypted interop
  formats. `.zed` tar is ustar (paths ≤ 255, files ≤ 8 GiB) — use `.tar.xz` for
  anything larger.
