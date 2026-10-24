# ZedCompress (Rust)

A sleek file/folder compressor with authenticated encryption. The flagship
`.zed` format is a **solid tar → LZMA (preset 9 | EXTREME) → optional
encryption**. Also reads/writes `.zip` and `.tar.xz`.

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
zed x out.zed ./restore                   # extract (prompts if encrypted)
zed l out.zed                             # list contents
zed v out.zed                             # verify integrity / MAC
zed selftest                              # RFC vectors + roundtrip + tamper
zed c out.zip data                        # .zip / .tar.xz also supported
```

- Level `0` = store (no compression); `1`–`9` = LZMA.
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
