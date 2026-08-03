# PzPass — Codebase Overview

**PzPass** is a minimal, zero-dependency password manager / encrypted secret vault written in **Zig** (v0.16.0+). The compiled binary is called `pzp`.

- **License:** MIT
- **Author:** Anton Sidorov (Tony Sidrock)
- **Repository:** <https://github.com/pzpass/pzpass>

---

## Tech Stack

| Aspect | Detail |
|--------|--------|
| **Language** | Zig exclusively (no C, no other languages) |
| **Zig Version** | `0.16.0`+ |
| **External Dependencies** | **None** — all crypto from `std.crypto` |
| **Build System** | Zig's built-in build system (`build.zig` + `build.zig.zon`) |
| **CI/CD** | GitHub Actions (6 workflows) |
| **Target Platforms** | Linux x86_64, Linux ARM64, macOS ARM64 |

---

## Directory Layout

```
├── .github/workflows/          # CI/CD: checks, release, security audit
├── cli/main.zig                # Entry point — calls pzpass.run()
├── dict/words.txt              # 10,399-word diceware dictionary
├── src/
│   ├── pzpass.zig              # Library root, CLI arg dispatch
│   ├── config.zig              # Crypto & vault constants
│   ├── crypto.zig              # encrypt/decrypt, key derivation, mlock
│   ├── vault.zig               # Vault struct + all CRUD operations
│   ├── interactive.zig         # TUI loop (alternate screen buffer)
│   ├── storage.zig             # Atomic file I/O (tmp → rename → .bak)
│   ├── format.zig              # Custom binary serialization
│   ├── termios.zig             # Terminal raw mode for password input
│   ├── passwordgen.zig         # Random password generator
│   ├── dicephrase.zig          # Diceware passphrase generator
│   └── dicelist.zig            # Auto-generated word blob + offset table
├── tools/
│   ├── dicelist_generator.zig  # Build-time code generator
│   ├── clean_helper.zig        # Build artifact cleanup
│   └── toolbox_utils.zig       # Shared helpers for build tools
├── build.zig                   # Build definition
├── build.zig.zon               # Package manifest (v0.0.4)
├── README.md
└── LICENSE
```

**Total source:** ~2,234 lines across all modules.

---

## Architecture

### Module Dependency Graph

```
cli/main.zig
    └── pzpass (src/pzpass.zig)
            ├── crypto.zig (std.crypto.pwhash, std.crypto.aead, std.crypto.random)
            ├── vault.zig
            │       ├── config.zig
            │       ├── crypto.zig
            │       ├── storage.zig
            │       ├── format.zig
            │       ├── passwordgen.zig
            │       └── dicephrase.zig
            │               └── dicelist.zig (generated)
            ├── interactive.zig
            │       ├── vault.zig
            │       ├── termios.zig
            │       └── crypto.zig
            ├── passwordgen.zig
            │       └── crypto.zig
            └── dicephrase.zig
                    ├── crypto.zig
                    ├── termios.zig
                    └── dicelist.zig
```

### Data Flow

```
User types pzp
       │
       ▼
cli/main.zig ──► src/pzpass.zig::run()
                       │
           ┌───────────┼────────────┐
           ▼           ▼            ▼
    No args?      "dice"       "pass"
   (interactive)  command      command
           │
           ▼
   src/interactive.zig::run()
   - Alternate screen buffer
   - SIGINT handler
   - Prompt for master password
           │
           ▼
   src/vault.zig::Vault.init()
   - Derive KEK via Argon2id
   - Decrypt vault key (ChaCha20-Poly1305)
   - Load entries from disk
           │
           ▼
   Interactive TUI loop:
   'a' add | 'e' edit | 'g' get | 'd' delete
   'l' list | 'f' find | 'o' gen password
   'i' gen diceware | 's' save | 'u' change pw
   'h' help | 'q' quit
```

---

## Encryption Model

```
User Password
     │
     ▼  Argon2id (t=5, m=256MiB, p=1)  ────►  KEK (Key Encryption Key)
     │                                              │
     ▼                                              ▼
  Salt (random, stored in header)          Decrypts the Vault Key
                                            (ChaCha20-Poly1305)
                                                     │
                                                     ▼
                                           Vault Key decrypts each
                                           entry's name & data
                                           (ChaCha20-Poly1305,
                                            unique nonce per field)
```

### Vault File Format (custom binary)

```
[MAGIC "PZPASS" (6 bytes)]
[VERSION (usize, LE)]
[SALT (16 bytes)]
[ITERATIONS (usize, LE)]
[MEM_COST (u32, LE)]
[PARALLELISM (usize, LE)]
[KEK_NONCE (12 bytes)]
[KEK_CIPHERTEXT (32 bytes)]
[KEK_TAG (16 bytes)]
[ENTRY_COUNT (usize, LE)]
[ENTRY_COUNT duplicate (usize, LE)]
For each entry:
  [NAME_LEN (usize, LE)]
  [DATA_LEN (usize, LE)]
  [NONCE_NAME (12 bytes)]
  [NONCE_DATA (12 bytes)]
  [CIPHERTEXT_NAME (variable)]
  [CIPHERTEXT_DATA (variable)]
  [TAG_NAME (16 bytes)]
  [TAG_DATA (16 bytes)]
```

---

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **No external deps** | Minimizes attack surface and supply-chain risk |
| **Vault key wrapping** | Changing master password re-wraps only the vault key (fast), not all entries |
| **Unique nonces per field** | Each entry name + data gets its own random 12-byte nonce |
| **Atomic file writes** | `.tmp` → rename → `.bak` pattern prevents vault corruption |
| **Build-time dice list** | `words.txt` → `dicelist.zig` at compile time; no runtime file I/O |
| **Argon2id params in header** | Stored per-vault so parameters could be upgraded per vault |
| **Dual entry count** | Serialized twice as a basic integrity check |
| **mlock for secrets** | Page-aligned allocations locked in RAM; zeroed + unlocked on `defer` |

---

## Security Practices

- **Memory hardening:** `mlock`/`mlock2` (Linux), `std.crypto.secureZero`, `munlock` on all sensitive buffers
- **AEAD authentication:** ChaCha20-Poly1305 detects ciphertext tampering
- **Entry size limit:** 16 MiB max per entry prevents memory exhaustion attacks
- **Terminal echo disabled** for all password prompts
- **CI security audit** scans for unsafe patterns (`@ptrCast`, `catch unreachable`, `@setRuntimeSafety(false)`, etc.)

---

## Build Commands

| Command | Purpose |
|---------|---------|
| `zig build` | Build debug binary → `zig-out/bin/pzp` |
| `zig build -Doptimize=ReleaseFast` | Release build → `~/.local/bin/pzp` |
| `zig build gen` | Regenerate `src/dicelist.zig` from `dict/words.txt` |
| `zig build clean` | Remove build artifacts |
| `zig build test` | Run tests |

---

## Code Statistics

| File | Lines | Role |
|------|-------|------|
| `src/vault.zig` | 898 | Core vault operations (CRUD, init, load, save, password change) |
| `src/format.zig` | 268 | Binary serialization / deserialization |
| `src/storage.zig` | 179 | Atomic file I/O |
| `src/interactive.zig` | 173 | TUI main loop |
| `src/crypto.zig` | 162 | Encryption, key derivation, mlock |
| `src/pzpass.zig` | 99 | CLI entry & arg dispatch |
| `src/dicephrase.zig` | 96 | Diceware passphrase generation |
| `src/passwordgen.zig` | 60 | Random password generation |
| `src/dicelist.zig` | 54 | Auto-generated word lookup (build-time) |
| `src/termios.zig` | 24 | Terminal raw mode |
| `src/config.zig` | 22 | Crypto constants |
