# PzPass

**PzPass** is a minimal, high-performance password generator and encrypted secret vault manager built with Zig. It prioritizes simplicity, control, and auditability over feature bloat.

Website: <https://pzpass.github.io/>

## Features

- Encrypted vault for storing secrets (ChaCha20-Poly1305 AEAD)
- Password-based key derivation (Argon2id)
- Interactive TUI vault manager (add, view, edit, delete, search entries)
- Secure password generation
- Diceware passphrase generation (10,399-word list)
- Memory locking (mlock) for sensitive data
- No external dependencies
- Local-first (no cloud)

---

## Philosophy

- Keep it simple
- Avoid hidden behavior
- No unnecessary dependencies
- Local-first (no cloud lock-in)

---

## How It Works

```
User Password
    ↓
Argon2id → KEK (Key Encryption Key)
    ↓
Decrypt Vault Key (wrapped with ChaCha20-Poly1305)
    ↓
Vault Key decrypts stored entries
```

### Core Concepts

- **User Password** — the only secret you need to remember
- **KEK** — derived from your password via Argon2id
- **Vault Key** — encrypts all stored entries; stored encrypted by the KEK
- **Entries** — name/value secrets encrypted with the vault key

---

## Install

Prebuilt binaries are published for Linux x86_64/arm64 and macOS arm64.

### Homebrew (macOS, Linux)

```bash
brew install meslab/tap/pzpass
```

Installs the `pzp` binary.

### Direct download

```bash
TAG=v1.0.1
TARGET=aarch64-macos  # or x86_64-linux, aarch64-linux
curl -fLO "https://github.com/pzpass/pzpass/releases/download/$TAG/pzp-$TAG-$TARGET.tar.gz"
curl -fLO "https://github.com/pzpass/pzpass/releases/download/$TAG/pzp-$TAG-$TARGET.tar.gz.sha256"
shasum -a 256 -c "pzp-$TAG-$TARGET.tar.gz.sha256"
tar -xzf "pzp-$TAG-$TARGET.tar.gz"
mkdir -p ~/.local/bin && install -m 0755 "pzp-$TAG-$TARGET/pzp" ~/.local/bin/pzp
```

Pick the latest tag from the [releases page](https://github.com/pzpass/pzpass/releases).
If you download the archive with a browser on macOS, clear the quarantine flag before running:
`xattr -d com.apple.quarantine ~/.local/bin/pzp`.

### Build from source

Requires Zig 0.17.0 or above.

```bash
git clone https://github.com/pzpass/pzpass.git
cd pzpass
zig build --release=small --prefix "$HOME/.local"
```

The binary is installed to `~/.local/bin/pzp`. Without `--prefix` it goes to `zig-out/bin/pzp`.
The diceware list (`src/dicelist.zig`) is regenerated from `dict/words.txt` on every build.

---

## Usage

### Interactive vault (default)

```bash
pzp
```

Opens a TUI vault at `~/.pzpass/<USER>.vault.dat`. Prompts for your master password.

#### Key bindings

| Key | Action |
|-----|--------|
| `a` | Add an entry |
| `g` | Generate a password/diceware entry |
| `e` | Edit an entry |
| `d` | Delete an entry |
| `l` | List entries |
| `f` | Find entries (filter by name) |
| `o` | Open/view an entry |
| `i` | Show vault info |
| `s` | Save vault to disk |
| `u` | Update master password |
| `h` | Show help |
| `q` / `Esc` | Quit |

### Open a custom vault file

```bash
pzp -f <filename>
```

### Generate a password

```bash
pzp pass [length]
```

Default length is 20 characters.

### Generate a diceware passphrase

```bash
pzp dice [word-count]
```

Default word count is 5. Press any key (except `q`/`Esc`) to generate another.

---

## Security Notes

- Passwords are never stored in plaintext
- Revealed records are securely wiped from memory
- Vault key is never stored in plaintext
- All secrets are encrypted at rest (ChaCha20-Poly1305)
- Key derivation uses Argon2id (memory-hard KDF)
- Sensitive memory regions are locked with `mlock` to prevent swapping
- Changing password re-wraps the vault key with a new KEK

---

## Crypto Details

| Component | Algorithm |
|-----------|-----------|
| Encryption | ChaCha20-Poly1305 (AEAD) |
| Key derivation | Argon2id |
| KDF parameters | t=5, m=2^18 (256 MiB), p=1 |
| Vault key size | 256-bit |

---

## Limitations

- No multi-user support
- No remote sync or cloud integration
- No GUI
- No recovery mechanism (lose the password = lose access)

---

## Support

If PzPass is useful to you, you can [buy me a coffee](https://buymeacoffee.com/storysquish).

---

## Contributing

Contributions are welcome, but keep it aligned:

- No unnecessary complexity
- No heavy dependencies
- Security and clarity first

---

## License

MIT
