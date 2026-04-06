# PzPass

**PzPass** is a minimal, high-performance password generator and encrypted secret vault manager built with Zig.

It prioritizes simplicity, control, and auditability over feature bloat.

---

## Features

- 🔐 Secure password generation
- 🗄️ Encrypted vault for storing secrets
- 🔑 Password-based key derivation (KEK model)
- ⚡ Fast and lightweight
- 🧩 Minimal design, easy to understand and audit
- 💻 CLI-first workflow

---

## Philosophy

PzPass follows a few strict principles:

- Keep it simple
- Avoid hidden behavior
- No unnecessary dependencies
- Local-first (no cloud lock-in)

This is a tool you can actually read, understand, and trust.

---

## How It Works

```
User Password
    ↓
KDF → KEK (Key Encryption Key)
    ↓
Decrypt Vault Key
    ↓
Vault Key decrypts stored secrets
```

### Core Concepts

- **User Password**  
  The only secret you need to remember.

- **KEK (Key Encryption Key)**  
  Derived from your password via a KDF.

- **Vault Key**  
  Encrypts all stored entries. Stored encrypted.

- **Entries**  
  Secrets encrypted using the vault key.

---

## Getting Started

### Clone

```bash
git clone https://github.com/pzpass/pzpass.git
cd pzpass
```

### Build

```bash
zig build -Doptimize=ReleaseFast
```

---

### Run

```bash
pzp
```

## Usage

> CLI is intentionally minimal and may evolve.

### Generate password

```bash
pzp pw <length>
```

### Generate diceware password

```bash
pzp dice <word-count>
```

---

## Security Notes

- Passwords are never stored
- Vault key is never stored in plaintext
- All secrets are encrypted at rest
- Changing password requires re-wrapping the vault key
- Rotating the vault key requires re-encrypting all entries

---

## Limitations (Current State)

- No multi-user support
- No remote sync or cloud integration
- No GUI
- No recovery mechanism (lose the password = lose access)

---

## Roadmap (Ideas, Not Promises)

- Multi-user support
- Remote storage (S3, Google Drive, etc.)

---

## Contributing

Contributions are welcome, but keep it aligned:

- No unnecessary complexity
- No heavy dependencies
- Security and clarity first

---

## License

MIT

---

## Final Thoughts

PzPass is not trying to be a mainstream password manager.

It’s for people who:
- want full control
- understand the trade-offs
- prefer simple, auditable systems

If you’re looking for convenience and polish, there are better options.
If you care about how things actually work, this might be worth using.
