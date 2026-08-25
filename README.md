# discord_extract

Discord local storage token extractor. Demonstrates how any user-level process can recover a Discord auth token in under one second with zero privilege escalation.

## What It Does

Extracts and decrypts Discord authentication tokens from the local machine by:

1. **Reading `Local State`** — parses the JSON file at `%APPDATA%\discord\Local State` to extract the Base64-encoded `encrypted_key`
2. **DPAPI decryption** — strips the 5-byte `DPAPI` prefix and calls `CryptUnprotectData` (user-context, no entropy) to recover the raw 32-byte AES-256 master key
3. **LevelDB parsing** — parses SSTable (`.ldb`/`.sst`) and WAL (`.log`) files inline with built-in Snappy decompression to find the `tokens` store under the `discord.com` origin
4. **AES-256-GCM decryption** — strips Discord's `dQw4w9WgXcQ:` safeStorage prefix, Base64-decodes, splits the v10 blob into nonce/ciphertext/tag, and decrypts via BCrypt CNG

## Why This Works

- **DPAPI is user-scoped, not process-scoped.** Any process running as the logged-in user can call `CryptUnprotectData` — no admin or SYSTEM token required
- **Discord inherits Chromium's Electron key storage.** Same `Local State` encryption flow as Chrome/Edge/Brave
- **LevelDB has no access control.** The database files are readable by any process with standard user-level file permissions
- **The token is a full session credential.** Grants complete Discord API access with no additional auth challenge

## Build

MSVC (Developer Command Prompt):
```
cl discord_extract.cpp /O2 /std:c++17 /EHsc /link crypt32.lib bcrypt.lib advapi32.lib
```

MinGW / MSYS2:
```
g++ discord_extract.cpp -O2 -std=c++17 -o discord_extract.exe -lcrypt32 -lbcrypt
```

No external dependencies. LevelDB format parsed inline — no libleveldb needed.

## Usage

```
discord_extract.exe [--out <file>] [--help]
```

Default output file: `discord_output.txt`

### Example Output

```
============================================================
  discord_extract
============================================================

  Discord
  --------------------------------------------------------
  Account : 123456789012345678
  Token   : MTIXXXXXXXXXXXXX.XXXXXX.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
  Status  : DECRYPTED

  [+] Full output saved to: discord_output.txt
```

## Supported Clients

- Discord
- Discord Canary
- Discord PTB
- Discord Development

All paths are resolved dynamically via `%APPDATA%` — nothing is hardcoded to any specific machine.

## Technical Details

| Component | Implementation |
|-----------|---------------|
| Key storage | `Local State` JSON → Base64 → DPAPI blob |
| Key decryption | `CryptUnprotectData` (user DPAPI context) |
| Token encryption | Chromium v10 — AES-256-GCM (12-byte nonce, 16-byte tag) |
| Token storage | LevelDB LocalStorage (`_https://discord.com\x00\x01tokens`) |
| LevelDB parser | Inline SSTable + WAL parser with Snappy decompression |
| Crypto backend | BCrypt CNG (`BCryptDecrypt` with `BCRYPT_CHAIN_MODE_GCM`) |
| safeStorage prefix | `dQw4w9WgXcQ:` stripped before Base64 decode |

## MITRE ATT&CK

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1140** — Deobfuscate/Decode Files
- **T1552.001** — Credentials in Files

## Disclaimer

This tool is for authorized security research and educational purposes only. Do not use it to access accounts you do not own. The author is not responsible for misuse.
