# Password Manager

A local-first desktop password manager built with Electron, React, and TypeScript.

## Security model

- The renderer has no Node.js or filesystem access.
- Electron uses context isolation, sandboxing, a restrictive CSP, local-only content, blocked navigation, and denied new windows.
- Vault data is stored as an authenticated AES-256-GCM envelope.
- The encryption key is derived from the master passphrase with scrypt (N=131072, r=8, p=1) and is kept only in the main process while unlocked.
- Writes are atomic and the vault is locked automatically after five minutes of inactivity.
- Passwords copied by the app are cleared from the clipboard after 30 seconds when the clipboard still contains the copied value.

No application can honestly guarantee 100% security. Keep Electron updated, use a unique strong master passphrase, and protect the operating system account running the app.

## Features

- Create and unlock an encrypted local vault
- Search services and usernames
- Add, edit, delete, reveal, and copy passwords
- Generate cryptographically random passwords
- Export encrypted .pmvault backups with a separate backup passphrase
- Import encrypted .pmvault backups, the legacy passwords.db SQLite file, or migration-friendly JSON/CSV files
- Duplicate imports are skipped by service and username
- Manual and inactivity auto-lock

## Development

Requires Node.js 20.19+ or 22.12+.

~~~
npm install
npm run dev
~~~

## Validate and build

~~~
npm run typecheck
npm run build
npm run dist
~~~

npm run dist creates a Windows NSIS installer through electron-builder.

### JSON/CSV import format

JSON can be an array of objects or an object with an entries array. Supported field names include:

~~~
[
  {
    "service": "LinkedIn",
    "username": "name@example.com",
    "password": "secret",
    "url": "https://linkedin.com",
    "notes": ""
  }
]
~~~

CSV must include service (or social/name) and password columns. username, email, url, website, and notes are also accepted.

The old Python/Tkinter source is retained as PasswordManager.py for reference. The existing passwords.db can be selected directly from Import passwords; it is read-only and the imported entries are re-encrypted into the new vault.
