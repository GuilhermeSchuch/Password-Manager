# AI Context: Password Manager Project

This document is the handoff context for AI agents working on this repository. Read it before changing code. Preserve existing user work, do not reset or discard unrelated changes, and do not expose password contents or passphrases in logs, screenshots, diagnostics, commits, or responses.

## Project purpose

This repository contains a local-first password manager rebuilt from an older Python/Tkinter application. It has two applications:

1. A desktop Electron application that creates, unlocks, edits, imports, and exports encrypted password vaults.
2. A separate Android Expo/React Native application that reads the desktop's encrypted `.pmvault` exports in read-only mode and allows searching, revealing, and copying fields.

There is no backend, account system, cloud sync, or network service. The intended security model is local-only operation.

## Repository layout

```text
Password manager/
├─ src/                         Electron application source
│  ├─ main/
│  │  ├─ main.ts                Electron main process, IPC, window security
│  │  ├─ vault.ts                Vault storage, crypto envelope, import/export
│  │  └─ sql-js.d.ts            sql.js typing declaration
│  ├─ preload/
│  │  ├─ preload.ts             Narrow contextBridge API
│  │  └─ api.d.ts               Renderer API typings
│  ├─ renderer/
│  │  ├─ App.tsx                Desktop React UI
│  │  ├─ main.tsx               Renderer entry point
│  │  └─ styles.css              Desktop styling
│  └─ shared/types.ts            Shared desktop data types
├─ packages/
│  └─ vault-format/
│     ├─ src/index.ts            Cross-platform `.pmvault` decoder
│     └─ package.json
├─ android/
│  ├─ App.tsx                    Read-only Android viewer
│  ├─ app.json                   Expo identity, icon, splash, Android package
│  ├─ eas.json                   EAS development/preview/production profiles
│  ├─ metro.config.js            Allows Android Metro to resolve root packages
│  ├─ assets/                    Android icon, adaptive icon, splash assets
│  └─ README.md                  Android-specific commands and behavior
├─ public/vault-logo.png         Existing Electron logo, reused by Android
├─ PasswordManager.py            Legacy Python/Tkinter reference source
├─ passwords.db                  Legacy SQLite input may exist locally; ignored by git
├─ package.json                  Electron scripts and dependencies
└─ README.md                     General project documentation
```

## Technology versions

Desktop root:

- Electron 43.4.0
- React 19.2.8 and React DOM 19.2.8
- TypeScript 5.9.x
- Vite 8.2.2
- electron-builder 26.15.3
- sql.js 1.14.2
- noble ciphers/hashes are installed at the root for the shared decoder

Android folder:

- Expo SDK 57
- React Native 0.86.3
- React 19.2.3
- TypeScript 6.x
- `expo-document-picker`, `expo-file-system`, `expo-screen-capture`, `expo-clipboard`, and `expo-dev-client`
- `@noble/ciphers` and `@noble/hashes`

## Desktop application behavior

The Electron application stores its active vault at:

```text
Electron app.getPath("userData")/vault.pmvault
```

The renderer never receives Node.js or filesystem access directly. The preload exposes only the typed `window.passwordManager` API. Main-process IPC handlers validate their sender, frame origin, argument types, and field lengths before calling `VaultStore`.

Important Electron security settings in `src/main/main.ts`:

- `app.enableSandbox()`
- `contextIsolation: true`
- `nodeIntegration: false`
- `sandbox: true`
- `webSecurity: true`
- insecure content disabled
- new windows denied
- navigation restricted to the local `app://bundle` protocol or the local Vite development server
- application menu removed with `Menu.setApplicationMenu(null)`
- browser window uses the vault logo as its Windows icon
- clipboard ownership is tracked and copied values are cleared after 30 seconds if unchanged
- vault is locked on application quit

Do not widen IPC access or add generic IPC channels. New functionality should use narrow, typed methods and keep validation in the main process.

## Desktop vault format

The desktop exporter creates a JSON file with the `.pmvault` extension. It is an authenticated encryption envelope:

```json
{
  "format": "password-manager-vault",
  "version": 1,
  "kdf": {
    "name": "scrypt",
    "N": 131072,
    "r": 8,
    "p": 1,
    "maxmem": 268435456
  },
  "salt": "base64",
  "iv": "base64",
  "tag": "base64",
  "ciphertext": "base64"
}
```

Crypto details:

- key length: 32 bytes
- KDF: scrypt, `N=131072`, `r=8`, `p=1`
- salt: 16 bytes
- cipher: AES-256-GCM
- IV/nonce: 12 bytes
- authentication tag: 16 bytes
- additional authenticated data: UTF-8 `password-manager-vault-v1`
- maximum accepted import size: 10 MiB
- export backup passphrase is separate from the desktop master passphrase

`src/main/vault.ts` currently uses Node's `node:crypto` for desktop encryption/decryption. `packages/vault-format/src/index.ts` is the platform-neutral decoder used by Android and must remain byte-compatible with the Electron format. It uses `@noble/hashes` scrypt and `@noble/ciphers` AES-GCM.

The Android decoder receives the Electron ciphertext and tag separately, concatenates `ciphertext || tag` for noble AES-GCM, and uses the same AAD. Do not change field names, KDF parameters, AAD, nonce lengths, tag lengths, or JSON structure without a deliberate migration/versioning plan.

The shared decoder accepts an optional scrypt progress callback. It must never log or return the passphrase.

## Desktop data model

`PasswordEntry`:

```ts
{
  id: string;
  service: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  createdAt: string;
  updatedAt: string;
}
```

The desktop UI supports:

- create and unlock vault
- add, edit, delete, reveal, and copy passwords
- cryptographically random password generation
- search by service and username
- encrypted `.pmvault` export/import
- legacy SQLite (`.db`, `.sqlite`, `.sqlite3`) import
- JSON and CSV import
- duplicate skipping by normalized service + username
- manual lock and five-minute inactivity lock

## Legacy import behavior

The old Python app used a SQLite database with a table shaped like:

```sql
socials(social, password)
```

The desktop importer reads `social` and `password` through `sql.js`, converts them into current `PasswordEntry` values, and re-encrypts them into the new vault. The legacy file is read-only; it is not modified.

JSON accepts either an array or `{ "entries": [...] }`. Supported aliases include `service`, `social`, `name`, `username`, `email`, `url`, `website`, `password`, and `notes`.

CSV requires a service/social/name column and a password column. Username/email, URL/website, and notes are optional.

Android does not import SQLite, JSON, or CSV. Android is intentionally limited to encrypted `.pmvault` viewing.

## Android read-only viewer

The Android app is in `android/` and must remain a viewer, not a second password editor.

Current behavior:

- user enters the encrypted export backup passphrase
- user chooses a file through the Android document picker
- selected file is copied/read into app memory
- shared decoder authenticates and decrypts locally
- entries can be searched by service or username
- fields can be revealed and copied
- there is no add, edit, delete, save, or export action
- decrypted entries are cleared on lock, backgrounding, and approximately three minutes of inactivity
- copied values are cleared after 30 seconds when the Android clipboard allows a safe comparison
- `expo-screen-capture` secure-screen protection is requested while the app is running
- no plaintext vault is written to app storage

The Android app uses explicit timeouts:

- document picker: five minutes
- file read: 30 seconds
- scrypt/AES decryption: three minutes

This prevents a storage-provider or cryptographic performance problem from presenting as an endless `Decrypting locally…` state.

### Android diagnostics screen

`android/App.tsx` contains a temporary Diagnostics screen accessible from:

- `Open diagnostics` on the authentication screen
- `Debug` in the loaded vault header

It records only operational information:

- app and secure-screen initialization
- document picker open/cancel/result
- filename, URI scheme, and byte counts
- file-read completion
- scrypt progress buckets
- decryption timing and entry count
- timeout and error messages
- lock/app-state events

It intentionally does not record passphrases, passwords, decrypted notes, or full file URIs. The screen has `Copy all logs` and `Clear` actions. Keep diagnostics temporary and safe; remove or redesign them before production if no longer needed.

## Android branding

`public/vault-logo.png` is the source Electron artwork. It is copied into:

- `android/assets/icon.png`
- `android/assets/splash-icon.png`
- `android/assets/android-icon-foreground.png`
- `android/assets/android-icon-monochrome.png`

The adaptive background remains the dark vault color configured in `android/app.json`. The React Native UI also renders `android/assets/icon.png` as its visible logo.

If the logo changes, update the source asset and all required Expo icon/splash slots, then run an Expo bundle/config check.

## Commands

From the repository root:

```powershell
npm install
npm run dev
npm run typecheck
npm run build
npm run dist
```

`npm run dist` builds the Electron app and creates a Windows NSIS installer through electron-builder. Typical outputs are under `dist/`, including the installer and `dist/win-unpacked/Password Manager.exe`.

From `android/`:

```powershell
npm install
npm start
npx tsc --noEmit
npx expo export --platform android
```

The Expo export is a JavaScript bundle validation; it is not the installable APK.

For a device-installable internal APK:

```powershell
npx eas-cli login
npx eas-cli build --platform android --profile preview
```

For a Google Play Android App Bundle:

```powershell
npx eas-cli build --platform android --profile production
```

`android/eas.json` has `development`, `preview`, and `production` profiles. The Android package identifier is `com.passwordmanager.vaultreader`.

## Verification expectations after changes

At minimum, run the checks relevant to the files changed:

- desktop changes: `npm run typecheck`
- Android TypeScript changes: `cd android; npx tsc --noEmit`
- Android Metro/import/asset changes: `cd android; npx expo export --platform android`
- vault format changes: create a real Electron-format envelope and verify Android/shared decryption with a known test entry; never commit the test vault or its passphrase

When changing encryption, verify both directions if possible and consider adding a versioned migration rather than silently accepting a new format.

## Coding and security rules for future AI agents

1. Never log, print, commit, or include real passwords, passphrases, decrypted notes, or full vault contents.
2. Preserve the Android viewer's read-only boundary. Do not add write APIs or a local plaintext database.
3. Keep Node/Electron APIs out of Android code. Android must use Expo-compatible APIs and the shared pure TypeScript decoder.
4. Keep Electron filesystem and crypto work in the main process, not the renderer.
5. Keep IPC methods narrow and validate all untrusted inputs in the main process.
6. Do not weaken sandboxing, context isolation, navigation restrictions, or clipboard clearing to solve a UI problem.
7. Treat `.pmvault` as sensitive encrypted data. Do not add cloud upload, analytics payloads, crash reports containing file data, or automatic backups without explicit user direction.
8. Use the export backup passphrase for exported files; do not assume it is the same as the desktop master passphrase.
9. Preserve existing user edits and inspect `git status` before broad changes.
10. Prefer small, verifiable changes and run the relevant typecheck/bundle commands before handoff.

## Known design limitations

No desktop or mobile application can honestly guarantee 100% security. Once a vault is unlocked, plaintext exists briefly in process memory and copied values are handled by the operating-system clipboard. Screenshot prevention and auto-lock are defense-in-depth, not absolute protection. Keep dependencies updated and protect the device account and backup passphrase.

The Android app currently uses pure JavaScript cryptography for cross-platform compatibility. On very slow devices, scrypt may take noticeable time; diagnostics and the bounded timeout are intentional. Do not reduce the KDF cost casually just to make the UI faster.
