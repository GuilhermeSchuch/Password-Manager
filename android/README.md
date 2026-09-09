# Vault Reader for Android

This is a separate Expo + React Native app for viewing encrypted `.pmvault` exports created by the Electron password manager.

## Behavior

- Imports `.pmvault` files through the Android system picker.
- Decrypts locally with the export backup passphrase.
- Keeps decrypted entries in memory only.
- Supports searching, revealing, and copying fields.
- Has no add, edit, delete, save, or export operation.
- Locks when sent to the background and after three minutes of inactivity.
- Clears copied values from the clipboard after 30 seconds when possible.
- Enables Android secure-screen protection while the app is running.

## Local development

```powershell
cd android
npm start
```

For a device-installable preview APK, install EAS CLI or use `npx`:

```powershell
cd android
npx eas-cli login
npx eas-cli build --platform android --profile preview
```

The `preview` profile produces an internal-distribution APK. The `production` profile produces an Android App Bundle for Google Play.

The shared decoder lives in `../packages/vault-format/src/index.ts` and matches the Electron export format: scrypt (`N=131072`, `r=8`, `p=1`) plus AES-256-GCM.
