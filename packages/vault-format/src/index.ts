import { gcm } from "@noble/ciphers/aes.js";
import { scryptAsync } from "@noble/hashes/scrypt.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";

function bytesToUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

export const VAULT_FORMAT = "password-manager-vault" as const;
export const VAULT_VERSION = 1 as const;
export const MAX_VAULT_BYTES = 10 * 1024 * 1024;

const KEY_LENGTH = 32;
const AAD = utf8ToBytes("password-manager-vault-v1");
const KDF = { name: "scrypt" as const, N: 131072, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

export type PasswordEntry = {
  id: string;
  service: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  createdAt: string;
  updatedAt: string;
};

type VaultData = { version: 1; entries: PasswordEntry[] };

export type VaultKeyDeriver = (passphrase: string, salt: Uint8Array) => Promise<Uint8Array>;

export type VaultEnvelope = {
  format: typeof VAULT_FORMAT;
  version: typeof VAULT_VERSION;
  kdf: typeof KDF;
  salt: string;
  iv: string;
  tag: string;
  ciphertext: string;
};

const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function base64ToBytes(value: unknown): Uint8Array {
  if (typeof value !== "string" || value.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
    throw new Error("Invalid vault data.");
  }
  const padding = value.endsWith("==") ? 2 : value.endsWith("=") ? 1 : 0;
  const output = new Uint8Array((value.length / 4) * 3 - padding);
  let outputIndex = 0;
  for (let index = 0; index < value.length; index += 4) {
    const a = BASE64_ALPHABET.indexOf(value[index]);
    const b = BASE64_ALPHABET.indexOf(value[index + 1]);
    const c = value[index + 2] === "=" ? 0 : BASE64_ALPHABET.indexOf(value[index + 2]);
    const d = value[index + 3] === "=" ? 0 : BASE64_ALPHABET.indexOf(value[index + 3]);
    if (a < 0 || b < 0 || c < 0 || d < 0) throw new Error("Invalid vault data.");
    const chunk = (a << 18) | (b << 12) | (c << 6) | d;
    if (outputIndex < output.length) output[outputIndex++] = (chunk >> 16) & 0xff;
    if (outputIndex < output.length) output[outputIndex++] = (chunk >> 8) & 0xff;
    if (outputIndex < output.length) output[outputIndex++] = chunk & 0xff;
  }
  return output;
}

function cleanText(value: unknown, maxLength: number): string {
  return typeof value === "string" ? value.trim().slice(0, maxLength) : "";
}

function validateEnvelope(value: unknown): VaultEnvelope {
  if (!value || typeof value !== "object") throw new Error("Invalid vault data.");
  const envelope = value as Partial<VaultEnvelope>;
  if (
    envelope.format !== VAULT_FORMAT || envelope.version !== VAULT_VERSION ||
    envelope.kdf?.name !== KDF.name || envelope.kdf.N !== KDF.N ||
    envelope.kdf.r !== KDF.r || envelope.kdf.p !== KDF.p
  ) throw new Error("Unsupported or invalid vault format.");
  return envelope as VaultEnvelope;
}

function validateVaultData(value: unknown): VaultData {
  if (!value || typeof value !== "object") throw new Error("Invalid vault contents.");
  const candidate = value as { version?: unknown; entries?: unknown };
  if (candidate.version !== VAULT_VERSION || !Array.isArray(candidate.entries)) throw new Error("Unsupported vault contents.");
  const entries = candidate.entries.map((entry) => {
    if (!entry || typeof entry !== "object") throw new Error("Invalid entry in vault.");
    const item = entry as Partial<PasswordEntry>;
    if (typeof item.id !== "string" || typeof item.password !== "string") throw new Error("Invalid entry in vault.");
    return {
      id: item.id.slice(0, 100), service: cleanText(item.service, 200), username: cleanText(item.username, 320),
      password: item.password.slice(0, 4096), url: cleanText(item.url, 1000),
      notes: typeof item.notes === "string" ? item.notes.slice(0, 10000) : "",
      createdAt: typeof item.createdAt === "string" ? item.createdAt : "",
      updatedAt: typeof item.updatedAt === "string" ? item.updatedAt : "",
    } satisfies PasswordEntry;
  });
  return { version: VAULT_VERSION, entries };
}

export async function decryptVaultBytes(
  bytes: Uint8Array,
  passphrase: string,
  onProgress?: (progress: number) => void,
  deriveKey?: VaultKeyDeriver,
): Promise<PasswordEntry[]> {
  if (bytes.byteLength > MAX_VAULT_BYTES) throw new Error("Vault file is too large.");
  if (passphrase.length < 12 || passphrase.length > 1024) throw new Error("Use the backup passphrase with at least 12 characters.");
  let envelope: VaultEnvelope;
  try {
    envelope = validateEnvelope(JSON.parse(bytesToUtf8(bytes)));
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error("Selected file is not a valid vault.");
    throw error;
  }
  const salt = base64ToBytes(envelope.salt);
  const iv = base64ToBytes(envelope.iv);
  const tag = base64ToBytes(envelope.tag);
  const ciphertext = base64ToBytes(envelope.ciphertext);
  if (salt.length !== 16 || iv.length !== 12 || tag.length !== 16 || ciphertext.length === 0) throw new Error("Invalid vault data.");
  try {
    const key = await (deriveKey ?? ((password, keySalt) => scryptAsync(password, keySalt, {
      N: KDF.N, r: KDF.r, p: KDF.p, dkLen: KEY_LENGTH, maxmem: KDF.maxmem, asyncTick: 10, onProgress,
    })))(passphrase, salt);
    if (key.byteLength !== KEY_LENGTH) throw new Error("Invalid derived key.");
    try {
      const authenticatedCiphertext = new Uint8Array(ciphertext.length + tag.length);
      authenticatedCiphertext.set(ciphertext);
      authenticatedCiphertext.set(tag, ciphertext.length);
      const plaintext = gcm(key, iv, AAD).decrypt(authenticatedCiphertext);
      return validateVaultData(JSON.parse(bytesToUtf8(plaintext))).entries;
    } finally {
      key.fill(0);
    }
  } catch {
    throw new Error("Unable to unlock: incorrect passphrase or corrupted vault.");
  }
}



