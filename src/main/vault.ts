import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  randomUUID,
  scrypt as scryptCallback,
} from "node:crypto";
import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";

import initSqlJs from "sql.js";

import type {
  EntryDraft,
  ImportResult,
  PasswordEntry,
  VaultSnapshot,
} from "../shared/types";

const KEY_LENGTH = 32;
const AAD = Buffer.from("password-manager-vault-v1", "utf8");
const MAX_IMPORT_BYTES = 10 * 1024 * 1024;
const KDF = {
  name: "scrypt",
  N: 131072,
  r: 8,
  p: 1,
  maxmem: 256 * 1024 * 1024,
} as const;

type VaultData = {
  version: 1;
  entries: PasswordEntry[];
};

type VaultEnvelope = {
  format: "password-manager-vault";
  version: 1;
  kdf: typeof KDF;
  salt: string;
  iv: string;
  tag: string;
  ciphertext: string;
};

function toBase64(value: Buffer): string {
  return value.toString("base64");
}

function fromBase64(value: unknown): Buffer {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
    throw new Error("Invalid vault data.");
  }
  return Buffer.from(value, "base64");
}

function assertPassphrase(passphrase: string): void {
  if (typeof passphrase !== "string" || passphrase.length < 12) {
    throw new Error("Use a passphrase with at least 12 characters.");
  }
  if (passphrase.length > 1024) {
    throw new Error("Passphrase is too long.");
  }
}

async function deriveKey(passphrase: string, salt: Buffer): Promise<Buffer> {
  const derived = await new Promise<Buffer>((resolve, reject) => {
    scryptCallback(passphrase, salt, KEY_LENGTH, {
      N: KDF.N,
      r: KDF.r,
      p: KDF.p,
      maxmem: KDF.maxmem,
    }, (error, key) => {
      if (error) reject(error);
      else resolve(key);
    });
  });
  return Buffer.from(derived);
}

function validateEnvelope(envelope: VaultEnvelope): void {
  if (
    envelope.format !== "password-manager-vault" ||
    envelope.version !== 1 ||
    envelope.kdf?.name !== KDF.name ||
    envelope.kdf.N !== KDF.N ||
    envelope.kdf.r !== KDF.r ||
    envelope.kdf.p !== KDF.p
  ) {
    throw new Error("Unsupported or invalid vault format.");
  }
}

async function encryptDataWithKey(
  data: VaultData,
  key: Buffer,
  salt: Buffer,
): Promise<VaultEnvelope> {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(AAD);
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(data), "utf8"),
    cipher.final(),
  ]);
  return {
    format: "password-manager-vault",
    version: 1,
    kdf: KDF,
    salt: toBase64(salt),
    iv: toBase64(iv),
    tag: toBase64(cipher.getAuthTag()),
    ciphertext: toBase64(ciphertext),
  };
}

async function encryptData(data: VaultData, passphrase: string): Promise<VaultEnvelope> {
  assertPassphrase(passphrase);
  const salt = randomBytes(16);
  const key = await deriveKey(passphrase, salt);
  try {
    return await encryptDataWithKey(data, key, salt);
  } finally {
    key.fill(0);
  }
}

async function decryptDataWithKey(envelope: VaultEnvelope, key: Buffer): Promise<VaultData> {
  validateEnvelope(envelope);
  const salt = fromBase64(envelope.salt);
  const iv = fromBase64(envelope.iv);
  const tag = fromBase64(envelope.tag);
  const ciphertext = fromBase64(envelope.ciphertext);
  if (salt.length !== 16 || iv.length !== 12 || tag.length !== 16 || ciphertext.length === 0) {
    throw new Error("Invalid vault data.");
  }
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAAD(AAD);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]).toString("utf8");
    return validateVaultData(JSON.parse(plaintext));
  } catch {
    throw new Error("Unable to unlock: incorrect passphrase or corrupted vault.");
  }
}

async function decryptData(envelope: VaultEnvelope, passphrase: string): Promise<VaultData> {
  assertPassphrase(passphrase);
  const salt = fromBase64(envelope.salt);
  if (salt.length !== 16) throw new Error("Invalid vault data.");
  const key = await deriveKey(passphrase, salt);
  try {
    return await decryptDataWithKey(envelope, key);
  } finally {
    key.fill(0);
  }
}

function cleanText(value: unknown, maxLength: number): string {
  return typeof value === "string" ? value.trim().slice(0, maxLength) : "";
}

function validateVaultData(value: unknown): VaultData {
  if (!value || typeof value !== "object") {
    throw new Error("Invalid vault contents.");
  }
  const candidate = value as { version?: unknown; entries?: unknown };
  if (candidate.version !== 1 || !Array.isArray(candidate.entries)) {
    throw new Error("Unsupported vault contents.");
  }
  const entries = candidate.entries.map((entry) => {
    if (!entry || typeof entry !== "object") {
      throw new Error("Invalid entry in vault.");
    }
    const item = entry as Partial<PasswordEntry>;
    if (typeof item.id !== "string" || typeof item.password !== "string") {
      throw new Error("Invalid entry in vault.");
    }
    return {
      id: item.id.slice(0, 100),
      service: cleanText(item.service, 200),
      username: cleanText(item.username, 320),
      password: item.password.slice(0, 4096),
      url: cleanText(item.url, 1000),
      notes: typeof item.notes === "string" ? item.notes.slice(0, 10000) : "",
      createdAt: typeof item.createdAt === "string" ? item.createdAt : new Date().toISOString(),
      updatedAt: typeof item.updatedAt === "string" ? item.updatedAt : new Date().toISOString(),
    };
  });
  return { version: 1, entries };
}

function emptyData(): VaultData {
  return { version: 1, entries: [] };
}

async function writeBytesAtomic(filePath: string, bytes: Buffer): Promise<void> {
  const parent = filePath.slice(0, Math.max(filePath.lastIndexOf("/"), filePath.lastIndexOf("\\")));
  if (parent) await mkdir(parent, { recursive: true });
  const temporaryPath = filePath + "." + randomUUID() + ".tmp";
  try {
    await writeFile(temporaryPath, bytes, { mode: 0o600 });
    await chmod(temporaryPath, 0o600);
    await rename(temporaryPath, filePath);
    await chmod(filePath, 0o600);
  } catch (error) {
    try {
      await rename(temporaryPath, temporaryPath + ".failed");
    } catch {
      // Best effort cleanup; never mask the original write error.
    }
    throw error;
  }
}

async function writeEncryptedFile(filePath: string, data: VaultData, passphrase: string): Promise<void> {
  const envelope = await encryptData(data, passphrase);
  await writeBytesAtomic(filePath, Buffer.from(JSON.stringify(envelope), "utf8"));
}

async function writeEncryptedFileWithKey(
  filePath: string,
  data: VaultData,
  key: Buffer,
  salt: Buffer,
): Promise<void> {
  const envelope = await encryptDataWithKey(data, key, salt);
  await writeBytesAtomic(filePath, Buffer.from(JSON.stringify(envelope), "utf8"));
}

async function readEnvelope(filePath: string): Promise<VaultEnvelope> {
  const bytes = await readFile(filePath);
  if (bytes.byteLength > MAX_IMPORT_BYTES) throw new Error("Vault file is too large.");
  try {
    return JSON.parse(bytes.toString("utf8")) as VaultEnvelope;
  } catch {
    throw new Error("Selected file is not a valid vault.");
  }
}

async function readEncryptedFile(filePath: string, passphrase: string): Promise<VaultData> {
  return decryptData(await readEnvelope(filePath), passphrase);
}

function normalizeDraft(draft: EntryDraft, existing?: PasswordEntry): PasswordEntry {
  const service = cleanText(draft.service, 200);
  const password = typeof draft.password === "string" ? draft.password.slice(0, 4096) : "";
  if (!service || !password) throw new Error("Service and password are required.");
  const now = new Date().toISOString();
  return {
    id: existing?.id ?? randomUUID(),
    service,
    username: cleanText(draft.username, 320),
    password,
    url: cleanText(draft.url, 1000),
    notes: typeof draft.notes === "string" ? draft.notes.slice(0, 10000) : "",
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
  };
}

function importedEntry(value: unknown): EntryDraft | null {
  if (!value || typeof value !== "object") return null;
  const item = value as Record<string, unknown>;
  const service = item.service ?? item.social ?? item.name;
  const password = item.password;
  if (typeof service !== "string" || typeof password !== "string") return null;
  return {
    service,
    username: typeof item.username === "string" ? item.username : typeof item.email === "string" ? item.email : "",
    password,
    url: typeof item.url === "string" ? item.url : "",
    notes: typeof item.notes === "string" ? item.notes : "",
  };
}

function parseCsvLine(line: string): string[] {
  const values: string[] = [];
  let current = "";
  let quoted = false;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (character === '"' && line[index + 1] === '"') {
      current += '"';
      index += 1;
    } else if (character === '"') {
      quoted = !quoted;
    } else if (character === "," && !quoted) {
      values.push(current);
      current = "";
    } else {
      current += character;
    }
  }
  values.push(current);
  return values;
}

async function readPlainImport(filePath: string): Promise<EntryDraft[]> {
  const bytes = await readFile(filePath);
  if (bytes.byteLength > MAX_IMPORT_BYTES) throw new Error("Import file is too large.");
  const extension = filePath.toLowerCase().slice(filePath.lastIndexOf("."));
  const text = bytes.toString("utf8");
  if (extension === ".json") {
    const parsed: unknown = JSON.parse(text);
    const values = Array.isArray(parsed)
      ? parsed
      : parsed && typeof parsed === "object" && Array.isArray((parsed as { entries?: unknown }).entries)
        ? (parsed as { entries: unknown[] }).entries
        : [];
    return values.map(importedEntry).filter((entry): entry is EntryDraft => entry !== null);
  }
  if (extension === ".csv") {
    const lines = text.split(/\r?\n/).filter((line) => line.trim());
    if (lines.length < 2) return [];
    const headers = parseCsvLine(lines[0]).map((header) => header.trim().toLowerCase());
    const column = (...names: string[]) => names.map((name) => headers.indexOf(name)).find((index) => index >= 0) ?? -1;
    const serviceIndex = column("service", "social", "name");
    const passwordIndex = column("password");
    const usernameIndex = column("username", "email");
    const urlIndex = column("url", "website");
    const notesIndex = column("notes");
    if (serviceIndex < 0 || passwordIndex < 0) throw new Error("CSV must contain service and password columns.");
    return lines.slice(1).map((line) => {
      const cells = parseCsvLine(line);
      return importedEntry({
        service: cells[serviceIndex] ?? "",
        password: cells[passwordIndex] ?? "",
        username: usernameIndex >= 0 ? cells[usernameIndex] ?? "" : "",
        url: urlIndex >= 0 ? cells[urlIndex] ?? "" : "",
        notes: notesIndex >= 0 ? cells[notesIndex] ?? "" : "",
      });
    }).filter((entry): entry is EntryDraft => entry !== null);
  }
  throw new Error("Use an encrypted .pmvault, .json, or .csv file.");
}

async function readLegacySqliteImport(filePath: string, wasmPath: string): Promise<EntryDraft[]> {
  const bytes = await readFile(filePath);
  if (bytes.byteLength > MAX_IMPORT_BYTES) throw new Error("Import file is too large.");
  const SQL = await initSqlJs({ locateFile: () => wasmPath });
  const database = new SQL.Database(bytes);
  try {
    const result = database.exec("SELECT social, password FROM socials ORDER BY social COLLATE NOCASE");
    const rows: unknown[][] = result[0]?.values ?? [];
    return rows.map((row) => importedEntry({ social: row[0], password: row[1] }))
      .filter((entry): entry is EntryDraft => entry !== null);
  } catch {
    throw new Error("Could not read this SQLite file. Expected a socials table with social and password columns.");
  } finally {
    database.close();
  }
}

export class VaultStore {
  private key: Buffer | null = null;
  private salt: Buffer | null = null;
  private data: VaultData | null = null;

  public constructor(
    private readonly filePath: string,
    private readonly sqliteWasmPath: string,
  ) {}

  public async hasVault(): Promise<boolean> {
    try {
      await readFile(this.filePath);
      return true;
    } catch {
      return false;
    }
  }

  public isUnlocked(): boolean {
    return this.key !== null && this.data !== null;
  }

  public async create(passphrase: string): Promise<VaultSnapshot> {
    assertPassphrase(passphrase);
    if (await this.hasVault()) throw new Error("A vault already exists.");
    this.salt = randomBytes(16);
    this.key = await deriveKey(passphrase, this.salt);
    this.data = emptyData();
    try {
      await this.persist();
      return this.snapshot();
    } catch (error) {
      this.lock();
      throw error;
    }
  }

  public async unlock(passphrase: string): Promise<VaultSnapshot> {
    assertPassphrase(passphrase);
    const envelope = await readEnvelope(this.filePath);
    const salt = fromBase64(envelope.salt);
    if (salt.length !== 16) throw new Error("Invalid vault data.");
    const key = await deriveKey(passphrase, salt);
    try {
      const loaded = await decryptDataWithKey(envelope, key);
      this.key = key;
      this.salt = salt;
      this.data = loaded;
      return this.snapshot();
    } catch (error) {
      key.fill(0);
      throw error;
    }
  }

  public lock(): void {
    this.key?.fill(0);
    this.key = null;
    this.salt = null;
    this.data = null;
  }

  public snapshot(): VaultSnapshot {
    this.requireUnlocked();
    return { entries: this.data!.entries.map((entry) => ({ ...entry })) };
  }

  public async saveEntry(draft: EntryDraft): Promise<VaultSnapshot> {
    this.requireUnlocked();
    const existing = draft.id ? this.data!.entries.find((entry) => entry.id === draft.id) : undefined;
    const entry = normalizeDraft(draft, existing);
    const duplicate = this.data!.entries.find(
      (item) => item.id !== entry.id &&
        item.service.toLocaleLowerCase() === entry.service.toLocaleLowerCase() &&
        item.username.toLocaleLowerCase() === entry.username.toLocaleLowerCase(),
    );
    if (duplicate) throw new Error("An entry for this service and username already exists.");
    if (existing) {
      this.data!.entries = this.data!.entries.map((item) => item.id === entry.id ? entry : item);
    } else {
      this.data!.entries.push(entry);
    }
    await this.persist();
    return this.snapshot();
  }

  public async deleteEntry(id: string): Promise<VaultSnapshot> {
    this.requireUnlocked();
    this.data!.entries = this.data!.entries.filter((entry) => entry.id !== id);
    await this.persist();
    return this.snapshot();
  }

  public async exportTo(filePath: string, passphrase: string): Promise<void> {
    this.requireUnlocked();
    await writeEncryptedFile(filePath, this.data!, passphrase);
  }

  public async importFrom(filePath: string, passphrase: string): Promise<ImportResult> {
    this.requireUnlocked();
    const extension = filePath.toLowerCase().slice(filePath.lastIndexOf("."));
    const importedData = extension === ".pmvault"
      ? await readEncryptedFile(filePath, passphrase)
      : extension === ".db" || extension === ".sqlite" || extension === ".sqlite3"
        ? { version: 1 as const, entries: (await readLegacySqliteImport(filePath, this.sqliteWasmPath)).map((draft) => normalizeDraft(draft)) }
      : { version: 1 as const, entries: (await readPlainImport(filePath)).map((draft) => normalizeDraft(draft)) };
    const existingKeys = new Set(
      this.data!.entries.map((entry) => [entry.service.toLocaleLowerCase(), entry.username.toLocaleLowerCase()].join("\u0000")),
    );
    const additions = importedData.entries.filter((entry) => {
      const key = [entry.service.toLocaleLowerCase(), entry.username.toLocaleLowerCase()].join("\u0000");
      if (existingKeys.has(key)) return false;
      existingKeys.add(key);
      return true;
    });
    this.data!.entries.push(...additions);
    await this.persist();
    return { imported: additions.length, ...this.snapshot() };
  }

  public getPassword(id: string): string {
    this.requireUnlocked();
    const entry = this.data!.entries.find((item) => item.id === id);
    if (!entry) throw new Error("Entry not found.");
    return entry.password;
  }

  private requireUnlocked(): void {
    if (!this.isUnlocked()) throw new Error("Vault is locked.");
  }

  private async persist(): Promise<void> {
    this.requireUnlocked();
    await writeEncryptedFileWithKey(this.filePath, this.data!, this.key!, this.salt!);
  }
}
