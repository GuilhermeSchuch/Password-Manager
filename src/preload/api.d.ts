import type {
  EntryDraft,
  ExportResult,
  ImportResult,
  VaultSnapshot,
  VaultStatus,
} from "../shared/types";

export type PasswordManagerApi = {
  status(): Promise<VaultStatus>;
  create(passphrase: string): Promise<VaultSnapshot>;
  unlock(passphrase: string): Promise<VaultSnapshot>;
  lock(): Promise<void>;
  list(): Promise<VaultSnapshot>;
  saveEntry(draft: EntryDraft): Promise<VaultSnapshot>;
  deleteEntry(id: string): Promise<VaultSnapshot>;
  copyPassword(id: string): Promise<void>;
  exportVault(passphrase: string): Promise<ExportResult>;
  importVault(passphrase: string): Promise<ImportResult & { canceled: boolean }>;
};

declare global {
  interface Window {
    passwordManager: PasswordManagerApi;
  }
}
