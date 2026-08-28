import { contextBridge, ipcRenderer } from "electron";

import type {
  EntryDraft,
  ExportResult,
  ImportResult,
  VaultSnapshot,
  VaultStatus,
} from "../shared/types";

const api = {
  status: (): Promise<VaultStatus> => ipcRenderer.invoke("vault:status"),
  create: (passphrase: string): Promise<VaultSnapshot> => ipcRenderer.invoke("vault:create", passphrase),
  unlock: (passphrase: string): Promise<VaultSnapshot> => ipcRenderer.invoke("vault:unlock", passphrase),
  lock: (): Promise<void> => ipcRenderer.invoke("vault:lock"),
  list: (): Promise<VaultSnapshot> => ipcRenderer.invoke("vault:list"),
  saveEntry: (draft: EntryDraft): Promise<VaultSnapshot> => ipcRenderer.invoke("vault:save-entry", draft),
  deleteEntry: (id: string): Promise<VaultSnapshot> => ipcRenderer.invoke("vault:delete-entry", id),
  copyPassword: (id: string): Promise<void> => ipcRenderer.invoke("vault:copy-password", id),
  exportVault: (passphrase: string): Promise<ExportResult> => ipcRenderer.invoke("vault:export", passphrase),
  importVault: (passphrase: string): Promise<ImportResult & { canceled: boolean }> => ipcRenderer.invoke("vault:import", passphrase),
};

contextBridge.exposeInMainWorld("passwordManager", api);
