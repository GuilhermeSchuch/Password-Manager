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

export type EntryDraft = {
  id?: string;
  service: string;
  username: string;
  password: string;
  url: string;
  notes: string;
};

export type VaultSnapshot = {
  entries: PasswordEntry[];
};

export type VaultStatus = {
  hasVault: boolean;
  locked: boolean;
};

export type ImportResult = VaultSnapshot & {
  imported: number;
};

export type ExportResult = {
  canceled: boolean;
};
