import { FormEvent, useEffect, useMemo, useState } from "react";

import { generatePassword, PASSWORD_LENGTH_MAX, PASSWORD_LENGTH_MIN, type PasswordGeneratorOptions } from "./password-generator";

import type {
  EntryDraft,
  PasswordEntry,
  VaultSnapshot,
  VaultStatus,
} from "../shared/types";

const emptyDraft: EntryDraft = {
  service: "",
  username: "",
  password: "",
  url: "",
  notes: "",
};

type PromptKind = "export" | "import" | null;
const defaultGeneratorOptions: PasswordGeneratorOptions = {
  length: 20,
  uppercase: true,
  lowercase: true,
  numbers: true,
  symbols: true,
};

type GeneratorToggle = Exclude<keyof PasswordGeneratorOptions, "length">;
const generatorGroups: Array<{ key: GeneratorToggle; label: string }> = [
  { key: "uppercase", label: "Uppercase" },
  { key: "lowercase", label: "Lowercase" },
  { key: "numbers", label: "Numbers" },
  { key: "symbols", label: "Symbols" },
];

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Something went wrong.";
}

function AuthScreen({ hasVault, onSubmit, busy, error }: {
  hasVault: boolean;
  onSubmit: (passphrase: string, confirmation: string) => void;
  busy: boolean;
  error: string;
}) {
  const [passphrase, setPassphrase] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const isCreate = !hasVault;

  function submit(event: FormEvent) {
    event.preventDefault();
    onSubmit(passphrase, confirmation);
  }

  return (
    <main className="auth-shell">
      <section className="auth-card">
        <div className="brand-mark"><img className="logo-image" src="/vault-logo.png" alt="" /></div>
        <p className="eyebrow">LOCAL · PRIVATE · ENCRYPTED</p>
        <h1>{isCreate ? "Create your vault" : "Welcome back"}</h1>
        <p className="auth-copy">
          {isCreate
            ? "Your vault never leaves this device. Choose a strong passphrase you will remember."
            : "Unlock your encrypted vault to access your passwords."}
        </p>
        <form onSubmit={submit} className="auth-form">
          <label>
            Master passphrase
            <input
              type="password"
              autoFocus
              value={passphrase}
              onChange={(event) => setPassphrase(event.target.value)}
              placeholder="At least 12 characters"
              autoComplete={isCreate ? "new-password" : "current-password"}
            />
          </label>
          {isCreate && (
            <label>
              Confirm passphrase
              <input
                type="password"
                value={confirmation}
                onChange={(event) => setConfirmation(event.target.value)}
                placeholder="Type it again"
                autoComplete="new-password"
              />
            </label>
          )}
          {error && <div className="form-error">{error}</div>}
          <button className="primary-button full-width" disabled={busy || passphrase.length < 12} type="submit">
            {busy ? "Working…" : isCreate ? "Create encrypted vault" : "Unlock vault"}
          </button>
        </form>
        <div className="security-note">
          <span>▣</span>
          <p>Encryption happens locally. The app cannot recover a forgotten master passphrase.</p>
        </div>
      </section>
    </main>
  );
}

function EntryForm({ draft, editing, onChange, onSave, onDelete, onNew, onGenerate, showPassword, onTogglePassword }: {
  draft: EntryDraft;
  editing: boolean;
  onChange: (field: keyof EntryDraft, value: string) => void;
  onSave: (event: FormEvent) => void;
  onDelete: () => void;
  onNew: () => void;
  onGenerate: (options: PasswordGeneratorOptions) => void;
  showPassword: boolean;
  onTogglePassword: () => void;
}) {
  const [generatorOptions, setGeneratorOptions] = useState<PasswordGeneratorOptions>(defaultGeneratorOptions);
  const enabledGroupCount = generatorGroups.filter(({ key }) => generatorOptions[key]).length;

  function updateGeneratorOption(key: GeneratorToggle, enabled: boolean) {
    setGeneratorOptions((current) => ({ ...current, [key]: enabled }));
  }

  function generate() {
    onGenerate(generatorOptions);
  }

  return (
    <form className="entry-form" onSubmit={onSave}>
      <div className="form-heading">
        <div>
          <p className="eyebrow">{editing ? "EDIT ENTRY" : "NEW ENTRY"}</p>
          <h2>{editing ? draft.service || "Edit password" : "Add a password"}</h2>
        </div>
        {editing && <button type="button" className="ghost-button compact" onClick={onNew}>New</button>}
      </div>

      <label>
        Service <span className="required">*</span>
        <input value={draft.service} onChange={(event) => onChange("service", event.target.value)} placeholder="e.g. LinkedIn" autoFocus={!editing} />
      </label>
      <label>
        Username or email
        <input value={draft.username} onChange={(event) => onChange("username", event.target.value)} placeholder="name@example.com" />
      </label>
      <label>
        Password <span className="required">*</span>
        <div className="password-input">
          <input
            type={showPassword ? "text" : "password"}
            value={draft.password}
            onChange={(event) => onChange("password", event.target.value)}
            placeholder="Enter or generate a password"
            autoComplete="new-password"
          />
          <button type="button" className="input-action" onClick={onTogglePassword} title={showPassword ? "Hide password" : "Show password"}>{showPassword ? "◉" : "○"}</button>
          <button type="button" className="input-action generator-action" onClick={generate} title="Generate secure password">✦</button>
        </div>
      </label>

      <section className="generator-panel" aria-label="Password generator">
        <div className="generator-heading">
          <div>
            <strong>Generate password</strong>
            <small>Choose the character types and length.</small>
          </div>
          <button type="button" className="secondary-button generator-button" onClick={generate} disabled={enabledGroupCount === 0}>Generate</button>
        </div>
        <label className="length-control">
          <span>Length <output>{generatorOptions.length}</output></span>
          <input
            type="range"
            min={PASSWORD_LENGTH_MIN}
            max={PASSWORD_LENGTH_MAX}
            value={generatorOptions.length}
            onChange={(event) => setGeneratorOptions((current) => ({ ...current, length: Number(event.target.value) }))}
          />
        </label>
        <div className="generator-options">
          {generatorGroups.map(({ key, label }) => (
            <label className="generator-option" key={key}>
              <input type="checkbox" checked={generatorOptions[key]} onChange={(event) => updateGeneratorOption(key, event.target.checked)} />
              <span>{label}</span>
            </label>
          ))}
        </div>
        {enabledGroupCount === 0 && <p className="generator-error">Select at least one character group.</p>}
      </section>

      <label>
        Website
        <input value={draft.url} onChange={(event) => onChange("url", event.target.value)} placeholder="https://" />
      </label>
      <label>
        Notes
        <textarea value={draft.notes} onChange={(event) => onChange("notes", event.target.value)} placeholder="Recovery codes, reminders, or other details" rows={4} />
      </label>
      <button className="primary-button full-width save-button" type="submit">
        {editing ? "Save changes" : "Save password"}
      </button>
      {editing && (
        <button className="danger-button full-width" type="button" onClick={onDelete}>Delete entry</button>
      )}
    </form>
  );
}
function App() {
  const [status, setStatus] = useState<VaultStatus | null>(null);
  const [entries, setEntries] = useState<PasswordEntry[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [draft, setDraft] = useState<EntryDraft>(emptyDraft);
  const [search, setSearch] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [toast, setToast] = useState("");
  const [promptKind, setPromptKind] = useState<PromptKind>(null);
  const [promptValue, setPromptValue] = useState("");
  const [promptError, setPromptError] = useState("");

  useEffect(() => {
    window.passwordManager.status()
      .then(setStatus)
      .catch((reason) => setError(errorMessage(reason)));
  }, []);

  useEffect(() => {
    if (!toast) return;
    const timeout = window.setTimeout(() => setToast(""), 3500);
    return () => window.clearTimeout(timeout);
  }, [toast]);

  useEffect(() => {
    if (!status?.hasVault || status.locked) return;
    let timer = window.setTimeout(lockAfterInactivity, 5 * 60 * 1000);
    const resetTimer = () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(lockAfterInactivity, 5 * 60 * 1000);
    };
    const activityEvents = ["mousedown", "keydown", "mousemove", "touchstart"];
    activityEvents.forEach((eventName) => window.addEventListener(eventName, resetTimer));
    return () => {
      window.clearTimeout(timer);
      activityEvents.forEach((eventName) => window.removeEventListener(eventName, resetTimer));
    };
  }, [status?.hasVault, status?.locked]);

  function lockAfterInactivity() {
    void window.passwordManager.lock().then(() => {
      setEntries([]);
      setSelectedId(null);
      setDraft({ ...emptyDraft });
      setStatus({ hasVault: true, locked: true });
      setToast("Vault locked after 5 minutes of inactivity");
    });
  }

  const filteredEntries = useMemo(() => {
    const query = search.trim().toLocaleLowerCase();
    return entries.filter((entry) =>
      !query ||
      entry.service.toLocaleLowerCase().includes(query) ||
      entry.username.toLocaleLowerCase().includes(query),
    );
  }, [entries, search]);

  const selectedEntry = entries.find((entry) => entry.id === selectedId);

  function applySnapshot(snapshot: VaultSnapshot) {
    setEntries(snapshot.entries);
    setSelectedId((current) => current && snapshot.entries.some((entry) => entry.id === current) ? current : null);
  }

  async function authenticate(passphrase: string, confirmation: string) {
    setBusy(true);
    setError("");
    try {
      if (!status?.hasVault) {
        if (passphrase !== confirmation) throw new Error("Passphrases do not match.");
        const snapshot = await window.passwordManager.create(passphrase);
        applySnapshot(snapshot);
        setStatus({ hasVault: true, locked: false });
      } else {
        const snapshot = await window.passwordManager.unlock(passphrase);
        applySnapshot(snapshot);
        setStatus({ hasVault: true, locked: false });
      }
    } catch (reason) {
      setError(errorMessage(reason));
    } finally {
      setBusy(false);
    }
  }

  function selectEntry(entry: PasswordEntry) {
    setSelectedId(entry.id);
    setDraft({
      id: entry.id,
      service: entry.service,
      username: entry.username,
      password: entry.password,
      url: entry.url,
      notes: entry.notes,
    });
    setShowPassword(false);
    setError("");
  }

  function newEntry() {
    setSelectedId(null);
    setDraft({ ...emptyDraft });
    setShowPassword(false);
    setError("");
  }

  function updateDraft(field: keyof EntryDraft, value: string) {
    setDraft((current) => ({ ...current, [field]: value }));
  }

  async function saveEntry(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const snapshot = await window.passwordManager.saveEntry(draft);
      applySnapshot(snapshot);
      const saved = snapshot.entries.find((entry) => entry.service === draft.service && (!draft.id || entry.id === draft.id));
      if (saved) selectEntry(saved);
      setToast(draft.id ? "Password updated" : "Password saved");
    } catch (reason) {
      setError(errorMessage(reason));
    } finally {
      setBusy(false);
    }
  }

  async function deleteEntry() {
    if (!selectedId || !window.confirm("Delete this password permanently?")) return;
    setBusy(true);
    setError("");
    try {
      const snapshot = await window.passwordManager.deleteEntry(selectedId);
      applySnapshot(snapshot);
      newEntry();
      setToast("Entry deleted");
    } catch (reason) {
      setError(errorMessage(reason));
    } finally {
      setBusy(false);
    }
  }

  async function copyPassword() {
    if (!selectedId) return;
    try {
      await window.passwordManager.copyPassword(selectedId);
      setToast("Password copied · clipboard clears in 30 seconds");
    } catch (reason) {
      setError(errorMessage(reason));
    }
  }

  async function lockVault() {
    await window.passwordManager.lock();
    setEntries([]);
    setSelectedId(null);
    setDraft({ ...emptyDraft });
    setStatus({ hasVault: true, locked: true });
    setToast("Vault locked");
  }

  function generateForEntry(options: PasswordGeneratorOptions) {
    try {
      updateDraft("password", generatePassword(options));
      setShowPassword(true);
      setError("");
      setToast("Secure password generated");
    } catch (reason) {
      setError(errorMessage(reason));
    }
  }

  function openPrompt(kind: PromptKind) {
    setPromptKind(kind);
    setPromptValue("");
    setPromptError("");
  }

  async function submitPrompt(event: FormEvent) {
    event.preventDefault();
    if (promptKind === "export" && promptValue.length < 12) {
      setPromptError("Use a passphrase with at least 12 characters.");
      return;
    }
    setBusy(true);
    setPromptError("");
    try {
      if (promptKind === "export") {
        const result = await window.passwordManager.exportVault(promptValue);
        if (!result.canceled) setToast("Encrypted vault exported");
      } else if (promptKind === "import") {
        const result = await window.passwordManager.importVault(promptValue);
        if (!result.canceled) {
          applySnapshot(result);
          setToast(result.imported + " new password" + (result.imported === 1 ? "" : "s") + " imported");
        }
      }
      setPromptKind(null);
      setPromptValue("");
    } catch (reason) {
      setPromptError(errorMessage(reason));
    } finally {
      setBusy(false);
    }
  }

  if (!status) {
    return <main className="loading-shell"><div className="spinner" /><span>Preparing your vault…</span></main>;
  }

  if (status.locked || !status.hasVault) {
    return <AuthScreen hasVault={status.hasVault} onSubmit={authenticate} busy={busy} error={error} />;
  }

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="brand-mark small"><img className="logo-image" src="/vault-logo.png" alt="" /></div>
          <div><strong>Vault</strong><span>password manager</span></div>
        </div>
        <div className="sidebar-section">
          <span className="sidebar-label">Your vault</span>
          <button className="nav-item active"><span>▦</span> All passwords <b>{entries.length}</b></button>
        </div>
        <div className="sidebar-section">
          <span className="sidebar-label">Tools</span>
          <button className="nav-item" onClick={() => openPrompt("import")}><span>↓</span> Import passwords</button>
          <button className="nav-item" onClick={() => openPrompt("export")}><span>↑</span> Export encrypted</button>
        </div>
        <div className="sidebar-footer">
          <div className="encryption-badge"><span>●</span><div><strong>Encrypted locally</strong><small>AES-256-GCM vault</small></div></div>
          <button className="lock-button" onClick={lockVault}><span>⌑</span> Lock vault</button>
        </div>
      </aside>

      <section className="content">
        <header className="topbar">
          <div>
            <p className="eyebrow">SECURE VAULT</p>
            <h1>All passwords</h1>
          </div>
          <div className="topbar-actions">
            <label className="search-box">
              <span className="search-icon" aria-hidden="true">
                <svg viewBox="0 0 24 24" focusable="false">
                  <circle cx="10.8" cy="10.8" r="6.8" />
                  <path d="m16 16 5 5" />
                </svg>
              </span>
              <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search services or usernames" />
              {search && <button type="button" onClick={() => setSearch("")}>×</button>}
            </label>
            <button className="primary-button new-password-button" onClick={newEntry}>
              <span className="button-leading" aria-hidden="true">+</span>
              <span>New password</span>
            </button>
          </div>
        </header>

        <div className="workspace">
          <section className="list-panel">
            <div className="list-meta"><span>{filteredEntries.length} {filteredEntries.length === 1 ? "entry" : "entries"}</span>{search && <span>matching “{search}”</span>}</div>
            <div className="entry-list">
              {filteredEntries.length === 0 ? (
                <div className="empty-state">
                  <div className="empty-icon">{search ? "⌕" : "✦"}</div>
                  <h3>{search ? "No matches found" : "Your vault is empty"}</h3>
                  <p>{search ? "Try a different service or username." : "Add your first password to get started."}</p>
                  {!search && <button className="secondary-button" onClick={newEntry}>Add password</button>}
                </div>
              ) : filteredEntries.map((entry) => (
                <button key={entry.id} className={"entry-row" + (entry.id === selectedId ? " selected" : "")} onClick={() => selectEntry(entry)}>
                  <span className="service-avatar">{entry.service.slice(0, 1).toUpperCase()}</span>
                  <span className="entry-summary"><strong>{entry.service}</strong><small>{entry.username || "No username"}</small></span>
                  <span className="entry-chevron">›</span>
                </button>
              ))}
            </div>
          </section>

          <section className="detail-panel">
            <EntryForm
              draft={draft}
              editing={Boolean(selectedEntry)}
              onChange={updateDraft}
              onSave={saveEntry}
              onDelete={deleteEntry}
              onNew={newEntry}
              onGenerate={generateForEntry}
              showPassword={showPassword}
              onTogglePassword={() => setShowPassword((current) => !current)}
            />
            {selectedEntry && (
              <button className="copy-button" onClick={copyPassword}><span>▣</span> Copy password</button>
            )}
            {error && <div className="inline-error">{error}</div>}
          </section>
        </div>
      </section>

      {toast && <div className="toast"><span>✓</span>{toast}</div>}

      {promptKind && (
        <div className="modal-backdrop" role="presentation">
          <form className="modal-card" onSubmit={submitPrompt}>
            <button type="button" className="modal-close" onClick={() => setPromptKind(null)}>×</button>
            <div className="modal-icon">{promptKind === "export" ? "↑" : "↓"}</div>
            <p className="eyebrow">{promptKind === "export" ? "PROTECT YOUR BACKUP" : "IMPORT A BACKUP"}</p>
            <h2>{promptKind === "export" ? "Export encrypted vault" : "Import passwords"}</h2>
            <p>{promptKind === "export" ? "Choose a passphrase for this backup. It can be different from your master passphrase." : "Select an encrypted .pmvault, the legacy passwords.db, JSON, or CSV file next. The passphrase is only needed for encrypted vault backups."}</p>
            <label>{promptKind === "export" ? "Backup passphrase" : "Backup passphrase (for .pmvault)"}<input autoFocus type="password" value={promptValue} onChange={(event) => setPromptValue(event.target.value)} placeholder={promptKind === "export" ? "At least 12 characters" : "Leave blank for JSON or CSV"} /></label>
            {promptError && <div className="form-error">{promptError}</div>}
            <button className="primary-button full-width" disabled={busy} type="submit">{promptKind === "export" ? "Choose location & export" : "Choose file & import"}</button>
          </form>
        </div>
      )}
    </main>
  );
}

export default App;


