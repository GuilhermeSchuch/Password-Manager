import { app, BrowserWindow, clipboard, dialog, ipcMain, Menu, net, protocol } from "electron";
import path from "node:path";
import { pathToFileURL } from "node:url";

import type { EntryDraft } from "../shared/types";
import { VaultStore } from "./vault";

protocol.registerSchemesAsPrivileged([
  {
    scheme: "app",
    privileges: { standard: true, secure: true, supportFetchAPI: true, allowServiceWorkers: false },
  },
]);
app.enableSandbox();

let mainWindow: BrowserWindow | null = null;
let clipboardTimer: NodeJS.Timeout | null = null;
let clipboardValue = "";
let vault: VaultStore;

const isDev = Boolean(process.env.VITE_DEV_SERVER_URL);
const sqliteWasmPath = app.isPackaged
  ? path.join(process.resourcesPath, "app.asar.unpacked", "node_modules", "sql.js", "dist", "sql-wasm.wasm")
  : path.join(app.getAppPath(), "node_modules", "sql.js", "dist", "sql-wasm.wasm");

function assertSender(event: Electron.IpcMainInvokeEvent): void {
  if (!mainWindow || event.sender !== mainWindow.webContents) {
    throw new Error("Unauthorized IPC sender.");
  }
  if (!event.senderFrame) throw new Error("Unauthorized IPC frame.");
  const url = new URL(event.senderFrame.url);
  const allowed = (url.protocol === "app:" && url.hostname === "bundle")
    || (isDev && url.protocol === "http:" && url.hostname === "127.0.0.1" && url.port === "5173");
  if (!allowed) throw new Error("Unauthorized IPC origin.");
}

function assertString(value: unknown, name: string, maxLength = 1024): asserts value is string {
  if (typeof value !== "string" || value.length > maxLength) {
    throw new Error("Invalid " + name + ".");
  }
}

function assertEntryDraft(value: unknown): asserts value is EntryDraft {
  if (!value || typeof value !== "object") throw new Error("Invalid entry.");
  const entry = value as Partial<EntryDraft>;
  for (const field of ["service", "username", "password", "url", "notes"] as const) {
    assertString(entry[field], field, field === "notes" ? 10000 : field === "password" ? 4096 : 1000);
  }
  if (entry.id !== undefined) assertString(entry.id, "entry id", 100);
}

function clearOwnedClipboard(): void {
  if (clipboardValue && clipboard.readText() === clipboardValue) clipboard.clear();
  clipboardValue = "";
  if (clipboardTimer) {
    clearTimeout(clipboardTimer);
    clipboardTimer = null;
  }
}

function registerIpc(): void {
  ipcMain.handle("vault:status", (event) => {
    assertSender(event);
    return vault.hasVault().then((hasVault) => ({ hasVault, locked: hasVault && !vault.isUnlocked() }));
  });

  ipcMain.handle("vault:create", (event, passphrase: unknown) => {
    assertSender(event);
    assertString(passphrase, "passphrase", 1024);
    return vault.create(passphrase);
  });

  ipcMain.handle("vault:unlock", (event, passphrase: unknown) => {
    assertSender(event);
    assertString(passphrase, "passphrase", 1024);
    return vault.unlock(passphrase);
  });

  ipcMain.handle("vault:lock", (event) => {
    assertSender(event);
    clearOwnedClipboard();
    vault.lock();
  });

  ipcMain.handle("vault:list", (event) => {
    assertSender(event);
    return vault.snapshot();
  });

  ipcMain.handle("vault:save-entry", (event, draft: unknown) => {
    assertSender(event);
    assertEntryDraft(draft);
    return vault.saveEntry(draft);
  });

  ipcMain.handle("vault:delete-entry", (event, id: unknown) => {
    assertSender(event);
    assertString(id, "entry id", 100);
    return vault.deleteEntry(id);
  });

  ipcMain.handle("vault:copy-password", (event, id: unknown) => {
    assertSender(event);
    assertString(id, "entry id", 100);
    clearOwnedClipboard();
    clipboardValue = vault.getPassword(id);
    clipboard.writeText(clipboardValue);
    clipboardTimer = setTimeout(clearOwnedClipboard, 30_000);
  });

  ipcMain.handle("vault:export", async (event, passphrase: unknown) => {
    assertSender(event);
    assertString(passphrase, "export passphrase", 1024);
    const result = await dialog.showSaveDialog(mainWindow!, {
      title: "Export encrypted vault",
      defaultPath: "password-manager-backup.pmvault",
      filters: [{ name: "Encrypted vault", extensions: ["pmvault"] }],
    });
    if (result.canceled || !result.filePath) return { canceled: true };
    await vault.exportTo(result.filePath, passphrase);
    return { canceled: false };
  });

  ipcMain.handle("vault:import", async (event, passphrase: unknown) => {
    assertSender(event);
    assertString(passphrase, "import passphrase", 1024);
    const result = await dialog.showOpenDialog(mainWindow!, {
      title: "Import passwords",
      properties: ["openFile"],
      filters: [
        { name: "Supported files", extensions: ["pmvault", "db", "sqlite", "sqlite3", "json", "csv"] },
        { name: "All files", extensions: ["*"] },
      ],
    });
    if (result.canceled || !result.filePaths[0]) return { canceled: true };
    const imported = await vault.importFrom(result.filePaths[0], passphrase);
    return { canceled: false, ...imported };
  });
}

async function registerAppProtocol(): Promise<void> {
  protocol.handle("app", async (request) => {
    const root = path.resolve(app.getAppPath(), "dist");
    const requestedPath = decodeURIComponent(new URL(request.url).pathname).replace(/^\/+/, "") || "index.html";
    const candidate = path.resolve(root, requestedPath);
    if (candidate !== root && !candidate.startsWith(root + path.sep)) {
      return new Response("Forbidden", { status: 403 });
    }
    return net.fetch(pathToFileURL(candidate).toString());
  });
}

function createWindow(): void {
  mainWindow = new BrowserWindow({
    width: 1180,
    height: 760,
    minWidth: 980,
    minHeight: 640,
    backgroundColor: "#08111f",
    title: "Password Manager",
    icon: path.join(app.getAppPath(), "public", "vault-logo.png"),
    webPreferences: {
      preload: path.join(app.getAppPath(), "dist-electron", "preload", "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      spellcheck: false,
    },
  });

  mainWindow.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  mainWindow.webContents.on("will-navigate", (event, url) => {
    const parsed = new URL(url);
    const allowed = (parsed.protocol === "app:" && parsed.hostname === "bundle")
      || (isDev && parsed.origin === "http://127.0.0.1:5173");
    if (!allowed) event.preventDefault();
  });
  mainWindow.on("closed", () => {
    mainWindow = null;
  });

  if (isDev) {
    void mainWindow.loadURL(process.env.VITE_DEV_SERVER_URL!);
  } else {
    void mainWindow.loadURL("app://bundle/index.html");
  }
}

app.whenReady().then(async () => {
  app.setAppUserModelId("com.passwordmanager.local");
  Menu.setApplicationMenu(null);
  vault = new VaultStore(path.join(app.getPath("userData"), "vault.pmvault"), sqliteWasmPath);
  await registerAppProtocol();
  registerIpc();
  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("before-quit", () => {
  clearOwnedClipboard();
  vault?.lock();
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
