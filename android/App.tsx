import { useEffect, useMemo, useRef, useState } from "react";
import { AppState, FlatList, Image, KeyboardAvoidingView, Platform, Pressable, ScrollView, StyleSheet, Text, TextInput, View } from "react-native";
import { StatusBar } from "expo-status-bar";
import * as Clipboard from "expo-clipboard";
import * as DocumentPicker from "expo-document-picker";
import { File } from "expo-file-system";
import { allowScreenCaptureAsync, preventScreenCaptureAsync } from "expo-screen-capture";
import QuickCrypto from "react-native-quick-crypto";
import { SafeAreaProvider, SafeAreaView } from "react-native-safe-area-context";

import { decryptVaultBytes, MAX_VAULT_BYTES, type PasswordEntry } from "../packages/vault-format/src";

const LOCK_AFTER_MS = 3 * 60 * 1000;
const CLIPBOARD_CLEAR_MS = 30 * 1000;
const PICKER_TIMEOUT_MS = 5 * 60 * 1000;
const FILE_READ_TIMEOUT_MS = 30 * 1000;
// The vault KDF is intentionally expensive. Ten minutes keeps the operation
// bounded while allowing slower Android devices to finish local decryption.
const DECRYPT_TIMEOUT_MS = 10 * 60 * 1000;
const KEY_LENGTH = 32;
const SCRYPT_OPTIONS = { N: 131072, r: 8, p: 1, maxmem: 256 * 1024 * 1024 } as const;

type Notice = { kind: "error" | "success"; text: string } | null;
type DebugLog = { id: string; time: string; message: string };

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Something went wrong.";
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number, message: string, onTimeout?: () => void): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      onTimeout?.();
      reject(new Error(message));
    }, timeoutMs);
    promise.then(
      (value) => { clearTimeout(timer); resolve(value); },
      (error) => { clearTimeout(timer); reject(error); },
    );
  });
}

function deriveNativeKey(passphrase: string, salt: Uint8Array, onProgress: (progress: number) => void): Promise<Uint8Array> {
  onProgress(0);
  return new Promise((resolve, reject) => {
    QuickCrypto.scrypt(passphrase, salt, KEY_LENGTH, SCRYPT_OPTIONS, (error, derivedKey) => {
      if (error) {
        reject(error);
        return;
      }
      if (!derivedKey) {
        reject(new Error("Native key derivation returned no key."));
        return;
      }
      onProgress(1);
      resolve(new Uint8Array(derivedKey));
    });
  });
}

function AppLogo() {
  return <View style={styles.logo}><Image source={require("./assets/icon.png")} style={styles.logoImage} /></View>;
}

function DebugScreen({ logs, onBack, onClear, onCopy }: { logs: DebugLog[]; onBack: () => void; onClear: () => void; onCopy: () => Promise<void> }) {
  const [copied, setCopied] = useState(false);

  async function copyLogs() {
    await onCopy();
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  }

  return (
    <SafeAreaView style={styles.debugScreen} edges={["top", "bottom"]}>
      <StatusBar style="light" />
      <View style={styles.debugHeader}>
        <View><Text style={styles.eyebrow}>TEMPORARY TOOL</Text><Text style={styles.debugTitle}>Diagnostics</Text></View>
        <Pressable style={styles.lockButton} onPress={onBack}><Text style={styles.lockButtonText}>Back</Text></Pressable>
      </View>
      <Text style={styles.debugDescription}>Import logs omit passphrases and password contents. They are kept only in memory and can be copied here to troubleshoot a device or storage-provider issue.</Text>
      <View style={styles.debugActions}>
        <Pressable style={({ pressed }) => [styles.debugAction, pressed && styles.pressed]} onPress={copyLogs}><Text style={styles.debugActionText}>{copied ? "Copied" : "Copy all logs"}</Text></Pressable>
        <Pressable style={({ pressed }) => [styles.debugAction, styles.debugActionSecondary, pressed && styles.pressed]} onPress={onClear}><Text style={styles.debugActionText}>Clear</Text></Pressable>
      </View>
      <FlatList
        data={[...logs].reverse()}
        keyExtractor={(item) => item.id}
        style={styles.debugList}
        contentContainerStyle={logs.length === 0 ? styles.debugEmptyList : styles.debugListContent}
        renderItem={({ item }) => <View style={styles.debugRow}><Text style={styles.debugTime}>{item.time}</Text><Text style={styles.debugMessage}>{item.message}</Text></View>}
        ListEmptyComponent={<Text style={styles.debugEmpty}>No diagnostics recorded yet.</Text>}
      />
    </SafeAreaView>
  );
}

function AppContent() {
  const [entries, setEntries] = useState<PasswordEntry[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [fileName, setFileName] = useState("");
  const [busy, setBusy] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showDebug, setShowDebug] = useState(false);
  const [notice, setNotice] = useState<Notice>(null);
  const [logs, setLogs] = useState<DebugLog[]>([]);
  const logsRef = useRef<DebugLog[]>([]);
  const lockTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const clipboardTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  function debugLog(message: string) {
    const entry: DebugLog = { id: `${Date.now()}-${Math.random()}`, time: new Date().toLocaleTimeString(), message };
    const next = [...logsRef.current, entry].slice(-300);
    logsRef.current = next;
    setLogs(next);
  }

  const selected = entries.find((entry) => entry.id === selectedId) ?? null;
  const filteredEntries = useMemo(() => {
    const query = search.trim().toLocaleLowerCase();
    return entries
      .filter((entry) => !query || entry.service.toLocaleLowerCase().includes(query) || entry.username.toLocaleLowerCase().includes(query))
      .sort((a, b) => a.service.localeCompare(b.service));
  }, [entries, search]);

  function lock() {
    debugLog("Vault locked; decrypted entries cleared from the app state.");
    setLoaded(false);
    setEntries([]);
    setSelectedId(null);
    setSearch("");
    setShowPassword(false);
    setPassphrase("");
  }

  function resetLockTimer() {
    if (lockTimer.current) clearTimeout(lockTimer.current);
    if (entries.length > 0) lockTimer.current = setTimeout(lock, LOCK_AFTER_MS);
  }

  useEffect(() => {
    debugLog("App started. Secure-screen protection requested.");
    void preventScreenCaptureAsync("vault-reader").then(
      () => debugLog("Secure-screen protection enabled."),
      (error) => debugLog(`Secure-screen protection unavailable: ${errorMessage(error)}`),
    );
    return () => {
      if (lockTimer.current) clearTimeout(lockTimer.current);
      if (clipboardTimer.current) clearTimeout(clipboardTimer.current);
      void allowScreenCaptureAsync("vault-reader");
    };
  }, []);

  useEffect(() => {
    const subscription = AppState.addEventListener("change", (state) => {
      debugLog(`App state changed: ${state}.`);
      if (state !== "active" && loaded) lock();
      else if (state === "active") resetLockTimer();
    });
    return () => subscription.remove();
  }, [entries.length, loaded]);

  useEffect(() => {
    if (!notice) return;
    const timer = setTimeout(() => setNotice(null), 3500);
    return () => clearTimeout(timer);
  }, [notice]);

  async function importVault() {
    if (passphrase.length < 12) {
      debugLog(`Import blocked: passphrase length is ${passphrase.length}; minimum is 12.`);
      setNotice({ kind: "error", text: "Enter the backup passphrase (at least 12 characters)." });
      return;
    }
    const startedAt = Date.now();
    let selectedAssetName = "unknown";
    setBusy(true);
    setNotice(null);
    debugLog("Import started. Passphrase length accepted; passphrase contents were not logged.");
    try {
      debugLog("Opening Android document picker.");
      const result = await withTimeout(
        DocumentPicker.getDocumentAsync({ type: ["application/octet-stream", "application/json", "*/*"], copyToCacheDirectory: true, multiple: false }),
        PICKER_TIMEOUT_MS,
        "The file picker did not respond. Please try again.",
      );
      if (result.canceled || !result.assets[0]) {
        debugLog("Document picker canceled or returned no file.");
        return;
      }
      const asset = result.assets[0];
      selectedAssetName = asset.name;
      const uriScheme = asset.uri.split(":")[0] || "unknown";
      debugLog(`File selected: ${asset.name || "unnamed"}; provider URI scheme: ${uriScheme}; reported size: ${asset.size ?? "unknown"} bytes.`);
      if (asset.size && asset.size > MAX_VAULT_BYTES) throw new Error("Vault file is too large.");

      debugLog("Reading selected file into app memory.");
      const bytes = await withTimeout(new File(asset.uri).bytes(), FILE_READ_TIMEOUT_MS, "Reading the selected file timed out. The storage provider may not have returned a local copy.");
      debugLog(`File read completed: ${bytes.byteLength} bytes.`);
      if (bytes.byteLength > MAX_VAULT_BYTES) throw new Error("Vault file is too large.");

      debugLog("Starting scrypt key derivation and AES-256-GCM authentication.");
      let lastProgressBucket = -1;
      let decryptionTimedOut = false;
      const onProgress = (progress: number) => {
        // Native scrypt reports only when it starts and finishes. Keep the
        // same diagnostics shape without logging late completion after a
        // timeout; the derived key is still wiped by the shared decoder.
        if (decryptionTimedOut) return;
        const bucket = Math.floor(progress * 10);
        if (bucket > lastProgressBucket) {
          lastProgressBucket = bucket;
          debugLog(`Key derivation progress: ${Math.min(bucket, 10) * 10}%.`);
        }
      };
      const decrypted = await withTimeout(
        decryptVaultBytes(bytes, passphrase, onProgress, (password, salt) => deriveNativeKey(password, salt, onProgress)),
        DECRYPT_TIMEOUT_MS,
        "Decryption timed out. The device may be too slow for this vault's security settings; check Diagnostics and try again.",
        () => { decryptionTimedOut = true; },
      );
      debugLog(`Decryption succeeded in ${Date.now() - startedAt} ms; ${decrypted.length} entries validated.`);
      setEntries(decrypted);
      setLoaded(true);
      setSelectedId(decrypted[0]?.id ?? null);
      setFileName(asset.name);
      setPassphrase("");
      setNotice({ kind: "success", text: `${decrypted.length} ${decrypted.length === 1 ? "entry" : "entries"} loaded locally.` });
      resetLockTimer();
    } catch (error) {
      const message = errorMessage(error);
      debugLog(`Import failed after ${Date.now() - startedAt} ms for ${selectedAssetName}: ${message}`);
      setNotice({ kind: "error", text: message });
    } finally {
      setBusy(false);
      debugLog("Import finished; busy state cleared.");
    }
  }

  async function copyValue(label: string, value: string) {
    if (!value) {
      setNotice({ kind: "error", text: `${label} is empty.` });
      return;
    }
    await Clipboard.setStringAsync(value);
    if (clipboardTimer.current) clearTimeout(clipboardTimer.current);
    clipboardTimer.current = setTimeout(async () => {
      try {
        if ((await Clipboard.getStringAsync()) === value) await Clipboard.setStringAsync("");
      } catch {
        debugLog("Clipboard auto-clear was unavailable on this device.");
      }
    }, CLIPBOARD_CLEAR_MS);
    setNotice({ kind: "success", text: `${label} copied. Clipboard clears in 30 seconds.` });
    resetLockTimer();
  }

  async function copyLogs() {
    const text = logsRef.current.length === 0
      ? "No diagnostics recorded."
      : logsRef.current.map((entry) => `[${entry.time}] ${entry.message}`).join("\n");
    await Clipboard.setStringAsync(text);
    debugLog("Diagnostics copied to clipboard. Passwords and passphrases are not included.");
  }

  function clearLogs() {
    logsRef.current = [];
    setLogs([]);
  }

  function selectEntry(entry: PasswordEntry) {
    setSelectedId(entry.id);
    setShowPassword(false);
    resetLockTimer();
  }

  if (showDebug) {
    return <DebugScreen logs={logs} onBack={() => setShowDebug(false)} onClear={clearLogs} onCopy={copyLogs} />;
  }

  if (!loaded) {
    return (
      <SafeAreaView style={styles.screen} edges={["top", "bottom"]}>
        <KeyboardAvoidingView style={styles.screen} behavior={Platform.OS === "ios" ? "padding" : "height"} keyboardVerticalOffset={Platform.OS === "ios" ? 24 : 0}>
          <StatusBar style="light" />
          <ScrollView contentContainerStyle={styles.authContent} keyboardShouldPersistTaps="handled">
            <AppLogo />
            <Text style={styles.eyebrow}>READ-ONLY VAULT</Text>
            <Text style={styles.title}>Open your backup</Text>
            <Text style={styles.subtitle}>Select an encrypted .pmvault export from the Electron app. It is decrypted only in this app's memory.</Text>
            <View style={styles.securityNote}>
              <Text style={styles.securityIcon}>✓</Text>
              <Text style={styles.securityText}>No editing, database, account, or network connection. This app can only view and copy entries.</Text>
            </View>
            <Text style={styles.label}>Backup passphrase</Text>
            <TextInput value={passphrase} onChangeText={setPassphrase} placeholder="At least 12 characters" placeholderTextColor="#7083a1" secureTextEntry autoCapitalize="none" autoCorrect={false} style={styles.input} onFocus={resetLockTimer} />
            <Pressable style={({ pressed }) => [styles.primaryButton, pressed && styles.pressed, busy && styles.disabled]} onPress={importVault} disabled={busy}>
              <Text style={styles.primaryButtonText}>{busy ? "Decrypting locally…" : "Choose .pmvault file"}</Text>
            </Pressable>
            <Pressable style={({ pressed }) => [styles.diagnosticButton, pressed && styles.pressed]} onPress={() => setShowDebug(true)}><Text style={styles.diagnosticButtonText}>Open diagnostics</Text></Pressable>
            {notice && <Notice notice={notice} />}
            <Text style={styles.footerText}>AES-256-GCM · scrypt · offline by design</Text>
          </ScrollView>
        </KeyboardAvoidingView>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={styles.screen} edges={["top", "bottom"]} onTouchStart={resetLockTimer}>
      <StatusBar style="light" />
      <View style={styles.header}>
        <View style={styles.headerBrand}><AppLogo /><View><Text style={styles.headerTitle}>Vault Reader</Text><Text style={styles.headerSub}>{fileName}</Text></View></View>
        <View style={styles.headerActions}>
          <Pressable style={styles.debugButton} onPress={() => setShowDebug(true)}><Text style={styles.debugButtonText}>Debug</Text></Pressable>
          <Pressable style={styles.lockButton} onPress={lock}><Text style={styles.lockButtonText}>Lock</Text></Pressable>
        </View>
      </View>
      <View style={styles.searchWrap}>
        <Text style={styles.searchIcon}>⌕</Text>
        <TextInput value={search} onChangeText={setSearch} placeholder="Search services or usernames" placeholderTextColor="#7083a1" style={styles.searchInput} autoCapitalize="none" autoCorrect={false} />
        {search.length > 0 && <Pressable onPress={() => setSearch("")}><Text style={styles.clearSearch}>×</Text></Pressable>}
      </View>
      <View style={styles.content}>
        <View style={styles.listHeader}><Text style={styles.listCount}>{filteredEntries.length} {filteredEntries.length === 1 ? "ENTRY" : "ENTRIES"}</Text><Text style={styles.readOnlyBadge}>READ ONLY</Text></View>
        <FlatList data={filteredEntries} keyExtractor={(item) => item.id} style={styles.list} contentContainerStyle={styles.listContent} keyboardShouldPersistTaps="handled" renderItem={({ item }) => (
          <Pressable style={({ pressed }) => [styles.entryRow, item.id === selectedId && styles.entryRowSelected, pressed && styles.pressed]} onPress={() => selectEntry(item)}>
            <View style={styles.avatar}><Text style={styles.avatarText}>{item.service.slice(0, 1).toUpperCase()}</Text></View>
            <View style={styles.entrySummary}><Text style={styles.entryService} numberOfLines={1}>{item.service}</Text><Text style={styles.entryUsername} numberOfLines={1}>{item.username || "No username"}</Text></View>
            <Text style={styles.chevron}>›</Text>
          </Pressable>
        )} ListEmptyComponent={<View style={styles.empty}><Text style={styles.emptyIcon}>⌕</Text><Text style={styles.emptyTitle}>No matches found</Text><Text style={styles.emptyText}>Try another service or username.</Text></View>} />
        {selected && <DetailPanel entry={selected} showPassword={showPassword} onTogglePassword={() => setShowPassword((value) => !value)} onCopy={copyValue} />}
      </View>
      {notice && <Notice notice={notice} />}
    </SafeAreaView>
  );
}

function App() {
  return <SafeAreaProvider><AppContent /></SafeAreaProvider>;
}

function DetailPanel({ entry, showPassword, onTogglePassword, onCopy }: { entry: PasswordEntry; showPassword: boolean; onTogglePassword: () => void; onCopy: (label: string, value: string) => void }) {
  return (
    <View style={styles.detailCard}>
      <View style={styles.detailHeading}><View><Text style={styles.eyebrow}>PASSWORD DETAILS</Text><Text style={styles.detailTitle}>{entry.service}</Text></View><View style={styles.readOnlyCircle}><Text style={styles.readOnlyCircleText}>⌁</Text></View></View>
      <CopyRow label="Username" value={entry.username} onCopy={onCopy} />
      <View style={styles.copyRow}><View style={styles.copyRowText}><Text style={styles.detailLabel}>Password</Text><Text style={styles.detailValue} numberOfLines={1}>{showPassword ? entry.password : "••••••••••••"}</Text></View><Pressable style={styles.smallButton} onPress={onTogglePassword}><Text style={styles.smallButtonText}>{showPassword ? "Hide" : "Show"}</Text></Pressable><Pressable style={styles.copyButton} onPress={() => onCopy("Password", entry.password)}><Text style={styles.copyButtonText}>Copy</Text></Pressable></View>
      {entry.url ? <CopyRow label="Website" value={entry.url} onCopy={onCopy} /> : null}
      {entry.notes ? <CopyRow label="Notes" value={entry.notes} onCopy={onCopy} multiline /> : null}
      <Text style={styles.readOnlyHint}>This viewer cannot edit or save passwords.</Text>
    </View>
  );
}

function CopyRow({ label, value, onCopy, multiline = false }: { label: string; value: string; onCopy: (label: string, value: string) => void; multiline?: boolean }) {
  return <View style={styles.copyRow}><View style={styles.copyRowText}><Text style={styles.detailLabel}>{label}</Text><Text style={[styles.detailValue, multiline && styles.multilineValue]} numberOfLines={multiline ? 3 : 1}>{value}</Text></View><Pressable style={styles.copyButton} onPress={() => onCopy(label, value)}><Text style={styles.copyButtonText}>Copy</Text></Pressable></View>;
}

function Notice({ notice }: { notice: Exclude<Notice, null> }) {
  return <View style={[styles.notice, notice.kind === "error" ? styles.errorNotice : styles.successNotice]}><Text style={styles.noticeText}>{notice.text}</Text></View>;
}

const styles = StyleSheet.create({
  screen: { flex: 1, backgroundColor: "#071426" },
  authContent: { flexGrow: 1, justifyContent: "center", padding: 26, paddingBottom: 40 },
  logo: { width: 58, height: 58, borderRadius: 18, backgroundColor: "#2e82ee", alignItems: "center", justifyContent: "center", shadowColor: "#2e82ee", shadowOpacity: 0.45, shadowRadius: 16, shadowOffset: { width: 0, height: 8 }, elevation: 8 },
  logoImage: { width: 58, height: 58, borderRadius: 18 },
  eyebrow: { color: "#5ba4ff", fontSize: 11, fontWeight: "800", letterSpacing: 2, marginTop: 22, marginBottom: 8 },
  title: { color: "#f5f8ff", fontSize: 32, fontWeight: "800", marginBottom: 12 },
  subtitle: { color: "#91a4c0", fontSize: 15, lineHeight: 23, marginBottom: 22 },
  securityNote: { flexDirection: "row", gap: 11, padding: 14, borderRadius: 12, backgroundColor: "#0d2037", borderWidth: 1, borderColor: "#1d3b5d", marginBottom: 24 },
  securityIcon: { color: "#5ba4ff", fontSize: 17, fontWeight: "800" },
  securityText: { flex: 1, color: "#a9bad2", fontSize: 12, lineHeight: 18 },
  label: { color: "#dce7f7", fontSize: 13, fontWeight: "700", marginBottom: 8 },
  input: { height: 54, borderWidth: 1, borderColor: "#294565", borderRadius: 11, color: "#f5f8ff", backgroundColor: "#0b1a2d", paddingHorizontal: 16, fontSize: 15, marginBottom: 14 },
  primaryButton: { height: 54, borderRadius: 12, backgroundColor: "#3285ee", alignItems: "center", justifyContent: "center", marginTop: 4 },
  primaryButtonText: { color: "#fff", fontWeight: "800", fontSize: 15 },
  diagnosticButton: { alignItems: "center", paddingVertical: 15 },
  diagnosticButtonText: { color: "#7ea7d3", fontWeight: "700", fontSize: 13 },
  pressed: { opacity: 0.78 },
  disabled: { opacity: 0.55 },
  footerText: { color: "#56708f", textAlign: "center", fontSize: 11, marginTop: 14, letterSpacing: 0.4 },
  header: { flexDirection: "row", alignItems: "center", justifyContent: "space-between", paddingHorizontal: 18, paddingTop: 17, paddingBottom: 15, borderBottomWidth: 1, borderBottomColor: "#17304d" },
  headerBrand: { flexDirection: "row", alignItems: "center", gap: 12 },
  headerTitle: { color: "#f4f7fc", fontSize: 18, fontWeight: "800" },
  headerSub: { color: "#7890ae", fontSize: 11, marginTop: 2, maxWidth: 150 },
  headerActions: { flexDirection: "row", alignItems: "center", gap: 7 },
  debugButton: { borderWidth: 1, borderColor: "#315276", borderRadius: 9, paddingHorizontal: 10, paddingVertical: 9 },
  debugButtonText: { color: "#9db5d3", fontWeight: "700", fontSize: 11 },
  lockButton: { borderWidth: 1, borderColor: "#315276", borderRadius: 9, paddingHorizontal: 13, paddingVertical: 9 },
  lockButtonText: { color: "#9db5d3", fontWeight: "700", fontSize: 12 },
  searchWrap: { flexDirection: "row", alignItems: "center", margin: 16, height: 50, borderWidth: 1, borderColor: "#294565", borderRadius: 11, backgroundColor: "#0b1a2d", paddingHorizontal: 13 },
  searchIcon: { color: "#71a9e8", fontSize: 25, marginRight: 8 },
  searchInput: { flex: 1, color: "#f4f7fc", fontSize: 14 },
  clearSearch: { color: "#8ea6c4", fontSize: 25, paddingLeft: 8 },
  content: { flex: 1, paddingHorizontal: 16 },
  listHeader: { flexDirection: "row", alignItems: "center", justifyContent: "space-between", marginBottom: 9 },
  listCount: { color: "#6795c9", fontSize: 10, letterSpacing: 1.5, fontWeight: "800" },
  readOnlyBadge: { color: "#78d4ba", fontSize: 9, letterSpacing: 1, fontWeight: "800", backgroundColor: "#10342e", paddingHorizontal: 8, paddingVertical: 5, borderRadius: 5 },
  list: { flex: 1 },
  listContent: { paddingBottom: 14 },
  entryRow: { flexDirection: "row", alignItems: "center", minHeight: 64, paddingHorizontal: 12, borderRadius: 11, marginBottom: 7, backgroundColor: "#0b1b2e", borderWidth: 1, borderColor: "#142d49" },
  entryRowSelected: { backgroundColor: "#102d4c", borderColor: "#2d72b8" },
  avatar: { width: 36, height: 36, borderRadius: 10, backgroundColor: "#163b62", alignItems: "center", justifyContent: "center", marginRight: 11 },
  avatarText: { color: "#75b5ff", fontSize: 16, fontWeight: "800" },
  entrySummary: { flex: 1 },
  entryService: { color: "#edf4ff", fontSize: 15, fontWeight: "700" },
  entryUsername: { color: "#7f98b7", fontSize: 12, marginTop: 4 },
  chevron: { color: "#6083a8", fontSize: 25, marginLeft: 8 },
  empty: { alignItems: "center", paddingTop: 70 },
  emptyIcon: { color: "#4e7faa", fontSize: 36, marginBottom: 12 },
  emptyTitle: { color: "#dce8f7", fontSize: 17, fontWeight: "800" },
  emptyText: { color: "#7890ae", marginTop: 7 },
  detailCard: { borderTopWidth: 1, borderTopColor: "#1a3858", paddingTop: 17, paddingBottom: 18 },
  detailHeading: { flexDirection: "row", alignItems: "center", justifyContent: "space-between", marginBottom: 10 },
  detailTitle: { color: "#f4f7fc", fontSize: 21, fontWeight: "800" },
  readOnlyCircle: { width: 37, height: 37, borderRadius: 19, backgroundColor: "#143354", alignItems: "center", justifyContent: "center" },
  readOnlyCircleText: { color: "#75b5ff", fontSize: 20 },
  copyRow: { flexDirection: "row", alignItems: "center", paddingVertical: 10, borderBottomWidth: 1, borderBottomColor: "#142c47", gap: 8 },
  copyRowText: { flex: 1 },
  detailLabel: { color: "#7898bb", fontSize: 10, letterSpacing: 1, fontWeight: "800", textTransform: "uppercase", marginBottom: 4 },
  detailValue: { color: "#e5eefb", fontSize: 14 },
  multilineValue: { lineHeight: 20 },
  smallButton: { borderWidth: 1, borderColor: "#294d73", borderRadius: 7, paddingHorizontal: 9, paddingVertical: 7 },
  smallButtonText: { color: "#9fc4ec", fontSize: 11, fontWeight: "700" },
  copyButton: { backgroundColor: "#1e5da1", borderRadius: 7, paddingHorizontal: 10, paddingVertical: 8 },
  copyButtonText: { color: "#fff", fontSize: 11, fontWeight: "800" },
  readOnlyHint: { color: "#5f7b9d", fontSize: 11, marginTop: 14, textAlign: "center" },
  notice: { position: "absolute", left: 18, right: 18, bottom: 22, padding: 13, borderRadius: 10, borderWidth: 1 },
  successNotice: { backgroundColor: "#0d302c", borderColor: "#287e6c" },
  errorNotice: { backgroundColor: "#351d2a", borderColor: "#9a4560" },
  noticeText: { color: "#eff8ff", fontSize: 12, lineHeight: 18, textAlign: "center" },
  debugScreen: { flex: 1, backgroundColor: "#071426", paddingHorizontal: 18 },
  debugHeader: { flexDirection: "row", alignItems: "center", justifyContent: "space-between", paddingTop: 19, paddingBottom: 12, borderBottomWidth: 1, borderBottomColor: "#17304d" },
  debugTitle: { color: "#f4f7fc", fontSize: 25, fontWeight: "800" },
  debugDescription: { color: "#91a4c0", fontSize: 13, lineHeight: 20, marginTop: 14 },
  debugActions: { flexDirection: "row", gap: 9, marginVertical: 15 },
  debugAction: { backgroundColor: "#286eb9", borderRadius: 9, paddingHorizontal: 14, paddingVertical: 10 },
  debugActionSecondary: { backgroundColor: "#173454" },
  debugActionText: { color: "#fff", fontSize: 12, fontWeight: "800" },
  debugList: { flex: 1 },
  debugListContent: { paddingBottom: 24 },
  debugEmptyList: { flexGrow: 1, justifyContent: "center" },
  debugEmpty: { color: "#7890ae", textAlign: "center" },
  debugRow: { paddingVertical: 10, borderBottomWidth: 1, borderBottomColor: "#142c47" },
  debugTime: { color: "#5f86ae", fontSize: 10, marginBottom: 4 },
  debugMessage: { color: "#dce8f7", fontSize: 12, lineHeight: 18 },
});

export default App;


