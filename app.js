// vamp-vault — client-side encrypted notes vault
// Pure crypto logic (works in browsers and Node >= 20 via WebCrypto).
// UI wiring at the bottom is guarded so this module is importable in tests.

const PBKDF2_ITERATIONS = 100000;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const VAULT_APP = "vamp-vault";
const VAULT_VERSION = 1;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function getSubtle() {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error("WebCrypto is not available in this environment");
  }
  return subtle;
}

export function bytesToBase64(bytes) {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < view.length; i += chunk) {
    binary += String.fromCharCode(...view.subarray(i, i + chunk));
  }
  return btoa(binary);
}

export function base64ToBytes(base64) {
  if (typeof base64 !== "string") {
    throw new TypeError("base64 input must be a string");
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function normalizeSalt(salt) {
  if (typeof salt === "string") return base64ToBytes(salt);
  if (salt instanceof Uint8Array) return salt;
  if (salt instanceof ArrayBuffer) return new Uint8Array(salt);
  if (ArrayBuffer.isView(salt)) {
    return new Uint8Array(salt.buffer, salt.byteOffset, salt.byteLength);
  }
  throw new TypeError("salt must be a Uint8Array, ArrayBuffer, or base64 string");
}

export async function deriveKey(passphrase, salt) {
  if (typeof passphrase !== "string" || passphrase.length === 0) {
    throw new TypeError("passphrase must be a non-empty string");
  }
  const subtle = getSubtle();
  const baseKey = await subtle.importKey(
    "raw",
    encoder.encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: normalizeSalt(salt),
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function encryptNote(plaintext, passphrase) {
  if (typeof plaintext !== "string") {
    throw new TypeError("plaintext must be a string");
  }
  const subtle = getSubtle();
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const key = await deriveKey(passphrase, salt);
  const ciphertext = await subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoder.encode(plaintext),
  );
  return {
    version: VAULT_VERSION,
    algorithm: "AES-GCM",
    kdf: "PBKDF2-SHA256",
    iterations: PBKDF2_ITERATIONS,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
  };
}

export async function decryptNote(payload, passphrase) {
  const data = typeof payload === "string" ? JSON.parse(payload) : payload;
  if (
    !data ||
    typeof data.salt !== "string" ||
    typeof data.iv !== "string" ||
    typeof data.ciphertext !== "string"
  ) {
    throw new TypeError("payload must include salt, iv, and ciphertext strings");
  }
  const subtle = getSubtle();
  const key = await deriveKey(passphrase, base64ToBytes(data.salt));
  let plaintext;
  try {
    plaintext = await subtle.decrypt(
      { name: "AES-GCM", iv: base64ToBytes(data.iv) },
      key,
      base64ToBytes(data.ciphertext),
    );
  } catch {
    throw new Error("Decryption failed: wrong passphrase or corrupted data");
  }
  return decoder.decode(plaintext);
}

function isEncryptedNote(note) {
  return (
    note !== null &&
    typeof note === "object" &&
    typeof note.salt === "string" &&
    typeof note.iv === "string" &&
    typeof note.ciphertext === "string"
  );
}

function notePayload(note) {
  // Accept either a bare encryptNote payload or a vault entry wrapping one.
  if (isEncryptedNote(note)) return note;
  if (note && typeof note === "object" && isEncryptedNote(note.payload)) {
    return note.payload;
  }
  return null;
}

export function serializeVault(notes) {
  const list = Array.isArray(notes) ? notes : notes?.notes;
  if (!Array.isArray(list)) {
    throw new TypeError("serializeVault expects an array of notes or a vault object");
  }
  for (const note of list) {
    if (!notePayload(note)) {
      throw new TypeError("every vault note must be an encrypted payload");
    }
  }
  return JSON.stringify(
    {
      app: VAULT_APP,
      version: VAULT_VERSION,
      exportedAt: new Date().toISOString(),
      notes: list,
    },
    null,
    2,
  );
}

export function deserializeVault(data) {
  const vault = typeof data === "string" ? JSON.parse(data) : data;
  if (!vault || typeof vault !== "object" || !Array.isArray(vault.notes)) {
    throw new TypeError("vault data must be an object with a notes array");
  }
  for (const note of vault.notes) {
    if (!notePayload(note)) {
      throw new TypeError("every vault note must be an encrypted payload");
    }
  }
  return {
    app: VAULT_APP,
    version: VAULT_VERSION,
    notes: vault.notes,
  };
}

// ---------------------------------------------------------------------------
// Browser UI wiring (skipped under Node / tests)
// ---------------------------------------------------------------------------

if (typeof document !== "undefined") {
  const STORAGE_KEY = "vamp-vault:entries";

  const passphraseInput = document.querySelector("#passphrase");
  const titleInput = document.querySelector("#note-title");
  const bodyInput = document.querySelector("#note-body");
  const saveButton = document.querySelector("#save-note");
  const listEl = document.querySelector("#note-list");
  const statusEl = document.querySelector("#status");
  const exportButton = document.querySelector("#export-vault");
  const importInput = document.querySelector("#import-vault");

  let entries = loadEntries();
  render();

  function loadEntries() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return [];
      return deserializeVault(raw).notes;
    } catch {
      return [];
    }
  }

  function persist() {
    localStorage.setItem(STORAGE_KEY, serializeVault(entries));
  }

  function setStatus(message, isError = false) {
    statusEl.textContent = message;
    statusEl.classList.toggle("error", isError);
  }

  function render() {
    listEl.innerHTML = "";
    if (entries.length === 0) {
      const empty = document.createElement("li");
      empty.className = "empty";
      empty.textContent = "The vault is empty. Seal your first note above.";
      listEl.append(empty);
      return;
    }
    entries.forEach((entry, index) => {
      const item = document.createElement("li");
      item.className = "note-card";

      const heading = document.createElement("h3");
      heading.textContent = entry.title ?? `Sealed note ${index + 1}`;

      const meta = document.createElement("p");
      meta.className = "meta";
      meta.textContent = entry.createdAt
        ? `Sealed ${new Date(entry.createdAt).toLocaleString()}`
        : "Sealed note";

      const body = document.createElement("p");
      body.className = "note-body";
      body.textContent = "Encrypted — decrypt with your passphrase to read.";

      const actions = document.createElement("div");
      actions.className = "actions";

      const decryptButton = document.createElement("button");
      decryptButton.type = "button";
      decryptButton.textContent = "Decrypt";
      decryptButton.addEventListener("click", async () => {
        try {
          const plain = await decryptNote(
            notePayload(entry),
            passphraseInput.value,
          );
          const parsed = JSON.parse(plain);
          heading.textContent = parsed.title || heading.textContent;
          body.textContent = parsed.body ?? "";
          setStatus("Note decrypted.");
        } catch (error) {
          setStatus(error.message, true);
        }
      });

      const deleteButton = document.createElement("button");
      deleteButton.type = "button";
      deleteButton.className = "ghost";
      deleteButton.textContent = "Delete";
      deleteButton.addEventListener("click", () => {
        entries.splice(index, 1);
        persist();
        render();
        setStatus("Note deleted.");
      });

      actions.append(decryptButton, deleteButton);
      item.append(heading, meta, body, actions);
      listEl.append(item);
    });
  }

  saveButton.addEventListener("click", async () => {
    const passphrase = passphraseInput.value;
    const title = titleInput.value.trim();
    const body = bodyInput.value;
    if (!passphrase) {
      setStatus("Enter a passphrase first.", true);
      return;
    }
    if (!body.trim()) {
      setStatus("Write something to seal.", true);
      return;
    }
    try {
      const payload = await encryptNote(
        JSON.stringify({ title, body }),
        passphrase,
      );
      entries.unshift({
        id: globalThis.crypto.randomUUID(),
        title: title || "Untitled note",
        createdAt: new Date().toISOString(),
        payload,
      });
      persist();
      titleInput.value = "";
      bodyInput.value = "";
      render();
      setStatus("Note sealed in the vault.");
    } catch (error) {
      setStatus(error.message, true);
    }
  });

  exportButton.addEventListener("click", () => {
    const blob = new Blob([serializeVault(entries)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "vamp-vault.json";
    link.click();
    URL.revokeObjectURL(url);
    setStatus("Encrypted vault exported.");
  });

  importInput.addEventListener("change", async () => {
    const [file] = importInput.files;
    if (!file) return;
    try {
      const vault = deserializeVault(await file.text());
      entries = vault.notes;
      persist();
      render();
      setStatus(`Imported ${entries.length} sealed note(s).`);
    } catch (error) {
      setStatus(`Import failed: ${error.message}`, true);
    } finally {
      importInput.value = "";
    }
  });
}
