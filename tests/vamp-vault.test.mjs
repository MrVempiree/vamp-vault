import { test } from "node:test";
import assert from "node:assert/strict";
import {
  deriveKey,
  encryptNote,
  decryptNote,
  serializeVault,
  deserializeVault,
  bytesToBase64,
  base64ToBytes,
} from "../app.js";

test("encrypt -> decrypt round-trip restores the plaintext", async () => {
  const payload = await encryptNote("meet me at midnight", "correct horse");
  assert.equal(typeof payload.salt, "string");
  assert.equal(typeof payload.iv, "string");
  assert.equal(typeof payload.ciphertext, "string");
  const plain = await decryptNote(payload, "correct horse");
  assert.equal(plain, "meet me at midnight");
});

test("round-trip preserves unicode and empty strings", async () => {
  for (const text of ["", "🦇 crimson moon — café", "line one\nline two"]) {
    const payload = await encryptNote(text, "pw");
    assert.equal(await decryptNote(payload, "pw"), text);
  }
});

test("wrong passphrase fails to decrypt", async () => {
  const payload = await encryptNote("secret", "right-passphrase");
  await assert.rejects(() => decryptNote(payload, "wrong-passphrase"), {
    message: /Decryption failed/,
  });
});

test("tampered ciphertext fails to decrypt", async () => {
  const payload = await encryptNote("secret", "pw");
  const bytes = base64ToBytes(payload.ciphertext);
  bytes[0] ^= 0xff;
  const tampered = { ...payload, ciphertext: bytesToBase64(bytes) };
  await assert.rejects(() => decryptNote(tampered, "pw"), {
    message: /Decryption failed/,
  });
});

test("same plaintext encrypts differently each time (random salt and iv)", async () => {
  const first = await encryptNote("same", "pw");
  const second = await encryptNote("same", "pw");
  assert.notEqual(first.salt, second.salt);
  assert.notEqual(first.iv, second.iv);
  assert.notEqual(first.ciphertext, second.ciphertext);
});

test("deriveKey returns a usable AES-GCM key and rejects empty passphrase", async () => {
  const salt = new Uint8Array(16).fill(7);
  const key = await deriveKey("pw", salt);
  assert.equal(key.algorithm.name, "AES-GCM");
  assert.equal(key.algorithm.length, 256);
  await assert.rejects(() => deriveKey("", salt), TypeError);
});

test("decryptNote accepts a JSON string payload", async () => {
  const payload = await encryptNote("stringy", "pw");
  assert.equal(await decryptNote(JSON.stringify(payload), "pw"), "stringy");
});

test("serializeVault -> deserializeVault round-trip keeps notes decryptable", async () => {
  const first = await encryptNote("first note", "pw");
  const second = await encryptNote("second note", "pw");
  const json = serializeVault([first, second]);
  const vault = deserializeVault(json);
  assert.equal(vault.app, "vamp-vault");
  assert.equal(vault.notes.length, 2);
  assert.equal(await decryptNote(vault.notes[0], "pw"), "first note");
  assert.equal(await decryptNote(vault.notes[1], "pw"), "second note");
});

test("deserializeVault rejects malformed vault data", () => {
  assert.throws(() => deserializeVault("{}"), TypeError);
  assert.throws(() => deserializeVault('{"notes":[{"nope":true}]}'), TypeError);
  assert.throws(() => serializeVault([{ nope: true }]), TypeError);
});

test("base64 helpers round-trip arbitrary bytes", () => {
  const bytes = new Uint8Array([0, 1, 2, 250, 255, 42]);
  assert.deepEqual(base64ToBytes(bytesToBase64(bytes)), bytes);
});
