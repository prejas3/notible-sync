/**
 * Notible Sync — replicate a workspace between your own machines through
 * your own Google Drive. No Notible server is involved and none can read
 * your notes: everything leaving this machine is encrypted under a key that
 * only your devices hold.
 *
 * One ES module, no build step, no dependencies. Crypto is WebCrypto,
 * compression is CompressionStream, both native.
 *
 * Design notes and the reasoning behind the trade-offs:
 * docs/superpowers/specs/2026-08-18-sync-plugin-design.md
 *
 * The pure functions below are exported by name so `self-check.mjs` can run
 * them under plain node; the plugin itself is the default export.
 */

// No client id and no client secret live here any more. As of API 1.7 Core
// owns both, together with the scope they may ask for, and this plugin names
// a provider instead (see PROVIDER below). That is not tidiness: a command
// that let its caller choose the client and the scopes would let ANY
// installed plugin raise a real Google consent screen asking for anything.
//
// ponytail: drive.appdata would have given a hidden folder, but Google
// rejects it despite documenting it as allowed (measured 2026-08-18).
// drive.file still only exposes files we created ourselves.
const FOLDER_NAME = "Notible Sync";

const SNAPSHOT_VERSION = 1;
const DEFAULT_INTERVAL_MINUTES = 15;
/** Refuse a peer object whose fields are absurd rather than writing it. */
const LIMITS = {
  title: 4_000,
  content: 20_000_000,
  props: 4_000_000,
  objects: 200_000,
  relations: 400_000,
  // A tombstone deletes an object AND its history, and blocks every future
  // write of that id (db.rs), so an unbounded list of them is a workspace
  // wipe with no undo. Same order as the object cap on purpose.
  tombstones: 200_000,
  // gzip decompresses before anything gets to look at it. Without a ceiling a
  // few hundred kilobytes on Drive can be gigabytes in this process.
  // ponytail: one flat cap, generous next to the per-object limits above.
  inflated: 512 * 1024 * 1024,
};

// Timestamps are epoch milliseconds and land in a Rust i64 (db.rs `now()`).
// Two things go wrong without a range: a tombstone dated year 275760 outranks
// every local edit forever, and a fractional value is cast outside the error
// path and kills sync for good. Anything outside this window is a broken or
// hostile writer, not a clock that is a little off.
const MIN_TIMESTAMP = 0;
const MAX_TIMESTAMP = Date.UTC(2200, 0, 1);
// A fixed upper bound is not enough on its own. A tombstone dated 2199 passes
// it, still outranks every local edit for the rest of the machine's life, and
// deletes the object AND its history with no way back. What a healthy peer
// cannot produce is a stamp from the FUTURE, so that is the real bound; the
// day of slack absorbs clock skew between two machines, which is ordinary.
const CLOCK_SKEW = 24 * 60 * 60 * 1000;

// ---------------------------------------------------------------- utilities

const enc = new TextEncoder();
const dec = new TextDecoder();

async function gzip(bytes) {
  const stream = new Blob([bytes]).stream().pipeThrough(new CompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/** Inflate, but stop reading the moment the result passes `limit` bytes. */
export async function gunzip(bytes, limit = LIMITS.inflated) {
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip"));
  const reader = stream.getReader();
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > limit) throw new Error("Snapshot expands past the size limit; refusing to read it.");
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  const out = new Uint8Array(size);
  let at = 0;
  for (const chunk of chunks) { out.set(chunk, at); at += chunk.length; }
  return out;
}

// Crockford base32 without I, L, O and U, so a key read off one screen and
// typed into another cannot be ruined by a letter that looks like a digit.
const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export function encodeKey(bytes) {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out.match(/.{1,5}/g).join("-");
}

export function decodeKey(text) {
  const clean = String(text).toUpperCase().replace(/[^0-9A-Z]/g, "")
    .replace(/O/g, "0").replace(/[IL]/g, "1").replace(/U/g, "V");
  let bits = 0;
  let value = 0;
  const out = [];
  for (const character of clean) {
    const index = ALPHABET.indexOf(character);
    if (index < 0) throw new Error(`Recovery key contains an unusable character: ${character}`);
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  if (out.length !== 32) throw new Error(`Recovery key must decode to 32 bytes, got ${out.length}.`);
  return new Uint8Array(out);
}

// ------------------------------------------------------------------- crypto

/**
 * AES-GCM and nothing else.
 *
 * ponytail: the design called for HMAC on top, but GCM's tag already proves
 * the file was written by someone holding the pairing key, which is exactly
 * the peer authentication we needed — somebody with access to the Drive
 * account but not the key cannot forge a snapshot. What it deliberately does
 * NOT do is tell paired devices apart: every paired device is equally
 * trusted. That is the intended model for "my laptop and my PC"; it would not
 * be enough for sharing a workspace with another person.
 */
async function keyFrom(bytes) {
  return crypto.subtle.importKey("raw", bytes, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function seal(keyBytes, payload) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const body = await gzip(enc.encode(JSON.stringify(payload)));
  const sealed = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    await keyFrom(keyBytes),
    body,
  ));
  const out = new Uint8Array(iv.length + sealed.length);
  out.set(iv, 0);
  out.set(sealed, iv.length);
  return out;
}

export async function unseal(keyBytes, bytes) {
  if (bytes.length <= 12) throw new Error("Snapshot is too short to be valid.");
  let plain;
  try {
    plain = new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: bytes.slice(0, 12) },
      await keyFrom(keyBytes),
      bytes.slice(12),
    ));
  } catch {
    // Wrong key and tampering are indistinguishable here, and should be:
    // both mean "do not write this to the database".
    throw new Error("This snapshot was not written by a paired device, or the recovery key is wrong.");
  }
  return safeParse(dec.decode(await gunzip(plain)));
}

// -------------------------------------------------------------------- media

/**
 * `media/<uuid>.<ext>` filenames mentioned anywhere in this text.
 *
 * The same shape Core stores and the same shape its media collector scans
 * for, so a note and its pictures agree on what a picture is called.
 */
export function mediaNamesIn(text) {
  if (typeof text !== "string" || !text) return [];
  return [...text.matchAll(MEDIA_REFERENCE)].map((match) => match[1]);
}

const MEDIA_REFERENCE = /media\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.(?:png|jpg|jpeg|gif|webp|svg|bmp))/g;

/**
 * Every media filename the LOCAL workspace refers to.
 *
 * Deliberately the whole workspace rather than the objects that just arrived.
 * If one download fails, the object is already in the database, so the next
 * cycle will not re-apply it (`upsert_synced_object` keeps the newer local
 * row) — and a delta-based list would never mention its picture again. Dead
 * image, permanently. Recomputing the full set costs one pass over content
 * already in memory.
 */
export function mediaNamesOf(objects) {
  const names = new Set();
  for (const object of objects ?? []) {
    for (const name of mediaNamesIn(object?.content)) names.add(name);
    for (const name of mediaNamesIn(object?.props)) names.add(name);
  }
  return [...names];
}

// --------------------------------------------------------------- validation

/**
 * Defence in depth, measured rather than assumed.
 *
 * `JSON.parse` alone does not pollute `Object.prototype` — it puts an own
 * data property on the result — and `Object.assign` does not either; it
 * swaps the target's own prototype at worst. Reaching `Object.prototype`
 * needs a recursive merge, which this plugin does not do.
 *
 * The reviver stays anyway, because it costs one line and this text comes
 * from another machine: the day someone deep-merges a peer's `props`, the
 * dangerous keys are already gone.
 */
export function safeParse(text) {
  return JSON.parse(text, (key, value) =>
    (key === "__proto__" || key === "constructor" || key === "prototype") ? undefined : value);
}

const isString = (value) => typeof value === "string";
const isTimestamp = (value) =>
  Number.isInteger(value)
  && value >= MIN_TIMESTAMP
  && value <= MAX_TIMESTAMP
  && value <= Date.now() + CLOCK_SKEW;
const isNullableTimestamp = (value) =>
  value === null || value === undefined || isTimestamp(value);

/**
 * Everything below arrived from another machine. It is authenticated (it
 * decrypted) but that only proves it came from a paired device, not that the
 * device was healthy — a half-written or version-skewed snapshot must bounce
 * off this function rather than reach `sync.apply`.
 *
 * Returns the parts worth applying and a list of what was dropped and why.
 */
export function validateSnapshot(snapshot, knownTypes) {
  const rejected = [];
  if (!snapshot || typeof snapshot !== "object") throw new Error("Snapshot is not an object.");
  if (snapshot.v !== SNAPSHOT_VERSION) {
    throw new Error(`Snapshot format ${snapshot.v} was written by a different version of this plugin.`);
  }
  if (!isString(snapshot.deviceId) || !snapshot.deviceId) throw new Error("Snapshot has no device id.");

  const list = (value) => (Array.isArray(value) ? value : []);
  // Whole-snapshot caps come first: a list this long is a broken or hostile
  // writer, and the tombstone list is the destructive one — every entry there
  // erases an object and its history and bars the id from ever coming back.
  for (const [field, cap] of [
    ["objects", LIMITS.objects],
    ["relations", LIMITS.relations],
    ["tombstones", LIMITS.tombstones],
    ["relationTombstones", LIMITS.tombstones],
  ]) {
    const count = list(snapshot[field]).length;
    if (count > cap) throw new Error(`Snapshot claims ${count} ${field} (limit ${cap}); refusing to apply.`);
  }

  const types = knownTypes instanceof Set ? knownTypes : new Set(knownTypes ?? []);
  const objects = [];
  for (const object of list(snapshot.objects)) {
    const bad = objectProblem(object, types);
    if (bad) rejected.push(`${isString(object?.id) ? object.id : "<no id>"}: ${bad}`);
    else objects.push(object);
  }

  const relations = list(snapshot.relations).filter((relation) =>
    isString(relation?.from_id) && isString(relation?.to_id) && isString(relation?.kind)
    && isTimestamp(relation?.created_at));
  const tombstones = list(snapshot.tombstones).filter((tombstone) =>
    isString(tombstone?.object_id) && isTimestamp(tombstone?.deleted_at));
  const relationTombstones = list(snapshot.relationTombstones).filter((tombstone) =>
    isString(tombstone?.from_id) && isString(tombstone?.to_id) && isString(tombstone?.kind)
    && isTimestamp(tombstone?.deleted_at));

  return { deviceId: snapshot.deviceId, objects, relations, tombstones, relationTombstones, rejected };
}

function objectProblem(object, types) {
  if (!object || typeof object !== "object") return "not an object";
  if (!isString(object.id) || !object.id) return "missing id";
  if (!isString(object.type) || !object.type) return "missing type";
  // An unknown type would render as nothing at all, or worse, as a
  // half-configured project. Better to skip the row and say so.
  if (types.size && !types.has(object.type)) return `unknown type "${object.type}"`;
  if (!isString(object.title)) return "title is not a string";
  if (object.title.length > LIMITS.title) return "title is too long";
  if (!isString(object.content)) return "content is not a string";
  if (object.content.length > LIMITS.content) return "content is too long";
  if (!isString(object.props)) return "props is not a string";
  if (object.props.length > LIMITS.props) return "props is too long";
  if (!isTimestamp(object.created_at) || !isTimestamp(object.updated_at)) return "bad timestamps";
  if (!isNullableTimestamp(object.archived_at) || !isNullableTimestamp(object.trashed_at)) return "bad archive/trash marker";
  if (object.parent_id !== null && object.parent_id !== undefined && !isString(object.parent_id)) return "bad parent id";
  return null;
}

/**
 * Split a validated peer snapshot into what can be written now and what has
 * to wait.
 *
 * The editor keeps the open note in an uncontrolled contenteditable and its
 * autosave retries on conflict, so a pulled change to the note the user is
 * looking at gets overwritten from a buffer that never saw it. Deferring is
 * the only fix available from outside Core.
 */
export function planApply(validated, openObjectId) {
  if (!openObjectId) return { apply: validated, deferred: [] };
  const deferred = validated.objects.filter((object) => object.id === openObjectId);
  if (!deferred.length) return { apply: validated, deferred: [] };
  return {
    apply: { ...validated, objects: validated.objects.filter((object) => object.id !== openObjectId) },
    deferred,
  };
}

// ---------------------------------------------------------------- Google API

/**
 * The provider name Core resolves to an OAuth client and a scope set.
 *
 * This plugin no longer carries either. It used the device flow — the one
 * built for televisions, where the user reads a code off one screen and
 * types it into another — because a plugin has no socket to catch a redirect
 * on. Core does, so as of API 1.7 it runs the loopback flow meant for desktop
 * applications: the browser opens, the user picks an account, and there is no
 * code at all.
 */
const PROVIDER = "google.drive.file";

class Google {
  constructor(storage, oauth) {
    this.storage = storage;
    this.oauth = oauth;
    this.accessToken = null;
    this.expiresAt = 0;
  }

  get refreshToken() { return this.storage.get("refreshToken"); }

  signedIn() { return Boolean(this.refreshToken); }

  async token() {
    if (this.accessToken && Date.now() < this.expiresAt - 60_000) return this.accessToken;
    const refresh = this.refreshToken;
    if (!refresh) throw new Error("Not signed in to Google.");
    // The refresh exchange needs the client secret, which now lives in Core.
    let granted;
    try {
      granted = await this.oauth.google.accessToken(PROVIDER, refresh);
    } catch (error) {
      // A refresh token that Google will not honour is not a transient
      // failure — it never recovers. Keeping it means the panel says
      // "connected" and every cycle fails, with no button that fixes it.
      //
      // The case that made this necessary: upgrading from a version that
      // used the device flow. That token was issued to a DIFFERENT OAuth
      // client, so the new one cannot refresh it. Same for a grant the user
      // revoked in their Google account.
      this.storage.delete("refreshToken");
      this.accessToken = null;
      throw new Error(`Google would not renew this device's access, so it has been signed out. Sign in again. (${error.message || error})`);
    }
    this.accessToken = granted.accessToken;
    this.expiresAt = Date.now() + (granted.expiresIn || 3600) * 1000;
    return this.accessToken;
  }

  async signIn() {
    // Returns once the browser round trip is done; Core holds the loopback
    // socket open for three minutes and gives up after that.
    const granted = await this.oauth.google.signIn(PROVIDER);
    if (!granted.refreshToken) throw new Error("Google did not return a refresh token.");
    this.storage.set("refreshToken", granted.refreshToken);
    this.accessToken = granted.accessToken;
    this.expiresAt = Date.now() + (granted.expiresIn || 3600) * 1000;
  }

  /**
   * Revoking on the way out matters more than usual here: plugin storage is
   * the webview's localStorage, so a token left behind is readable by every
   * other plugin installed later.
   */
  async signOut() {
    const refresh = this.refreshToken;
    this.storage.delete("refreshToken");
    this.storage.delete("folderId");
    this.accessToken = null;
    if (!refresh) return;
    try {
      await this.oauth.google.revoke(refresh);
    } catch { /* the local token is already gone; a stale grant is the lesser problem */ }
  }

  async api(path, init = {}) {
    const headers = new Headers(init.headers);
    headers.set("Authorization", `Bearer ${await this.token()}`);
    const response = await fetch(`https://www.googleapis.com${path}`, { ...init, headers });
    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Drive returned ${response.status}: ${text.slice(0, 200)}`);
    }
    return response;
  }

  async folderId() {
    const cached = this.storage.get("folderId");
    if (cached) return cached;
    const query = `name='${FOLDER_NAME}' and mimeType='application/vnd.google-apps.folder' and trashed=false`;
    const found = await (await this.api(`/drive/v3/files?q=${encodeURIComponent(query)}&fields=files(id)`)).json();
    const id = found.files?.[0]?.id ?? (await (await this.api("/drive/v3/files?fields=id", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: FOLDER_NAME, mimeType: "application/vnd.google-apps.folder" }),
    })).json()).id;
    this.storage.set("folderId", id);
    return id;
  }

  /** The `media` subfolder, created on first use. */
  async mediaFolderId() {
    const cached = this.storage.get("mediaFolderId");
    if (cached) return cached;
    const parent = await this.folderId();
    const query = `name='media' and '${parent}' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false`;
    const found = await (await this.api(`/drive/v3/files?q=${encodeURIComponent(query)}&fields=files(id)`)).json();
    const id = found.files?.[0]?.id ?? (await (await this.api("/drive/v3/files?fields=id", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "media", mimeType: "application/vnd.google-apps.folder", parents: [parent] }),
    })).json()).id;
    this.storage.set("mediaFolderId", id);
    return id;
  }

  /**
   * Every file in a folder, following `nextPageToken`.
   *
   * The page used to stop at 100 with the token ignored. Past that, this
   * device's own snapshot fell off the end of the list, `upload` took the
   * "create" branch, and a SECOND `device-<id>.json` appeared — after which
   * peers applied two diverging snapshots from the same machine. Media files
   * live in their own folder partly so they cannot push the snapshots off a
   * page, but the paging is the actual fix.
   */
  async list(folderId) {
    const parent = folderId ?? (await this.folderId());
    const query = `'${parent}' in parents and trashed=false`;
    const files = [];
    let pageToken = "";
    do {
      const page = `/drive/v3/files?q=${encodeURIComponent(query)}&fields=nextPageToken,files(id,name,modifiedTime)&pageSize=1000${pageToken ? `&pageToken=${encodeURIComponent(pageToken)}` : ""}`;
      const found = await (await this.api(page)).json();
      files.push(...(found.files ?? []));
      pageToken = found.nextPageToken ?? "";
      // A folder this large is a bug somewhere else; stop rather than page
      // forever on a runaway account.
      if (files.length > 20_000) break;
    } while (pageToken);
    return files;
  }

  async download(fileId) {
    return new Uint8Array(await (await this.api(`/drive/v3/files/${fileId}?alt=media`)).arrayBuffer());
  }

  async upload(name, bytes, existingId, parentId) {
    const metadata = existingId ? {} : { name, parents: [parentId ?? (await this.folderId())] };
    const boundary = `notible${crypto.randomUUID()}`;
    const head = `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify(metadata)}\r\n--${boundary}\r\nContent-Type: application/octet-stream\r\n\r\n`;
    const body = new Blob([head, bytes, `\r\n--${boundary}--`]);
    const path = existingId
      ? `/upload/drive/v3/files/${existingId}?uploadType=multipart&fields=id`
      : "/upload/drive/v3/files?uploadType=multipart&fields=id";
    const response = await this.api(path, {
      method: existingId ? "PATCH" : "POST",
      headers: { "Content-Type": `multipart/related; boundary=${boundary}` },
      body,
    });
    return (await response.json()).id;
  }
}

// ------------------------------------------------------------------ the sync

class Sync {
  constructor(context) {
    this.context = context;
    this.google = new Google(context.storage, context.oauth);
    this.applying = false;
    this.openObjectId = null;
    this.status = { state: "idle", text: "Never synchronised." };
    this.listeners = new Set();
  }

  onStatus(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  setStatus(state, text) {
    this.status = { state, text };
    for (const listener of this.listeners) listener(this.status);
  }

  keyBytes() {
    const stored = this.context.storage.get("key");
    if (!stored) throw new Error("This device is not paired yet.");
    return decodeKey(stored);
  }

  createKey() {
    const key = encodeKey(crypto.getRandomValues(new Uint8Array(32)));
    this.context.storage.set("key", key);
    return key;
  }

  usePairingKey(text) {
    const bytes = decodeKey(text);
    this.context.storage.set("key", encodeKey(bytes));
  }

  /**
   * Carry pasted images both ways.
   *
   * One file per image, in its own Drive folder, uploaded once: the name is a
   * UUID, so a file that is there is already the right one. Snapshots are
   * re-uploaded every cycle and a 20 MB screenshot inside one would make that
   * a bill rather than a sync.
   *
   * Every failure here is reported and stepped over. A missing picture is
   * worth a line in the status; it is not worth abandoning a cycle that
   * carried the text successfully.
   */
  async syncMedia(snapshot, key, notes) {
    const wanted = mediaNamesOf(snapshot.objects);
    if (!wanted.length) return { pulled: 0, pushed: 0 };
    let missing = [];
    try {
      missing = await this.context.data.sync.media.missing(wanted);
    } catch (error) {
      notes.push(`media: ${error.message}`);
      return { pulled: 0, pushed: 0 };
    }
    const folder = await this.google.mediaFolderId();
    const remote = new Map((await this.google.list(folder)).map((file) => [file.name, file.id]));

    let pulled = 0;
    for (const name of missing) {
      const id = remote.get(`${name}.bin`);
      // Not on Drive yet: the machine that pasted it has not run a cycle
      // since. Nothing is wrong and nothing needs saying.
      if (!id) continue;
      try {
        // `seal` JSON-encodes its payload, so what comes back out is the
        // base64 string that went in.
        const base64 = await unseal(key, await this.google.download(id));
        await this.context.data.sync.media.write(name, base64);
        pulled += 1;
      } catch (error) {
        notes.push(`${name}: ${error.message}`);
      }
    }

    let pushed = 0;
    const present = wanted.filter((name) => !missing.includes(name));
    for (const name of present) {
      if (remote.has(`${name}.bin`)) continue;
      try {
        const base64 = await this.context.data.sync.media.read(name);
        await this.google.upload(`${name}.bin`, await seal(key, base64), undefined, folder);
        pushed += 1;
      } catch (error) {
        // The likeliest cause by far: the user has not switched image
        // reading on. Say it once, not once per file.
        notes.push(`images not sent: ${error.message}`);
        break;
      }
    }
    return { pulled, pushed };
  }

  async run() {
    if (this.applying) return null;
    this.applying = true;
    try {
      this.setStatus("busy", "Synchronising…");
      const key = this.keyBytes();
      const local = await this.context.data.sync.export();
      const files = await this.google.list();
      const mine = `device-${local.deviceId}.json`;

      let pulled = 0;
      let skipped = 0;
      const notes = [];
      const types = new Set((await this.context.data.types.list()).map((type) => type.name));

      for (const file of files) {
        if (file.name === mine) continue;
        let validated;
        try {
          validated = validateSnapshot(await unseal(key, await this.google.download(file.id)), types);
        } catch (error) {
          // One unreadable peer file must not stop the others, and must never
          // be read as "that device deleted everything".
          notes.push(`${file.name}: ${error.message}`);
          continue;
        }
        if (validated.rejected.length) notes.push(`${file.name}: skipped ${validated.rejected.length} object(s)`);
        const { apply, deferred } = planApply(validated, this.openObjectId);
        skipped += deferred.length;
        const result = await this.context.data.sync.apply({
          cursor: local.cursor,
          objects: apply.objects,
          relations: apply.relations,
          tombstones: apply.tombstones,
          relation_tombstones: apply.relationTombstones,
        });
        pulled += result.appliedObjects;
      }

      // Push last, so what we upload already includes anything just pulled.
      const fresh = await this.context.data.sync.export();
      const media = await this.syncMedia(fresh, key, notes);
      const sealed = await seal(key, {
        v: SNAPSHOT_VERSION,
        deviceId: fresh.deviceId,
        writtenAt: Date.now(),
        objects: fresh.objects,
        relations: fresh.relations,
        tombstones: fresh.tombstones,
        relationTombstones: fresh.relationTombstones,
      });
      await this.google.upload(mine, sealed, files.find((file) => file.name === mine)?.id);

      this.context.storage.set("lastSync", Date.now());
      const detail = [
        `${pulled} change(s) in`,
        `${fresh.objects.length} object(s) out`,
        media.pulled ? `${media.pulled} image(s) in` : null,
        media.pushed ? `${media.pushed} image(s) out` : null,
        skipped ? `${skipped} held back (note is open)` : null,
      ].filter(Boolean).join(", ");
      this.setStatus("ok", `${detail}.${notes.length ? ` ${notes.join(" ")}` : ""}`);
      return { pulled, skipped, notes, media };
    } catch (error) {
      this.setStatus("error", error.message || String(error));
      throw error;
    } finally {
      this.applying = false;
    }
  }
}

// ----------------------------------------------------------------------- UI

const styles = `
/*
 * Written on the PUBLIC token contract (--notible-*), with no colour literals
 * anywhere. The previous version fell back to its own hexes — including a
 * green accent — so on any host that had not defined the deprecated
 * unprefixed aliases this panel rendered in colours Notible does not own.
 *
 * The visual rules are the app's: an outline instead of a fill, no coloured
 * ribbon, no card-inside-a-card, and no title (the settings navigation
 * already names this screen).
 */
.nsync {
  display: grid;
  gap: 14px;
  max-width: 100%;
  color: var(--notible-text);
}
.nsync-shell { display: grid; gap: 12px; }
/* Each step is a disclosure: finished setup collapses to its header, the
   parts you actually use stay open. Header doubles as the summary. */
.nsync-step > summary { list-style: none; cursor: pointer; }
.nsync-step > summary::-webkit-details-marker { display: none; }
.nsync-step > summary::after { content: "\\25B8"; margin-left: 2px; color: var(--notible-faint); font-size: 11px; }
.nsync-step[open] > summary::after { content: "\\25BE"; }
.nsync-step:not([open]) { gap: 0; }
.nsync-lead { margin: 0; max-width: 66ch; color: var(--notible-muted); font-size: 13px; line-height: 1.55; }
.nsync-summary {
  display: flex;
  align-items: center;
  gap: 9px;
  padding-bottom: 10px;
  border-bottom: 1px solid var(--notible-border);
  color: var(--notible-muted);
  font-size: 12px;
}
.nsync-summary__dot {
  width: 8px;
  height: 8px;
  flex: 0 0 auto;
  border-radius: 50%;
  background: var(--notible-border);
}
/* Three states, three colours, all from the public contract: --notible-success
  is Notible's own muted sage — a healthy sync should read as calm, not as a
   traffic light. Work in progress borrows the accent; trouble is the same red
   the rest of the app uses for it. */
.nsync-summary[data-state="ok"] { color: var(--notible-success); }
.nsync-summary[data-state="busy"] { color: var(--notible-accent); }
.nsync-summary[data-state="error"] { color: var(--notible-danger); }
.nsync-summary[data-state="ok"] .nsync-summary__dot { background: var(--notible-success); }
.nsync-summary[data-state="busy"] .nsync-summary__dot { background: var(--notible-accent); }
.nsync-summary[data-state="error"] .nsync-summary__dot { background: var(--notible-danger); }
.nsync-body { display: grid; }
/* No card per step — a hairline between rows, the way Core's own settings
   list reads. The chevron and the status word share the right edge. */
.nsync-step {
  display: grid;
  gap: 10px;
  padding: 13px 0;
  border-top: 1px solid var(--notible-border-subtle, var(--notible-border));
}
.nsync-step:first-of-type { border-top: 0; }
.nsync-step__header {
  display: flex;
  align-items: center;
  gap: 10px;
}
.nsync-step__heading { display: flex; align-items: baseline; gap: 9px; min-width: 0; }
/* The step number orders the setup; it is not decoration, so it stays quiet
   rather than wearing the accent colour. */
.nsync-step__number { color: var(--notible-faint); font-size: 11px; font-variant-numeric: tabular-nums; }
.nsync-step h4 { margin: 0; color: var(--notible-text); font-size: 14px; line-height: 1.2; }
.nsync-step__badge { flex: 0 0 auto; margin-left: auto; color: var(--notible-muted); font-size: 11px; }
.nsync-step p { max-width: 66ch; margin: 0; color: var(--notible-muted); font-size: 12px; line-height: 1.55; }
.nsync-actions,
.nsync-row { display: flex; align-items: center; gap: 9px; flex-wrap: wrap; }
.nsync button {
  min-height: 32px;
  padding: 6px 11px;
  border: 1px solid var(--notible-border);
  border-radius: 7px;
  background: transparent;
  color: var(--notible-text);
  font: inherit;
  font-size: 12px;
  cursor: pointer;
  transition: background-color 160ms ease, border-color 160ms ease;
}
.nsync button:hover:not(:disabled) { border-color: var(--notible-accent); background: var(--notible-hover); }
.nsync button:focus-visible,
.nsync input:focus-visible { outline: 2px solid var(--notible-accent); outline-offset: 2px; }
.nsync button:disabled { cursor: not-allowed; opacity: .46; }
.nsync .nsync-button--primary {
  border-color: var(--notible-accent);
  background: var(--notible-accent);
  color: var(--notible-on-accent);
  font-weight: 600;
}
.nsync .nsync-button--primary:hover:not(:disabled) { border-color: var(--notible-accent-hover); background: var(--notible-accent-hover); }
.nsync .nsync-button--danger { border-color: var(--notible-border); color: var(--notible-danger); }
.nsync .nsync-button--danger:hover:not(:disabled) { border-color: var(--notible-danger); background: var(--notible-danger-surface); }
.nsync code {
  font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
  font-size: 12px;
  letter-spacing: .045em;
  word-break: break-all;
}
.nsync-key {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 11px;
  border: 1px solid var(--notible-border);
  border-radius: 8px;
}
.nsync-key code { min-width: 0; flex: 1; color: var(--notible-text); }
.nsync input:not([type="checkbox"]) {
  min-width: 0;
  min-height: 32px;
  padding: 6px 9px;
  border: 1px solid var(--notible-border);
  border-radius: 7px;
  background: var(--notible-surface);
  color: var(--notible-text);
  font: inherit;
  font-size: 12px;
}
.nsync input[type="number"] { width: 70px; text-align: center; font-variant-numeric: tabular-nums; }
.nsync input[type="checkbox"] {
  width: 18px;
  height: 18px;
  flex: 0 0 auto;
  margin: 0;
  accent-color: var(--notible-accent);
}
.nsync-pairing-entry { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 9px; }
.nsync-schedule {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) auto auto;
  align-items: center;
  gap: 9px;
  color: var(--notible-muted);
  font-size: 12px;
}
.nsync-schedule__label { min-width: 0; }
.nsync-status { display: grid; gap: 4px; }
.nsync .status { margin: 0; color: var(--notible-muted); font-size: 12px; line-height: 1.45; }
.nsync .status[data-state="busy"],
.nsync .status[data-state="ok"] { color: var(--notible-accent); }
.nsync .status[data-state="error"],
.nsync-error { color: var(--notible-danger); }
.nsync-error { min-height: 1em; }
.nsync-hint { color: var(--notible-faint) !important; font-size: 11px !important; }
@media (max-width: 520px) {
  .nsync-pairing-entry { grid-template-columns: 1fr; }
  .nsync-schedule { grid-template-columns: auto minmax(0, 1fr); }
  .nsync-schedule__interval,
  .nsync-schedule__suffix { grid-column: 2; }
}
`;

function element(tag, properties = {}, children = []) {
  const node = Object.assign(document.createElement(tag), properties);
  for (const child of children) node.append(child);
  return node;
}

function mountPanel(sync, container) {
  const root = element("div", { className: "nsync" });
  root.append(element("style", { textContent: styles }));
  const shell = element("div", { className: "nsync-shell" });
  shell.append(element("p", { className: "nsync-lead", textContent: "Keeps this workspace in step across your devices through your own Google Drive. Nothing leaves this machine unencrypted." }));

  const status = element("div", { className: "status" });
  status.setAttribute("role", "status");
  status.setAttribute("aria-live", "polite");
  const summaryText = element("span", {});
  const summary = element("div", { className: "nsync-summary" }, [
    element("span", { className: "nsync-summary__dot" }),
    summaryText,
  ]);
  shell.append(summary);
  const paint = ({ state, text }) => {
    status.dataset.state = state;
    const lastSync = sync.context.storage.get("lastSync");
    status.textContent = state === "idle" && lastSync
      ? `Last synced ${new Date(lastSync).toLocaleString()}`
      : text;
    summary.dataset.state = state;
    summaryText.textContent = ({ idle: "Ready when setup is complete", busy: "Synchronising", ok: "Synced", error: "Needs attention" })[state] ?? "Notible Sync";
  };
  const stopWatching = sync.onStatus(paint);
  paint(sync.status);

  // Steps are collapsed by default and only stay open if the user opens
  // them. `render()` rebuilds every <details>, so the open set lives out
  // here to survive a re-render.
  const openSteps = new Set();
  const stepDetails = (step, { primary } = {}) => {
    const details = element("details", { className: "nsync-step", open: openSteps.has(step) });
    details.dataset.step = step;
    if (primary) details.dataset.primary = "true";
    details.addEventListener("toggle", () => { details.open ? openSteps.add(step) : openSteps.delete(step); });
    return details;
  };

  const render = () => {
    body.replaceChildren();
    const signedIn = sync.google.signedIn();
    const paired = Boolean(sync.context.storage.get("key"));
    const ready = signedIn && paired;
    summary.dataset.setup = ready ? "ready" : "incomplete";
    if (sync.status.state === "idle") {
      summaryText.textContent = ready ? "Ready to synchronise" : "Complete setup to begin";
    }

    // --- account
    const account = element("details", { className: "nsync-step", "data-step": "1", open: !signedIn });
    account.append(element("summary", { className: "nsync-step__header" }, [
      element("div", { className: "nsync-step__heading" }, [
        element("span", { className: "nsync-step__number", textContent: "01" }),
        element("h4", { textContent: "Google account" }),
      ]),
      element("span", { className: "nsync-step__badge", textContent: signedIn ? "Connected" : "Not connected" }),
    ]));
    if (signedIn) {
      const out = element("button", { className: "nsync-button--danger", type: "button", textContent: "Sign out and revoke access" });
      out.onclick = async () => { await sync.google.signOut(); render(); };
      account.append(
        element("p", {
          textContent: `Snapshots live in a visible “${FOLDER_NAME}” folder on your Drive.`,
          title: "Pasted images go in its “media” subfolder, and only travel while Settings → Files & links → “Let plugins read pasted images” is on. Notes sync either way.",
        }),
        element("div", { className: "nsync-actions" }, [out]),
      );
    } else {
      const button = element("button", { className: "nsync-button--primary", type: "button", textContent: "Sign in with Google" });
      const hint = element("p", { className: "nsync-hint", textContent: "Notible encrypts your notes before they leave this device." });
      button.onclick = async () => {
        button.disabled = true;
        const original = hint.textContent;
        hint.textContent = "Finish signing in in your browser, then come back here.";
        try {
          await sync.google.signIn();
          render();
        } catch (error) {
          hint.textContent = error.message;
        } finally {
          button.disabled = false;
          if (hint.textContent.startsWith("Finish signing in")) hint.textContent = original;
        }
      };
      account.append(element("div", { className: "nsync-actions" }, [button]), hint);
    }
    body.append(account);

    // --- pairing
    const pairing = element("details", { className: "nsync-step", "data-step": "2", open: !paired });
    pairing.append(element("summary", { className: "nsync-step__header" }, [
      element("div", { className: "nsync-step__heading" }, [
        element("span", { className: "nsync-step__number", textContent: "02" }),
        element("h4", { textContent: "Pairing key" }),
      ]),
      element("span", { className: "nsync-step__badge", textContent: paired ? "Paired" : "Needs setup" }),
    ]));
    if (paired) {
      const pairingKey = sync.context.storage.get("key");
      const copy = element("button", { className: "nsync-button", type: "button", textContent: "Copy key" });
      copy.onclick = async () => {
        const original = copy.textContent;
        try {
          await navigator.clipboard.writeText(pairingKey);
          copy.textContent = "Copied";
        } catch {
          copy.textContent = "Copy unavailable";
        }
        setTimeout(() => { copy.textContent = original; }, 1800);
      };
      pairing.append(
        element("p", { textContent: "Enter this key on your other device. Anyone without it cannot read your snapshots. Keep it somewhere safe: it cannot be recovered." }),
        element("div", { className: "nsync-key" }, [element("code", { textContent: pairingKey }), copy]),
      );
    } else {
      const input = element("input", { id: "nsync-pairing-key", placeholder: "Paste the key from your first device", spellcheck: false, autocomplete: "off" });
      const label = element("label", { className: "nsync-hint", htmlFor: "nsync-pairing-key", textContent: "Create a key on your first device, then paste it here." });
      const create = element("button", { type: "button", textContent: "Create a new key" });
      const use = element("button", { className: "nsync-button--primary", type: "button", textContent: "Use this key" });
      const error = element("p", { className: "nsync-error" });
      error.setAttribute("role", "alert");
      create.onclick = () => { sync.createKey(); render(); };
      use.onclick = () => {
        try { sync.usePairingKey(input.value); render(); } catch (problem) { error.textContent = problem.message; }
      };
      pairing.append(
        label,
        element("div", { className: "nsync-actions" }, [create]),
        element("div", { className: "nsync-pairing-entry" }, [input, use]),
        error,
      );
    }
    body.append(pairing);

    // --- run
    const runState = sync.status.state === "busy"
      ? "Working"
      : sync.status.state === "error"
        ? "Needs attention"
        : ready
          ? sync.status.state === "ok" ? "Up to date" : "Ready"
          : "Locked";
    const run = stepDetails("3", { primary: true });
    run.append(element("summary", { className: "nsync-step__header" }, [
      element("div", { className: "nsync-step__heading" }, [
        element("span", { className: "nsync-step__number", textContent: "03" }),
        element("h4", { textContent: "Synchronise" }),
      ]),
      element("span", { className: "nsync-step__badge", textContent: runState }),
    ]));
    const now = element("button", { className: "nsync-button--primary", type: "button", textContent: "Synchronise now", disabled: !ready });
    now.onclick = async () => {
      now.disabled = true;
      try { await sync.run(); } catch { /* status already shows it */ } finally { now.disabled = false; }
    };
    run.append(
      element("p", {
        textContent: "The first run uploads this device’s workspace and downloads the others. Nothing is merged or deleted automatically.",
        title: "Pasted images travel too, but only while Settings → Files & links → “Let plugins read pasted images” is on. Notes sync either way.",
      }),
      element("div", { className: "nsync-actions" }, [now]),
      element("div", { className: "nsync-status" }, [
        status,
        !ready ? element("p", { className: "nsync-hint", textContent: "Connect Google Drive and pair this device to enable synchronisation." }) : null,
      ].filter(Boolean)),
    );
    body.append(run);

    // --- automatic
    const auto = stepDetails("4");
    auto.append(element("summary", { className: "nsync-step__header" }, [
      element("div", { className: "nsync-step__heading" }, [
        element("span", { className: "nsync-step__number", textContent: "04" }),
        element("h4", { textContent: "Automatic synchronisation" }),
      ]),
      element("span", { className: "nsync-step__badge", textContent: "Optional" }),
    ]));
    const toggle = element("input", { id: "nsync-auto-toggle", type: "checkbox", checked: Boolean(sync.context.storage.get("auto")) });
    const every = element("input", {
      className: "nsync-schedule__interval",
      type: "number", min: "1", max: "1440", inputmode: "numeric",
      value: String(sync.context.storage.get("intervalMinutes") ?? DEFAULT_INTERVAL_MINUTES),
    });
    every.disabled = !toggle.checked;
    const persist = () => {
      sync.context.storage.set("auto", toggle.checked);
      sync.context.storage.set("intervalMinutes", Math.min(1440, Math.max(1, Number(every.value) || DEFAULT_INTERVAL_MINUTES)));
      every.disabled = !toggle.checked;
      sync.onScheduleChanged?.();
    };
    toggle.onchange = persist;
    every.onchange = persist;
    auto.append(
      element("div", { className: "nsync-schedule" }, [
        toggle,
        element("label", { className: "nsync-schedule__label", htmlFor: "nsync-auto-toggle", textContent: "Synchronise on a timer, every" }),
        every,
        element("span", { className: "nsync-schedule__suffix", textContent: "minutes" }),
      ]),
      element("p", { className: "nsync-hint", textContent: "Off by default. Automatic runs still contact Google to check for changes." }),
    );
    body.append(auto);
  };

  const body = element("div", { className: "nsync-body" });
  shell.append(body);
  root.append(shell);
  render();
  container.append(root);
  return { dispose: () => { stopWatching(); root.remove(); } };
}

// ------------------------------------------------------------------- plugin

export default {
  // Core reads `plugin.json` first, then checks that the entry module claims
  // the same identity — an entry that disagrees with the manifest the user
  // was shown is refused. Keep id, version and apiVersion in step with
  // plugin.json; `self-check.mjs` asserts they match.
  manifest: {
    id: "notible.sync",
    name: "Notible Sync",
    version: "0.4.2",
    apiVersion: "1.7",
    description: "Replicate this workspace between your own machines through your own Google Drive. Snapshots are encrypted on this device before upload, so neither Notible nor Google can read them. Nothing is merged and nothing is deleted behind your back.",
    author: "Notible",
    permissions: ["data.sync", "data.read", "workspace.ui", "network"],
  },

  onload(context) {
    const sync = new Sync(context);
    this._sync = sync;
    this._disposables = [];

    this._disposables.push(context.events.on("object.opened", (payload) => { sync.openObjectId = payload?.id ?? null; }));

    // Renders in this plugin's own detail pane on the Plugins screen (Core
    // draws `settings.register({ mount })` there), so it shows only when the
    // user picks this row — not on the empty Plugins screen for everyone.
    this._disposables.push(context.settings.register({
      id: "sync",
      title: "Account & sync",
      mount: ({ container }) => mountPanel(sync, container),
    }));

    this._disposables.push(context.commands.register({
      id: "now",
      name: "Sync: synchronise now",
      description: "Push this device's snapshot and take in the others.",
      execute: () => sync.run(),
    }));

    // ponytail: a timer, not a change feed. `object.updated` also fires for
    // our own writes, so reacting to it means filtering our own echo; a plain
    // interval cannot loop and is honest about being eventually consistent.
    const reschedule = () => {
      clearInterval(this._timer);
      this._timer = null;
      if (!context.storage.get("auto")) return;
      const minutes = Math.max(1, context.storage.get("intervalMinutes") ?? DEFAULT_INTERVAL_MINUTES);
      this._timer = setInterval(() => { sync.run().catch(() => {}); }, minutes * 60_000);
    };
    sync.onScheduleChanged = reschedule;
    reschedule();
  },

  onunload() {
    clearInterval(this._timer);
    this._timer = null;
    for (const disposable of this._disposables ?? []) disposable.dispose?.();
    this._disposables = [];
    this._sync = null;
  },
};
