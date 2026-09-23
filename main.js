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

  // Both optional and display-only: older versions of this plugin write
  // neither, and a peer's panel shows what it has.
  const deviceName = isString(snapshot.deviceName) ? snapshot.deviceName.slice(0, 80) : "";
  const writtenAt = isTimestamp(snapshot.writtenAt) ? snapshot.writtenAt : null;
  return { deviceId: snapshot.deviceId, deviceName, writtenAt, objects, relations, tombstones, relationTombstones, rejected };
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

/** SHA-256 of a value's JSON, as hex. Used to skip re-uploading a snapshot
 * that has not changed since this device last sent it. */
export async function digestOf(value) {
  const bytes = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(JSON.stringify(value))));
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

// ---------------------------------------------------------------- conflicts
//
// Without this, an object edited on two devices between syncs kept whichever
// edit was newer and dropped the other without a word. Now:
//
// - "Edited on both" is told apart from "edited on one side" by a BASE: the
//   object as it looked in that peer's snapshot the last time this device read
//   it. Local differs from the base -> we changed it since; remote differs ->
//   the peer did. Both, and different from each other -> a conflict. Hashes,
//   not clocks, so a machine whose clock is off cannot fake or hide one.
// - A table (whose rows, columns and cells all carry ids) is merged cell by
//   cell: a column added here and a cell changed there both survive.
// - Anything else, or a cell changed on both sides: the newer version wins as
//   before, and the losing one is saved next to it as a conflict copy. Only the
//   device whose OWN version lost makes that copy -- both devices see the same
//   conflict, and the copy must appear once.
//
// No base yet (first run on this version, or an object new to that peer):
// plain newest-wins, exactly the old behaviour.

/** Table props kept as merge bases, per peer, in characters. */
const TABLE_BASE_BUDGET = 500_000;

/** cyrb53: a fast 53-bit string hash. Not security -- a collision would only
 * hide one conflict, which is the old behaviour anyway. */
function hash53(text) {
  let h1 = 0xdeadbeef;
  let h2 = 0x41c6ce57;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(36);
}

// Props minus what a device writes for itself. Automations keeps a run log
// in the project's props, rewritten on each device on its own; counted as
// content, two devices that both ran a check looked like a conflicting edit
// and one of them made a conflict copy every sync cycle.
function userProps(props) {
  if (typeof props !== "string" || !props.includes("_automationLog")) return props;
  try {
    const { _automationLog, ...rest } = JSON.parse(props);
    return JSON.stringify(rest);
  } catch {
    return props;
  }
}

/** What a user would call "the object's content" -- everything but the clock. */
export function objectHash(object) {
  return hash53(JSON.stringify([
    object.type, object.title, object.content, userProps(object.props),
    object.archived_at ?? null, object.trashed_at ?? null, object.parent_id ?? null,
  ]));
}

// An empty cell has several spellings ("", null, missing, an unticked box);
// they must compare equal or a column added on one side reads as a conflict
// in every row.
const isEmptyCell = (value) => value === undefined || value === null || value === "" || value === false;
// Key order must not matter either: Tables writes a row's cells in column
// order, so the same row can come back spelled differently.
const canon = (value) => JSON.stringify(value ?? null, (_, v) => (v && typeof v === "object" && !Array.isArray(v)
  ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, v[k]]))
  : v));
const cellKey = (value) => (isEmptyCell(value) ? "" : canon(value));
const valueKey = (value) => canon(value);
const rowKey = (row) => canon(Object.fromEntries(Object.entries(row?.cells ?? {}).filter(([, v]) => !isEmptyCell(v))));

/**
 * Three-way merge of two Tables `props` strings against their common base.
 * `localNewer` breaks ties (same cell changed on both sides): the newer
 * object's value wins. Returns null when any side is not a readable table --
 * the caller then falls back to a conflict copy. `localLost` says whether any
 * of this device's cell edits lost, i.e. whether this device owes a copy.
 *
 * The output is canonical (sorted keys) so both devices, merging the same
 * three versions from opposite ends, write byte-identical props and the
 * exchange settles instead of ping-ponging.
 */
export function mergeTableProps(baseText, localText, remoteText, localNewer) {
  const parse = (text) => {
    try {
      const value = JSON.parse(text || "{}");
      return value && typeof value === "object" && !Array.isArray(value) ? value : null;
    } catch {
      return null;
    }
  };
  const base = parse(baseText);
  const mine = parse(localText);
  const theirs = parse(remoteText);
  if (!base || !mine || !theirs) return null;

  let conflicts = 0;
  let localLost = false;
  const pick = (b, l, r, key, isCell) => {
    if (key(l) === key(r)) return l;
    if (key(l) === key(b)) return r;
    if (key(r) === key(b)) return l;
    if (isCell) {
      conflicts += 1;
      if (!localNewer) localLost = true;
    }
    return localNewer ? l : r;
  };
  const byId = (list) => new Map((Array.isArray(list) ? list : [])
    .filter((item) => item && typeof item.id === "string")
    .map((item) => [item.id, item]));
  const sorted = (object) => Object.fromEntries(Object.keys(object).sort().map((k) => [k, object[k]]));

  const mergeList = (field, mergeItem, itemKey) => {
    const b = byId(base[field]);
    const l = byId(mine[field]);
    const r = byId(theirs[field]);
    const [first, second] = localNewer ? [l, r] : [r, l];
    const out = [];
    for (const id of new Set([...first.keys(), ...second.keys()])) {
      const bi = b.get(id);
      const li = l.get(id);
      const ri = r.get(id);
      if (li && ri) { out.push(mergeItem(bi, li, ri)); continue; }
      const present = li ?? ri;
      // Added on one side: keep. Deleted on one side: gone -- unless the
      // other side changed it since, in which case keeping it loses nothing.
      if (!bi || itemKey(bi) !== itemKey(present)) out.push(present);
    }
    return out;
  };

  const merged = {
    columns: mergeList("columns", (b, l, r) => sorted(pick(b, l, r, valueKey, false)), valueKey),
    rows: mergeList("rows", (b, l, r) => {
      const cells = {};
      const ids = new Set([...Object.keys(l.cells ?? {}), ...Object.keys(r.cells ?? {})]);
      for (const id of [...ids].sort()) {
        const value = pick(b?.cells?.[id], l.cells?.[id], r.cells?.[id], cellKey, true);
        if (value !== undefined) cells[id] = value;
      }
      return { id: l.id, cells };
    }, rowKey),
  };
  // Styles, merged cells, width lock: whole-value three-way, newer wins a tie.
  // Not counted as a lost edit -- they are formatting, not data.
  for (const key of new Set([...Object.keys(mine), ...Object.keys(theirs)])) {
    if (key === "columns" || key === "rows") continue;
    const value = pick(base[key], mine[key], theirs[key], valueKey, false);
    if (value !== undefined) merged[key] = value;
  }
  return { props: JSON.stringify(sorted(merged)), conflicts, localLost };
}

/**
 * Decide what to hand `data.sync.apply` for one peer's objects.
 *
 * `localById` is this device's current objects; `bases` / `tableBases` are
 * that peer's objects (hash / table props) as last read. Returns the objects
 * to apply -- merged tables and conflict copies included -- plus a status
 * note per conflict.
 */
export function planConflicts(remoteObjects, localById, bases, tableBases, copyLabel, now = Date.now()) {
  const objects = [];
  const notes = [];
  let conflicts = 0;
  const copyOf = (local) => ({
    ...local,
    id: crypto.randomUUID(),
    title: `${local.title || "Untitled"} (conflict copy — ${copyLabel})`.slice(0, LIMITS.title),
    created_at: now,
    updated_at: now,
  });

  for (const remote of remoteObjects) {
    const local = localById.get(remote.id);
    const base = bases[remote.id];
    const remoteHash = objectHash(remote);
    const localHash = local ? objectHash(local) : null;
    if (!local || !base || remoteHash === localHash || localHash === base || remoteHash === base) {
      objects.push(remote);
      continue;
    }
    conflicts += 1;
    const localNewer = local.updated_at !== remote.updated_at ? local.updated_at > remote.updated_at : localHash > remoteHash;
    // Strictly newer than both, so Core's newest-wins takes it on every device.
    const stamp = Math.max(local.updated_at, remote.updated_at) + 1;
    const title = remote.title || local.title || "Untitled";

    const merged = remote.type === "table" && local.type === "table" && typeof tableBases[remote.id] === "string"
      ? mergeTableProps(tableBases[remote.id], local.props, remote.props, localNewer)
      : null;
    if (merged) {
      objects.push({ ...(localNewer ? local : remote), props: merged.props, updated_at: stamp });
      if (merged.localLost) objects.push(copyOf(local));
      notes.push(merged.conflicts
        ? `"${title}": merged edits from both devices; ${merged.conflicts} cell(s) changed on both, newer kept${merged.localLost ? ", this device's version saved as a conflict copy" : ""}.`
        : `"${title}": merged edits from both devices.`);
      continue;
    }

    if (localNewer) {
      // Core keeps ours by itself. The other device copies its own version
      // when it reads this one.
      notes.push(`"${title}": edited on both devices; this device's newer version kept.`);
      continue;
    }
    objects.push(remote.updated_at > local.updated_at ? remote : { ...remote, updated_at: stamp });
    // A version that was in the trash is not worth resurrecting as a copy.
    if (!local.trashed_at) objects.push(copyOf(local));
    notes.push(`"${title}": edited on both devices; the other device's newer version kept, this device's saved as a conflict copy.`);
  }
  return { objects, notes, conflicts };
}

/** Next base for one peer: its objects as just read -- except the held-back
 * ones, which keep their old base because this device has not taken them. */
export function nextBases(peerObjects, previous, previousTables, heldBack) {
  const bases = {};
  const tables = {};
  let budget = TABLE_BASE_BUDGET;
  for (const object of peerObjects) {
    if (heldBack.has(object.id)) {
      if (previous[object.id]) bases[object.id] = previous[object.id];
      if (previousTables[object.id]) tables[object.id] = previousTables[object.id];
      continue;
    }
    bases[object.id] = objectHash(object);
    // ponytail: bases live in the app's shared localStorage (a few MB for
    // every plugin together), so big tables get no base and fall back to a
    // conflict copy. A Core-side store would lift this.
    if (object.type === "table" && object.props.length <= budget) {
      tables[object.id] = object.props;
      budget -= object.props.length;
    }
  }
  return { bases, tables };
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

  /** What other devices call this one in their panel. Blank until named. */
  deviceName() {
    return String(this.context.storage.get("deviceName") ?? "").trim().slice(0, 80);
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
      let conflicts = 0;
      // This device's objects as they stand, kept current as each peer is
      // applied, so the next peer's conflicts are judged against the result.
      const localById = new Map(local.objects.map((object) => [object.id, object]));
      const copyLabel = `${this.deviceName() || "this device"}, ${new Date().toLocaleString()}`;
      const notes = [];
      const types = new Set((await this.context.data.types.list()).map((type) => type.name));

      // Peer snapshots already applied, by Drive file id -> modifiedTime, so an
      // unchanged one is not downloaded and applied again every cycle.
      // ponytail: memory only. The first run after every start reads
      // everything again, which also covers a restored local database; a
      // change in installed types (objects that were refused as unknown) resets it.
      const typesKey = [...types].sort().join("\n");
      if (this.seenTypes !== typesKey) {
        this.seen = new Map();
        this.seenTypes = typesKey;
      }
      const peers = this.context.storage.get("peers") ?? {};

      for (const file of files) {
        if (file.name === mine) continue;
        if (file.modifiedTime && this.seen.get(file.id) === file.modifiedTime) continue;
        // One peer failing -- unreadable, or refused by the database -- must
        // not stop the others or this device's own push, and must never be
        // read as "that device deleted everything".
        try {
          const validated = validateSnapshot(await unseal(key, await this.google.download(file.id)), types);
          peers[validated.deviceId] = {
            name: validated.deviceName || peers[validated.deviceId]?.name || "",
            writtenAt: validated.writtenAt,
          };
          if (validated.rejected.length) notes.push(`${file.name}: skipped ${validated.rejected.length} object(s)`);
          const { apply, deferred } = planApply(validated, this.openObjectId);
          skipped += deferred.length;
          const peerBases = this.context.storage.get(`bases:${validated.deviceId}`) ?? {};
          const peerTables = this.context.storage.get(`tableBases:${validated.deviceId}`) ?? {};
          const resolved = planConflicts(apply.objects, localById, peerBases, peerTables, copyLabel);
          const result = await this.context.data.sync.apply({
            cursor: local.cursor,
            objects: resolved.objects,
            relations: apply.relations,
            tombstones: apply.tombstones,
            relation_tombstones: apply.relationTombstones,
          });
          pulled += result.appliedObjects;
          conflicts += resolved.conflicts;
          notes.push(...resolved.notes);
          // Mirror Core's newest-wins so the next peer sees what is now here.
          for (const object of resolved.objects) {
            const current = localById.get(object.id);
            if (!current || object.updated_at > current.updated_at) localById.set(object.id, object);
          }
          // Only after a successful apply: a base must never run ahead of
          // what this device actually took in.
          const next = nextBases(validated.objects, peerBases, peerTables, new Set(deferred.map((object) => object.id)));
          this.context.storage.set(`bases:${validated.deviceId}`, next.bases);
          this.context.storage.set(`tableBases:${validated.deviceId}`, next.tables);
          // Something held back has to be offered again on the next run.
          if (!deferred.length) this.seen.set(file.id, file.modifiedTime);
        } catch (error) {
          notes.push(`${file.name}: ${error.message}`);
        }
      }
      this.context.storage.set("peers", peers);

      // Push last, so what we upload already includes anything just pulled.
      const fresh = await this.context.data.sync.export();
      const media = await this.syncMedia(fresh, key, notes);
      const payload = {
        objects: fresh.objects,
        relations: fresh.relations,
        tombstones: fresh.tombstones,
        relationTombstones: fresh.relationTombstones,
      };
      const deviceName = this.deviceName();
      const digest = await digestOf({ deviceName, ...payload });
      const existing = files.find((file) => file.name === mine)?.id;
      // Same content as this device's last upload (and the file is still
      // there): nothing to send. Memory only, so every start pushes once.
      const pushed = !existing || digest !== this.pushedDigest;
      if (pushed) {
        const sealed = await seal(key, { v: SNAPSHOT_VERSION, deviceId: fresh.deviceId, deviceName, writtenAt: Date.now(), ...payload });
        await this.google.upload(mine, sealed, existing);
        this.pushedDigest = digest;
        this.context.storage.set("lastPush", Date.now());
      }

      this.context.storage.set("lastSync", Date.now());
      const detail = [
        `${pulled} change(s) in`,
        conflicts ? `${conflicts} edited on both devices` : null,
        pushed ? `${fresh.objects.length} object(s) out` : "nothing new to send",
        media.pulled ? `${media.pulled} image(s) in` : null,
        media.pushed ? `${media.pushed} image(s) out` : null,
        skipped ? `${skipped} held back (note is open)` : null,
      ].filter(Boolean).join(", ");
      this.setStatus("ok", `${detail}.${notes.length ? ` ${notes.join(" ")}` : ""}`);
      return { pulled, skipped, notes, media, pushed, conflicts };
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
.nsync-devices { display: grid; gap: 6px; margin-top: 12px; }
.nsync-device-name { max-width: 260px; }
.nsync-peers { margin: 0; padding-left: 18px; font-size: 12px; }
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
  // This device's name and every other device's last upload -- the answer
  // to "did the other machine actually send it?", which the status line alone
  // could not give. Lives outside render() like `status`, repainted with it.
  const devices = element("div", { className: "nsync-devices" });
  const nameInput = element("input", {
    className: "nsync-device-name",
    type: "text",
    maxLength: 80,
    placeholder: "e.g. Work laptop",
    value: sync.deviceName(),
  });
  nameInput.onchange = () => { sync.context.storage.set("deviceName", nameInput.value.trim()); };
  const peerList = element("ul", { className: "nsync-peers" });
  devices.append(
    element("label", { className: "nsync-hint", textContent: "This device is called" }),
    nameInput,
    element("p", { className: "nsync-hint", textContent: "Other devices — when each last sent its changes:" }),
    peerList,
  );
  const paintPeers = () => {
    const peers = Object.entries(sync.context.storage.get("peers") ?? {});
    peerList.replaceChildren(...(peers.length
      ? peers
        .sort((a, b) => (b[1].writtenAt ?? 0) - (a[1].writtenAt ?? 0))
        .map(([id, peer]) => element("li", {
          textContent: `${peer.name || `Unnamed device (${id.slice(0, 6)})`}: ${peer.writtenAt ? new Date(peer.writtenAt).toLocaleString() : "unknown (older plugin version)"}`,
        }))
      : [element("li", { className: "nsync-hint", textContent: "None seen yet." })]));
  };

  const paint = ({ state, text }) => {
    paintPeers();
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
        devices,
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
    const toggle = element("input", { id: "nsync-auto-toggle", type: "checkbox", checked: sync.context.storage.get("auto") ?? true });
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
        element("label", { className: "nsync-schedule__label", htmlFor: "nsync-auto-toggle", textContent: "Synchronise automatically, and at least every" }),
        every,
        element("span", { className: "nsync-schedule__suffix", textContent: "minutes" }),
      ]),
      element("p", { className: "nsync-hint", textContent: "On by default: also runs when Notible starts and about a minute after you change something. Each run contacts Google." }),
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
    version: "0.4.4",
    apiVersion: "1.7",
    description: "Replicate this workspace between your own machines through your own Google Drive. Snapshots are encrypted on this device before upload, so neither Notible nor Google can read them. Nothing is merged and nothing is deleted behind your back.",
    author: "Notible",
    permissions: ["data.sync", "data.read", "workspace.ui", "network"],
  },

  onload(context) {
    const sync = new Sync(context);
    this._sync = sync;
    this._disposables = [];

    // Only the note editor needs its open object held back. A table reloads
    // itself when sync rewrites it (Tables 0.6.8), and with no "closed" event
    // in Core a held-back table never synced at all.
    this._disposables.push(context.events.on("object.opened", (payload) => {
      sync.openObjectId = payload?.type === "table" ? null : payload?.id ?? null;
    }));

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
      if (!(context.storage.get("auto") ?? true)) return;
      const minutes = Math.max(1, context.storage.get("intervalMinutes") ?? DEFAULT_INTERVAL_MINUTES);
      this._timer = setInterval(() => { sync.run().catch(() => {}); }, minutes * 60_000);
    };
    sync.onScheduleChanged = reschedule;
    reschedule();

    // The timer alone left a machine's edits on that machine until the next
    // tick, or forever with the timer off (the old default): a column added
    // at work never reached Drive. So also: once shortly after start, and a
    // minute after the last local change. Only when set up -- an automatic run
    // that can only fail would just paint the status red.
    const autoRun = () => {
      if (!(context.storage.get("auto") ?? true) || !(sync.google.signedIn() && Boolean(context.storage.get("key")))) return;
      sync.run().catch(() => {});
    };
    this._startTimer = setTimeout(autoRun, 10_000);
    this._disposables.push(context.events.on("workspace.changed", () => {
      // Our own apply announces workspace.changed too; that is not a local edit.
      if (sync.applying) return;
      clearTimeout(this._changeTimer);
      this._changeTimer = setTimeout(autoRun, 60_000);
    }));
  },

  onunload() {
    clearInterval(this._timer);
    clearTimeout(this._startTimer);
    clearTimeout(this._changeTimer);
    this._timer = null;
    for (const disposable of this._disposables ?? []) disposable.dispose?.();
    this._disposables = [];
    this._sync = null;
  },
};
