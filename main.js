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
  return { deviceId: snapshot.deviceId, deviceName, writtenAt, objects, relations, tombstones, relationTombstones, rejected, conflicts: readConflictDescriptors({ objects, conflicts: snapshot.conflicts }) };
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

// <sync-merge>
// SYNC-MERGE-A (Hive #5): conflict handling shared by Notible Sync and Sync
// Simple. This file is the source; `node scripts/sync-merge-inline.mjs`
// copies it into both main.js files between the sync-merge markers, and both
// self-checks fail when a copy drifts. Pure: no imports, no outside names.

/** Same as LIMITS.title in main.js; a conflict copy's title is cut to it. */
export const MERGE_TITLE_LIMIT = 4_000;
// SYNC-NO-LOSS (Hive #14, F9): the receiver's validateSnapshot caps titles in
// UTF-16 units, so copy titles are cut in units too, never inside a surrogate pair.
const cutUnits = (text, max) => {
  const out = text.slice(0, Math.max(0, max));
  return /[\uD800-\uDBFF]$/.test(out) ? out.slice(0, -1) : out;
};
const copyTitle = (title, suffix) => cutUnits(title || "Untitled", MERGE_TITLE_LIMIT - suffix.length) + suffix;

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
  // SYNC-NO-LOSS (Hive #14, F6): a structure this merge cannot read (rows or
  // columns not a list, an item without a string id, a duplicate id, cells
  // not an object) is a bail, never "every row deleted".
  const readable = (value, field) => {
    const list = value[field];
    if (list === undefined) return true;
    if (!Array.isArray(list)) return false;
    const ids = new Set();
    for (const item of list) {
      if (!item || typeof item !== "object" || typeof item.id !== "string" || !item.id || ids.has(item.id)) return false;
      if (field === "rows" && item.cells !== undefined && (!item.cells || typeof item.cells !== "object" || Array.isArray(item.cells))) return false;
      ids.add(item.id);
    }
    return true;
  };
  const parse = (text) => {
    try {
      const value = JSON.parse(text || "{}");
      return value && typeof value === "object" && !Array.isArray(value) && readable(value, "columns") && readable(value, "rows") ? value : null;
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
    // Value-equal but maybe spelled differently ("" / null / missing, key order):
    // pick by localNewer, which flips under a L/R swap, so both devices write the same bytes.
    if (key(l) === key(r)) return localNewer ? l : r;
    if (key(l) === key(b)) return r;
    if (key(r) === key(b)) return l;
    if (isCell) {
      conflicts += 1;
      if (!localNewer) localLost = true;
    }
    return localNewer ? l : r;
  };
  const byId = (list) => new Map((list ?? []).map((item) => [item.id, item]));
  const sorted = (object) => Object.fromEntries(Object.keys(object).sort().map((k) => [k, object[k]]));
  // SYNC-NO-LOSS (Hive #14, F5): a column deleted on one side stays when the
  // other side edited a cell under it (an edit beats a delete). The deleting
  // side's cells in that column then read as the base, so they don't clash.
  const [bCols, lCols, rCols, bRows] = [base.columns, mine.columns, theirs.columns, base.rows].map(byId);
  const cellEdited = (rows, col) => [...byId(rows).values()]
    .some((row) => cellKey(row.cells?.[col]) !== cellKey(bRows.get(row.id)?.cells?.[col]));
  const keepColumn = (id) => (lCols.has(id) ? cellEdited(mine.rows, id) : cellEdited(theirs.rows, id));
  const deleter = (id) => (!bCols.has(id) ? null : !lCols.has(id) ? "l" : !rCols.has(id) ? "r" : null);

  const mergeList = (field, mergeItem, itemKey, keep = () => false) => {
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
      if (!bi || itemKey(bi) !== itemKey(present) || keep(id)) out.push(present);
    }
    return out;
  };

  const columns = mergeList("columns", (b, l, r) => sorted(pick(b, l, r, valueKey, false)), valueKey, keepColumn);
  const kept = new Set(columns.map((c) => c.id));
  const merged = {
    columns,
    rows: mergeList("rows", (b, l, r) => {
      const cells = {};
      const ids = new Set([...Object.keys(l.cells ?? {}), ...Object.keys(r.cells ?? {})]);
      for (const id of [...ids].sort()) {
        const gone = kept.has(id) ? deleter(id) : null;
        const lv = gone === "l" ? b?.cells?.[id] : l.cells?.[id];
        const rv = gone === "r" ? b?.cells?.[id] : r.cells?.[id];
        const value = pick(b?.cells?.[id], lv, rv, cellKey, true);
        // Empty spellings ("", null, false, missing) are one value: omit, so the bytes never depend on the side.
        if (!isEmptyCell(value)) cells[id] = value;
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

// E14B-SYNC-FENCE (Hive #2): a table embedded in a note (```notible-table,
// one JSON line per row) merges cell by cell like a standalone one, as long
// as the text around it is the same on both devices.
// ponytail: fences matched by position; adding, removing or reordering whole
// blocks, or editing the text around them, falls back to a conflict copy (Hive #5).
const FENCE_MARK = "\u0000fence";
function splitFences(content) {
  let lines;
  try {
    const doc = JSON.parse(content);
    if (!doc || !Array.isArray(doc.content)) return null;
    // Only Core's own flat shape (documentFromText): one plain paragraph per
    // line. Anything richer (marks, headings) would not survive the rebuild.
    lines = doc.content.map((node) => {
      if (!node || node.type !== "paragraph") throw new Error("not flat");
      const parts = node.content ?? [];
      if (parts.length > 1 || parts.some((part) => part.type !== "text" || part.marks)) throw new Error("not flat");
      return parts[0]?.text ?? "";
    });
  } catch { return null; }
  const outside = [];
  const fences = [];
  let current = null;
  for (const line of lines) {
    if (current) {
      if (line.trim() === "```") { fences.push(current); outside.push(FENCE_MARK); current = null; } else current.push(line);
    } else if (line.trim() === "```notible-table") current = [];
    else outside.push(line);
  }
  return current ? null : { outside: outside.join("\n"), fences };
}
function fenceToProps(body) {
  const [head, ...rows] = body.filter((line) => line.trim()).map((line) => JSON.parse(line));
  if (!head || head.v !== 1) throw new Error("unknown table version");
  const { v, ...rest } = head;
  return JSON.stringify({ ...rest, rows });
}
function propsToFence(props) {
  const { rows = [], ...rest } = JSON.parse(props);
  return [JSON.stringify({ v: 1, ...rest }), ...rows.map((row) => JSON.stringify(row))];
}
export function mergeEmbeddedTables(baseContent, localContent, remoteContent, localNewer) {
  const [base, local, remote] = [baseContent, localContent, remoteContent].map(splitFences);
  if (!base || !local || !remote || base.outside !== local.outside || local.outside !== remote.outside) return null;
  if (!local.fences.length || base.fences.length !== local.fences.length || local.fences.length !== remote.fences.length) return null;
  let conflicts = 0;
  let localLost = false;
  const merged = [];
  try {
    for (let i = 0; i < local.fences.length; i++) {
      const result = mergeTableProps(fenceToProps(base.fences[i]), fenceToProps(local.fences[i]), fenceToProps(remote.fences[i]), localNewer);
      if (!result) return null;
      conflicts += result.conflicts;
      localLost ||= result.localLost;
      merged.push(propsToFence(result.props));
    }
  } catch { return null; }
  const out = [];
  let index = 0;
  for (const line of local.outside.split("\n")) out.push(...(line === FENCE_MARK ? ["```notible-table", ...merged[index++], "```"] : [line]));
  const paragraphs = out.map((text) => (text ? { type: "paragraph", content: [{ type: "text", text }] } : { type: "paragraph" }));
  return { content: JSON.stringify({ type: "doc", content: paragraphs }), conflicts, localLost };
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
  const events = []; // SYNC-NOTICE (Hive #11): where this device's change did not win
  let conflicts = 0;
  const copyOf = (local, trashedAt = local.trashed_at) => ({
    ...local,
    id: crypto.randomUUID(),
    trashed_at: trashedAt,
    title: copyTitle(local.title, ` (conflict copy — ${copyLabel})`),
    created_at: now,
    updated_at: now,
  });

  for (const remote of remoteObjects) {
    const local = localById.get(remote.id);
    const base = bases[remote.id];
    const remoteHash = objectHash(remote);
    const localHash = local ? objectHash(local) : null;
    // SYNC-ABA (Hive #12): remote == base only means "nothing to take" when
    // newest-wins keeps our row. A newer peer row with the base text (a revert,
    // or a re-stamp) would land over our edit, so it is a conflict: the peer's
    // row wins, ours is kept as a copy. A restored database looks the same
    // (case 15) and gets a copy of the restored text too; stamps cannot tell
    // the two apart (fuzz reset seeds 3984, 7231), and a copy loses nothing.
    const remoteUnchanged = remoteHash === base && remote.updated_at <= local?.updated_at;
    // SYNC-NO-LOSS (Hive #14, F3): no base (first exchange, lost bases, a new
    // peer) is unknown history, not "only the peer changed": two rows that
    // differ are a conflict, so the older one is kept as a copy.
    if (!local || remoteHash === localHash || localHash === base || remoteUnchanged) {
      objects.push(remote);
      continue;
    }
    conflicts += 1;
    const localNewer = local.updated_at !== remote.updated_at ? local.updated_at > remote.updated_at : localHash > remoteHash;
    // Strictly newer than both, so Core's newest-wins takes it on every device.
    const stamp = Math.max(local.updated_at, remote.updated_at) + 1;
    const title = remote.title || local.title || "Untitled";

    // A stale base must not turn a trash-only change into a duplicate.
    if (objectHash({ ...local, trashed_at: null }) === objectHash({ ...remote, trashed_at: null })) {
      if (!localNewer) objects.push(remote.updated_at > local.updated_at ? remote : { ...remote, updated_at: stamp });
      if (!localNewer && local.trashed_at != null && remote.trashed_at == null) events.push({ kind: "restored", id: remote.id, title });
      notes.push('Trash state resolved using the newer version.');
      continue;
    }

    const merged = local.trashed_at == null && remote.trashed_at == null && remote.type === "table" && local.type === "table" && typeof tableBases[remote.id] === "string"
      ? mergeTableProps(tableBases[remote.id], local.props, remote.props, localNewer)
      : null;
    if (merged) {
      objects.push({ ...(localNewer ? local : remote), props: merged.props, updated_at: stamp });
      if (merged.localLost) {
        const copy = copyOf(local);
        objects.push(copy);
        events.push({ kind: "copy", id: remote.id, title, copy: copy.title, copyId: copy.id, mine: true });
      }
      notes.push(merged.conflicts
        ? `"${title}": merged edits from both devices; ${merged.conflicts} cell(s) changed on both, newer kept${merged.localLost ? ", this device's version saved as a conflict copy" : ""}.`
        : `"${title}": merged edits from both devices.`);
      continue;
    }

    // E14B-SYNC-FENCE (Hive #2): a note whose only difference is cells of
    // its embedded tables merges like a table instead of becoming a copy.
    const embedded = local.trashed_at == null && remote.trashed_at == null && local.type !== "table" && remote.type === local.type
      && local.title === remote.title && local.props === remote.props && typeof tableBases[remote.id] === "string"
      ? mergeEmbeddedTables(tableBases[remote.id], local.content, remote.content, localNewer)
      : null;
    if (embedded) {
      objects.push({ ...(localNewer ? local : remote), content: embedded.content, updated_at: stamp });
      if (embedded.localLost) {
        const copy = copyOf(local);
        objects.push(copy);
        events.push({ kind: "copy", id: remote.id, title, copy: copy.title, copyId: copy.id, mine: true });
      }
      notes.push(embedded.conflicts
        ? `"${title}": merged table edits from both devices; ${embedded.conflicts} cell(s) changed on both, newer kept${embedded.localLost ? ", this device's version saved as a conflict copy" : ""}.`
        : `"${title}": merged table edits from both devices.`);
      continue;
    }

    if (localNewer) {
      // Core keeps ours by itself. The other device copies its own version
      // when it reads this one.
      notes.push(`"${title}": edited on both devices; this device's newer version kept.`);
      continue;
    }
    objects.push(remote.updated_at > local.updated_at ? remote : { ...remote, updated_at: stamp });
    // SYNC-NO-LOSS (Hive #14, F4): a trashed version is copied too when it
    // holds its own edit (trash is recoverable storage); the copy stays in the
    // trash. Only a version that differs from the base by the trash alone
    // has nothing to keep.
    const trashedEdit = local.trashed_at != null && objectHash({ ...local, trashed_at: null }) !== base;
    const savedCopy = local.trashed_at == null || trashedEdit;
    if (savedCopy) {
      const copy = copyOf(local, trashedEdit ? local.trashed_at : remote.trashed_at ?? null);
      objects.push(copy);
      events.push({ kind: "copy", id: remote.id, title, copy: copy.title, copyId: copy.id, mine: true });
    } else if (remote.trashed_at == null) events.push({ kind: "restored", id: remote.id, title });
    notes.push(`"${title}": edited on both devices; the other device's newer version kept, ${savedCopy ? (trashedEdit || remote.trashed_at != null ? "this device's saved as a conflict copy in trash" : "this device's saved as a conflict copy") : "this device's trashed version not copied"}.`);
  }
  return { objects, notes, events, conflicts };
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
    } else if (typeof object.content === "string" && object.content.includes("```notible-table") && object.content.length <= budget) {
      // E14B-SYNC-FENCE (Hive #2): a note's embedded tables need its last content as the base.
      tables[object.id] = object.content;
      budget -= object.content.length;
    }
  }
  return { bases, tables };
}


// ---------------------------------------------------------------- body diff3
// SYNC-MERGE-A (Hive #5): line-level three-way merge of Core's flat note
// bodies (one plain paragraph per line, coreDocument.ts documentFromText).

const MAX_UNITS = 20_000;
const MAX_D = 2_000;

/** Lines of a flat body, or null for any richer shape (then: legacy path). */
export function flatLines(content) {
  if (content === "" || content === "{}") return [];
  let doc;
  try { doc = JSON.parse(content); } catch { return null; }
  if (!doc || typeof doc !== "object" || doc.type !== "doc" || !Array.isArray(doc.content) || Object.keys(doc).length !== 2) return null;
  const lines = [];
  for (const p of doc.content) {
    if (!p || p.type !== "paragraph") return null;
    const keys = Object.keys(p);
    if (keys.length === 1) { lines.push(""); continue; }
    if (keys.length !== 2 || !Array.isArray(p.content) || p.content.length !== 1) return null;
    const t = p.content[0];
    if (!t || t.type !== "text" || Object.keys(t).length !== 2 || typeof t.text !== "string" || !t.text || t.text.includes("\n")) return null;
    lines.push(t.text);
  }
  // Core writes "" as one empty paragraph; both mean "no lines" (linesToContent writes it back).
  return lines.length === 1 && lines[0] === "" ? [] : lines;
}

/** Exactly documentFromText(lines.join("\n")), so every device writes the same bytes. */
export function linesToContent(lines) {
  const list = lines.length ? lines : [""];
  return JSON.stringify({ type: "doc", content: list.map((text) => (text ? { type: "paragraph", content: [{ type: "text", text }] } : { type: "paragraph" })) });
}

/** One unit per line; a fenced block (``` ... ```) is one unit. Unclosed: null. */
export function toUnits(lines) {
  const units = [];
  let fence = null;
  for (const line of lines) {
    if (fence) {
      fence.push(line);
      if (line.trim() === "```") { units.push(fence.join("\n")); fence = null; }
    } else if (line.trim().startsWith("```")) fence = [line];
    else units.push(line);
  }
  return fence ? null : units;
}

/** Myers O(ND): hunks {s, e, ins} turning a into b, or null over budget. */
export function diffUnits(a, b) {
  if (a.length > MAX_UNITS || b.length > MAX_UNITS) return null;
  let p = 0;
  while (p < a.length && p < b.length && a[p] === b[p]) p++;
  let q = 0;
  while (q < a.length - p && q < b.length - p && a[a.length - 1 - q] === b[b.length - 1 - q]) q++;
  const A = a.slice(p, a.length - q);
  const B = b.slice(p, b.length - q);
  const n = A.length;
  const m = B.length;
  if (!n || !m) return n || m ? [{ s: p, e: p + n, ins: B }] : [];
  const max = Math.min(n + m, MAX_D);
  const off = max + 1;
  const v = new Int32Array(2 * off + 1);
  // ponytail: one -d..d slice per step, O(D^2) ints (~16 MB at MAX_D);
  // a Hirschberg split if that ever matters.
  const trace = [];
  let found = -1;
  for (let d = 0; d <= max && found < 0; d++) {
    trace.push(v.slice(off - d, off + d + 1));
    for (let k = -d; k <= d; k += 2) {
      let x = k === -d || (k !== d && v[off + k - 1] < v[off + k + 1]) ? v[off + k + 1] : v[off + k - 1] + 1;
      let y = x - k;
      while (x < n && y < m && A[x] === B[y]) { x++; y++; }
      v[off + k] = x;
      if (x >= n && y >= m) { found = d; break; }
    }
  }
  if (found < 0) return null;
  const at = (d, k) => trace[d][k + d];
  const ops = [];
  let x = n;
  let y = m;
  for (let d = found; d > 0; d--) {
    const k = x - y;
    const down = k === -d || (k !== d && at(d, k - 1) < at(d, k + 1));
    const pk = down ? k + 1 : k - 1;
    const px = at(d, pk);
    const py = px - pk;
    ops.push(down ? { x: px, ins: B[py] } : { x: px, del: true });
    x = px;
    y = py;
  }
  ops.reverse();
  const hunks = [];
  for (const op of ops) {
    let h = hunks[hunks.length - 1];
    if (!h || op.x !== h.e) { h = { s: op.x, e: op.x, ins: [] }; hunks.push(h); }
    if (op.del) h.e++; else h.ins.push(op.ins);
  }
  return hunks.map((h) => ({ s: h.s + p, e: h.e + p, ins: h.ins }));
}

export function applyHunks(a, hunks) {
  const out = [];
  let c = 0;
  for (const h of hunks) { out.push(...a.slice(c, h.s), ...h.ins); c = h.e; }
  return [...out, ...a.slice(c)];
}

const sameUnits = (x, y) => x.length === y.length && x.every((u, i) => u === y[i]);
/** big holds small in order, with only insertions around it. */
const containsUnits = (big, small) => {
  let i = 0;
  for (const u of big) if (i < small.length && u === small[i]) i++;
  return i === small.length;
};
const isTableUnit = (u) => u.split("\n")[0].trim() === "```notible-table";

function mergeTableUnit(b, l, r, localNewer) {
  try {
    const props = [b, l, r].map((u) => fenceToProps(u.split("\n").slice(1, -1)));
    const m = mergeTableProps(props[0], props[1], props[2], localNewer);
    return m && { units: [["```notible-table", ...propsToFence(m.props), "```"].join("\n")], lost: m.conflicts > 0 };
  } catch {
    return null;
  }
}

/** diff3 over units. `lost`: the older side lost an edit (it owes a copy). */
export function mergeLines(base, l, r, localNewer) {
  const hl = diffUnits(base, l);
  const hr = diffUnits(base, r);
  if (!hl || !hr) return null;
  const all = [...hl.map((h) => ({ ...h, side: "L" })), ...hr.map((h) => ({ ...h, side: "R" }))];
  const parent = all.map((_, i) => i);
  const find = (i) => (parent[i] === i ? i : (parent[i] = find(parent[i])));
  // ponytail: O(H^2) over hunks, H <= 2 * MAX_D.
  for (let i = 0; i < hl.length; i++) {
    for (let j = hl.length; j < all.length; j++) {
      const a = all[i];
      const b = all[j];
      const samePoint = a.s === a.e && b.s === b.e && a.s === b.s;
      if (samePoint || (a.s < b.e && b.s < a.e)) parent[find(i)] = find(j);
    }
  }
  const groups = new Map();
  all.forEach((h, i) => {
    const root = find(i);
    const g = groups.get(root) ?? { S: h.s, E: h.e, members: [] };
    g.S = Math.min(g.S, h.s);
    g.E = Math.max(g.E, h.e);
    g.members.push(h);
    groups.set(root, g);
  });
  const ordered = [...groups.values()].sort((a, b) => a.S - b.S || (a.E - a.S) - (b.E - b.S));
  const sideText = (g, side) => {
    const out = [];
    let c = g.S;
    for (const h of g.members.filter((x) => x.side === side)) { out.push(...base.slice(c, h.s), ...h.ins); c = h.e; }
    return [...out, ...base.slice(c, g.E)];
  };
  const resolve = (g) => {
    const L = sideText(g, "L");
    const R = sideText(g, "R");
    const sides = new Set(g.members.map((h) => h.side));
    if (sides.size === 1) return { units: sides.has("L") ? L : R, lost: false };
    if (sameUnits(L, R)) return { units: L, lost: false };
    const newer = localNewer ? L : R;
    const older = localNewer ? R : L;
    // Blank-only difference (checked first so same-spot blank insertions do not stack).
    if (sameUnits(L.filter((u) => u !== ""), R.filter((u) => u !== ""))) return { units: newer, lost: false };
    if (g.S === g.E) {
      let pre = 0;
      while (pre < L.length && pre < R.length && L[pre] === R[pre]) pre++;
      let suf = 0;
      while (suf < L.length - pre && suf < R.length - pre && L[L.length - 1 - suf] === R[R.length - 1 - suf]) suf++;
      return { units: [...L.slice(0, pre), ...newer.slice(pre, newer.length - suf), ...older.slice(pre, older.length - suf), ...L.slice(L.length - suf)], lost: false };
    }
    if (L.length && R.length) {
      if (containsUnits(L, R)) return { units: L, lost: false };
      if (containsUnits(R, L)) return { units: R, lost: false };
    }
    const B = base.slice(g.S, g.E);
    if (B.length === 1 && L.length === 1 && R.length === 1 && isTableUnit(B[0]) && isTableUnit(L[0]) && isTableUnit(R[0])) {
      return mergeTableUnit(B[0], L[0], R[0], localNewer);
    }
    return { units: newer, lost: true };
  };
  const units = [];
  let lost = false;
  let cursor = 0;
  for (const g of ordered) {
    if (g.S < cursor) return null; // ponytail: cannot happen with separate hunks; bail rather than guess
    units.push(...base.slice(cursor, g.S));
    const res = resolve(g);
    if (!res) return null;
    units.push(...res.units);
    lost ||= res.lost;
    cursor = g.E;
  }
  units.push(...base.slice(cursor));
  return { units, lost };
}

// ---------------------------------------------------------------- object merge
// SYNC-MERGE-A (Hive #5). Every tie goes through localNewer, never through
// "which side is local", so mergeObject(b, L, R, x) == mergeObject(b, R, L, !x).

// ------------------------------------------------------- structural JSON merge
// SYNC-STRUCT (Hive #6; spec docs/superpowers/specs/2026-10-06-sync-structural-json-merge.md).
// Boards keep a whole canvas in one prop or one line of content, so the
// key-by-key / line-by-line merge clashed on any two concurrent edits and made
// a conflict copy of the whole board. These merge by item id instead, like
// mergeTableProps; anything unreadable is still a bail (null), never a loss.

const plainObject = (v) => Boolean(v) && typeof v === "object" && !Array.isArray(v);
const sortKeys = (v) => JSON.parse(canon(v));

/** Three-way pick of key `k`: `from` is the side to copy it from (it may lack it = deleted). */
function mergeKey(b, l, r, k, localNewer) {
  const key = (o) => (o !== undefined && Object.hasOwn(o, k) ? valueKey(o[k]) : undefined);
  const [kb, kl, kr] = [key(b), key(l), key(r)];
  if (kl === kr) return { from: localNewer ? l : r, clash: false };
  if (kr === kb) return { from: l, clash: false };
  if (kl === kb) return { from: r, clash: false };
  return { from: localNewer ? l : r, clash: true };
}

/** Objects with unique non-empty string ids (missing = empty list), else null. */
function idItems(list, itemOk = () => true) {
  if (list === undefined) return [];
  if (!Array.isArray(list)) return null;
  const ids = new Set();
  for (const item of list) {
    if (!plainObject(item) || typeof item.id !== "string" || !item.id || ids.has(item.id) || !itemOk(item)) return null;
    ids.add(item.id);
  }
  return list;
}

/**
 * Three-way merge of id-keyed lists. An item added on either side stays; one
 * deleted on a side stays only if the other side changed it (an edit beats a
 * delete). Fields merge one by one; a clash takes the newer side and counts
 * as a lost edit unless the field is in `layout` (or `silent` is set).
 * `fields` holds custom merges for a field changed on both sides. Order: the
 * side that reordered the shared items (the newer one if both did), with the
 * other side's new items placed after the item they followed. Symmetric:
 * (b, l, r, x) and (b, r, l, !x) give the same list.
 */
function mergeIdList(base, mine, theirs, localNewer, { layout = [], silent = false, fields = {}, sorted = false } = {}) {
  const byId = (list) => new Map(list.map((item) => [item.id, item]));
  const [b, l, r] = [base, mine, theirs].map(byId);
  let lost = false;
  const mergeItem = (bi, li, ri) => {
    // Null prototype and own-key lookups (Codex on #6): a field named
    // "__proto__" or "constructor" is an ordinary field here.
    const out = Object.create(null);
    for (const k of [...new Set([...Object.keys(li), ...Object.keys(ri)])].sort()) {
      const { from, clash } = mergeKey(bi, li, ri, k, localNewer);
      if (clash && Object.hasOwn(fields, k)) { out[k] = fields[k](bi?.[k], li[k], ri[k]); continue; }
      if (clash && !silent && !layout.includes(k)) lost = true;
      if (Object.hasOwn(from, k)) out[k] = JSON.parse(valueKey(from[k]));
    }
    return out;
  };
  const kept = new Set();
  for (const id of new Set([...l.keys(), ...r.keys()])) {
    const present = l.get(id) ?? r.get(id);
    if ((l.has(id) && r.has(id)) || !b.has(id) || valueKey(b.get(id)) !== valueKey(present)) kept.add(id);
  }
  const items = new Map([...kept].map((id) => [id, l.has(id) && r.has(id) ? mergeItem(b.get(id), l.get(id), r.get(id)) : sortKeys(l.get(id) ?? r.get(id))]));
  let order;
  if (sorted) order = [...kept].sort();
  else {
    const shared = (list) => list.map((item) => item.id).filter((id) => b.has(id) && l.has(id) && r.has(id)).join("\n");
    const lMoved = shared(mine) !== shared(base);
    const rMoved = shared(theirs) !== shared(base);
    const [first, second] = (lMoved !== rMoved ? lMoved : localNewer) ? [mine, theirs] : [theirs, mine];
    order = first.map((item) => item.id).filter((id) => kept.has(id));
    let at = 0;
    for (const { id } of second) {
      if (!kept.has(id)) continue;
      const i = order.indexOf(id);
      if (i >= 0) at = i + 1;
      else order.splice(at++, 0, id);
    }
  }
  return { list: order.map((id) => items.get(id)), lost };
}

const NODE_LAYOUT = ["x", "y", "width", "height", "color", "shape"];

/** Whiteboard content `{version: 1, nodes, edges, viewport}`; `table` node rows are one value. */
function mergeWhiteboard(bText, lText, rText, localNewer) {
  const parse = (text) => {
    if (!text || !text.trim()) return { version: 1, nodes: [], edges: [] };
    let v;
    try { v = JSON.parse(text); } catch { return null; }
    const edgeOk = (e) => typeof e.from === "string" && typeof e.to === "string";
    return plainObject(v) && v.version === 1 && Array.isArray(v.nodes) && Array.isArray(v.edges) && idItems(v.nodes) && idItems(v.edges, edgeOk) ? v : null;
  };
  const [b, l, r] = [bText, lText, rText].map(parse);
  if (!b || !l || !r) return null;
  const nodes = mergeIdList(b.nodes, l.nodes, r.nodes, localNewer, { layout: NODE_LAYOUT });
  const edges = mergeIdList(b.edges, l.edges, r.edges, localNewer, { sorted: true });
  let lost = nodes.lost || edges.lost;
  const out = Object.create(null);
  for (const k of new Set([...Object.keys(l), ...Object.keys(r)])) {
    if (k === "nodes" || k === "edges") continue;
    const { from, clash } = mergeKey(b, l, r, k, localNewer);
    if (clash && k !== "viewport") lost = true;
    if (Object.hasOwn(from, k)) out[k] = from[k];
  }
  // An edge to a node that is gone (deleted on one side) goes with it.
  const live = new Set(nodes.list.map((n) => n.id));
  out.nodes = nodes.list;
  out.edges = edges.list.filter((e) => live.has(e.from) && live.has(e.to));
  return { v: JSON.stringify(sortKeys(out)), lost };
}

/** Typewriter `tw.board`: card id -> {x, y}. Positions only, so never a lost edit. */
function mergeBoardPositions(b, l, r, localNewer) {
  const list = (v) => {
    if (v === undefined) return [];
    if (!plainObject(v)) return null;
    const out = Object.entries(v).map(([id, at]) => (plainObject(at) && Number.isFinite(at.x) && Number.isFinite(at.y) ? { ...at, id } : null));
    return out.includes(null) || out.some((item) => !item.id) ? null : out;
  };
  const [lb, ll, lr] = [b, l, r].map(list);
  if (!lb || !ll || !lr) return null;
  const m = mergeIdList(lb, ll, lr, localNewer, { silent: true, sorted: true });
  return { value: Object.fromEntries(m.list.map(({ id, ...at }) => [id, at])), lost: false };
}

/** Members added on either side, minus members removed on either side. */
const mergeSet = (b = [], l, r) => {
  const [B, L, R] = [b, l, r].map((list) => new Set(list));
  return [...new Set([...l, ...r])].filter((x) => (L.has(x) && R.has(x)) || !B.has(x)).sort();
};

/**
 * Typewriter `tw.frames`: [{id, title, members}]. A card or frame sits in at
 * most one frame, so a member both sides put in different frames stays in the
 * newer side's; empty frames are dropped (as the board does); a nesting cycle
 * is a bail.
 */
function mergeFrames(b, l, r, localNewer) {
  const frameOk = (f) => Array.isArray(f.members) && f.members.every((m) => typeof m === "string") && (f.title === undefined || typeof f.title === "string");
  const [fb, fl, fr] = [b, l, r].map((v) => idItems(v, frameOk));
  if (!fb || !fl || !fr) return null;
  const m = mergeIdList(fb, fl, fr, localNewer, { fields: { members: mergeSet } });
  const [newer, older] = localNewer ? [fl, fr] : [fr, fl];
  const home = (frames, member) => frames.find((f) => f.members.includes(member))?.id;
  const owners = new Map();
  for (const f of m.list) for (const x of f.members) owners.set(x, [...(owners.get(x) ?? []), f.id]);
  for (const [x, ids] of owners) {
    if (ids.length < 2) continue;
    const keep = [home(newer, x), home(older, x)].find((id) => ids.includes(id)) ?? [...ids].sort()[0];
    for (const f of m.list) if (f.id !== keep) f.members = f.members.filter((y) => y !== x);
  }
  const frames = m.list.filter((f) => f.members.length > 0);
  const inside = new Map(frames.map((f) => [f.id, f.members]));
  const state = new Map(); // 1 = on the path, 2 = done
  const cycle = (id) => {
    if (state.get(id) === 1) return true;
    if (state.get(id) === 2 || !inside.has(id)) return false;
    state.set(id, 1);
    const found = inside.get(id).some(cycle);
    state.set(id, 2);
    return found;
  };
  if (frames.some((f) => cycle(f.id))) return null;
  return { value: frames, lost: m.lost };
}

const idListProp = (opts, itemOk) => (b, l, r, localNewer) => {
  const [ib, il, ir] = [b, l, r].map((v) => idItems(v, itemOk));
  if (!ib || !il || !ir) return null;
  const m = mergeIdList(ib, il, ir, localNewer, opts);
  return { value: m.list, lost: m.lost };
};

/**
 * Hive #24: `tags` (strings) and `deps` ([{on, kind}], one per `on`) merge as
 * sets: an add on either side stays, a removal wins only against an untouched
 * entry. A dependency kind changed on both sides: newer, silently (a
 * scheduling setting, like view settings); any other dep field clash is a
 * copy. Duplicates, junk or an unknown kind are a bail.
 */
function mergeTags(b, l, r, localNewer) {
  const items = (v) => {
    if (v === undefined) return [];
    if (!Array.isArray(v) || v.some((tag) => typeof tag !== "string" || !tag) || new Set(v).size !== v.length) return null;
    return v.map((id) => ({ id }));
  };
  const [ib, il, ir] = [b, l, r].map(items);
  if (!ib || !il || !ir) return null;
  return { value: mergeIdList(ib, il, ir, localNewer, { silent: true }).list.map((item) => item.id), lost: false };
}

// The kinds `depsOf` (ganttCascade.ts) reads; it turns anything else into
// "finish-start", so a malformed kind winning would erase the other edit.
const DEP_KINDS = new Set(["finish-start", "start-start", "finish-finish", "start-finish"]);

function mergeDeps(b, l, r, localNewer) {
  const items = (v) => {
    if (v === undefined) return [];
    if (!Array.isArray(v) || !v.every((dep) => plainObject(dep) && !Object.hasOwn(dep, "id"))) return null;
    // Codex on #24: an omitted kind is the legacy spelling of "finish-start"
    // (as `depsOf` reads it), so it is filled in on every side and never
    // clashes with an explicit one; any other kind is a bail.
    const deps = v.map(({ on, ...rest }) => ({ kind: "finish-start", ...rest, id: on }));
    return deps.every((dep) => DEP_KINDS.has(dep.kind)) ? idItems(deps) : null;
  };
  const [ib, il, ir] = [b, l, r].map(items);
  if (!ib || !il || !ir) return null;
  // Only `kind` clashes are silent (Szymon 06.10); a clash on any other field
  // (a note, an unknown field) keeps the newer value and makes a conflict copy.
  const m = mergeIdList(ib, il, ir, localNewer, { layout: ["kind"] });
  return { value: m.list.map(({ id, ...rest }) => ({ on: id, ...rest })), lost: m.lost };
}

/** Props merged by id when both sides changed them; every other key stays whole-value. */
const STRUCTURED_PROPS = {
  tags: mergeTags,
  deps: mergeDeps,
  "tw.board": mergeBoardPositions,
  "tw.frames": mergeFrames,
  // Each item must pass its reader (readMarkers, viewsFromObject) on every
  // side, or the merge would keep it and the reader drop it (Codex on #6).
  "tw.timeline": idListProp({ layout: ["x", "jump"] }, (m) => Number.isFinite(m.x)),
  // Szymon 06.10: a view setting never costs a project a conflict copy.
  _views: idListProp({ silent: true }, (v) => typeof v.layout === "string"),
};

function mergeContent(type, b, l, r, localNewer) {
  if (l === r || r === b) return { v: l, lost: false };
  if (l === b) return { v: r, lost: false };
  if (type === "whiteboard") return mergeWhiteboard(b, l, r, localNewer);
  const [ub, ul, ur] = [b, l, r].map((c) => { const lines = flatLines(c); return lines && toUnits(lines); });
  if (!ub || !ul || !ur) return null;
  const m = mergeLines(ub, ul, ur, localNewer);
  return m && { v: linesToContent(m.units.flatMap((u) => u.split("\n"))), lost: m.lost };
}

function mergeProps(type, b, l, r, localNewer) {
  if (l === r || r === b) return { v: l, lost: false };
  if (l === b) return { v: r, lost: false };
  if (type === "table") {
    const m = mergeTableProps(b, l, r, localNewer);
    return m && { v: m.props, lost: m.conflicts > 0 };
  }
  const parse = (text) => {
    try { const v = JSON.parse(text || "{}"); return v && typeof v === "object" && !Array.isArray(v) ? v : null; } catch { return null; }
  };
  const [pb, pl, pr] = [b, l, r].map(parse);
  if (!pb || !pl || !pr) return null;
  // Null prototype: a "__proto__" key from a peer stays an ordinary key.
  const out = Object.create(null);
  let lost = false;
  const key3 = (o, k) => (Object.hasOwn(o, k) ? valueKey(o[k]) : undefined);
  for (const k of [...new Set([...Object.keys(pb), ...Object.keys(pl), ...Object.keys(pr)])].sort()) {
    const winner = localNewer ? pl : pr;
    let from;
    if (k === "_automationLog") from = winner;
    else {
      const [kb, kl, kr] = [key3(pb, k), key3(pl, k), key3(pr, k)];
      if (kl === kr || kr === kb) from = pl;
      else if (kl === kb) from = pr;
      else if (Object.hasOwn(STRUCTURED_PROPS, k)) {
        const m = STRUCTURED_PROPS[k](pb[k], pl[k], pr[k], localNewer);
        if (!m) return null;
        lost ||= m.lost;
        out[k] = JSON.parse(valueKey(m.value));
        continue;
      }
      else { from = winner; lost = true; }
    }
    // Canonical value, so both devices write the same bytes.
    if (Object.hasOwn(from, k)) out[k] = JSON.parse(valueKey(from[k]));
  }
  return { v: JSON.stringify(out), lost };
}

export function mergeObject(base, L, R, localNewer) {
  if (base.type !== L.type || L.type !== R.type) return null;
  const newer = localNewer ? L : R;
  const notes = [];
  // SYNC-NOTICE (Hive #11): what the user should hear about; pullPeer adds id and title.
  const events = [];
  const three = (b, l, r) => (l === r || r === b ? { v: l } : l === b ? { v: r } : { v: localNewer ? l : r, clash: true });
  const title = three(base.title, L.title, R.title);
  const parent = three(base.parent_id ?? null, L.parent_id ?? null, R.parent_id ?? null);
  const archived = three(base.archived_at ?? null, L.archived_at ?? null, R.archived_at ?? null);
  const props = mergeProps(L.type, base.props, L.props, R.props, localNewer);
  if (!props) return null;
  const content = mergeContent(L.type, base.content, L.content, R.content, localNewer);
  if (!content) return null;
  const shown = title.v || "Untitled";
  const name = Array.from(shown).length > 80 ? `${Array.from(shown).slice(0, 80).join("")}…` : shown;
  if (parent.clash || archived.clash) {
    notes.push(`"${name}": moved or archived on both devices; the newer placement was kept.`);
    // SYNC-NOTICE fix (Hive #16, F6): an archive clash is not a move.
    if (!localNewer && parent.clash) events.push("moved");
    if (!localNewer && archived.clash) events.push("archived");
  }

  const bt = base.trashed_at ?? null;
  const untrashed = (o) => objectHash({ ...o, trashed_at: null });
  const baseUntrashed = untrashed(base);
  const trashOnly = (o) => bt === null && (o.trashed_at ?? null) !== null && untrashed(o) === baseUntrashed;
  const editedLive = (o) => (o.trashed_at ?? null) === null && untrashed(o) !== baseUntrashed;
  let trashed_at;
  if ((trashOnly(L) && editedLive(R)) || (trashOnly(R) && editedLive(L))) {
    trashed_at = null;
    notes.push(`"${name}" was deleted on one device but edited on another, so it was kept.`);
    events.push(trashOnly(L) ? "restored" : "kept-edit");
  } else if ((L.trashed_at ?? null) !== null && (R.trashed_at ?? null) !== null) trashed_at = Math.max(L.trashed_at, R.trashed_at);
  else trashed_at = three(bt, L.trashed_at ?? null, R.trashed_at ?? null).v;

  if (trashed_at != null && editedLive(L)) events.push("edit-in-trash");
  const lost = Boolean(title.clash) || props.lost || content.lost;
  // Hive #7: only an entirely reviewed body conflict can dispose of its copy.
  const fields = [content.lost && "content", title.clash && "title", props.lost && "props", parent.clash && "parent_id", archived.clash && "archived_at"].filter(Boolean);
  return {
    fields,
    object: {
      ...newer,
      id: L.id,
      title: title.v,
      parent_id: parent.v,
      archived_at: archived.v,
      props: props.v,
      content: content.v,
      trashed_at,
      created_at: Math.min(L.created_at, R.created_at),
      updated_at: Math.max(L.updated_at, R.updated_at) + 1,
    },
    loser: lost ? (localNewer ? "R" : "L") : null,
    notes,
    events,
  };
}

// ---------------------------------------------------------------- lineage
// SYNC-MERGE-A (Hive #5). Entry = [vid, vh, by, at]: a version id, its
// objectHash, the device name that made it ("" unknown) and its updated_at.
// Newest first, at most 8. Spec §3.

export const LINEAGE_MAX = 8;
const VID = /^[0-9a-z]{1,16}$/;
const VH = /^[0-9a-z]{1,11}$/;
const MAX_AT = Date.UTC(2200, 0, 1);

/** Ids that may appear in store keys; any other id takes the legacy path. */
export const storeable = (id) => typeof id === "string" && /^[A-Za-z0-9-]{1,64}$/.test(id);

export function randomVid() {
  return [...crypto.getRandomValues(new Uint8Array(12))].map((b) => (b % 36).toString(36)).join("");
}
export const seedEntry = (vh, salt) => [salt ? "r" + hash53(salt + ":" + vh) : "c" + vh, vh, "", 0];
/**
 * Either kind of seed: "c" + vh (first upgrade) or a salted "r" re-seed.
 * Checks 3/4 restrict only "c" seeds (fix round 4, R3-2); see `found` in pullPeer.
 */
export const isSeed = (e) => e[0] === "c" + e[1] || (e[0][0] === "r" && e[2] === "" && e[3] === 0);
export const isSeedOnly = (l) => l.length === 1 && l[0][0] === "c" + l[0][1] && l[0][2] === "" && l[0][3] === 0;
export const mergeVid = (a, b, vh) => "m" + hash53([a, b].sort().join(":") + ":" + vh);
const byVid = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

/** X's and Y's entries deduped by vid, ordered by min position, vid tie-break. */
export function merged(x, y) {
  const pos = new Map();
  for (const list of [x, y]) {
    list.forEach((e, i) => {
      const p = pos.get(e[0]);
      if (!p) pos.set(e[0], { i, e });
      else if (i < p.i) p.i = i;
    });
  }
  return [...pos.values()].sort((a, b) => a.i - b.i || byVid(a.e[0], b.e[0])).slice(0, LINEAGE_MAX).map((p) => p.e);
}

export const pin = (h, x) => [h, ...x.filter((e) => e[0] !== h[0])].slice(0, LINEAGE_MAX);

/** The shared entry with the smallest max(position); vid tie-break. a's copy. */
export function ancestor(a, b) {
  const inA = new Map();
  a.forEach((e, i) => { if (!inA.has(e[0])) inA.set(e[0], { i, e }); });
  let best = null;
  let bestMax = Infinity;
  b.forEach((e, j) => {
    const hit = inA.get(e[0]);
    if (!hit) return;
    const m = Math.max(hit.i, j);
    if (m < bestMax || (m === bestMax && byVid(e[0], best[0]) < 0)) { best = hit.e; bestMax = m; }
  });
  return best;
}

/** A peer snapshot's lineage, validated. Anything malformed is dropped. */
export function readLineage(snapshot) {
  if (snapshot?.lineageV !== 1) return {};
  const devices = snapshot.devices;
  if (!Array.isArray(devices) || devices.length > 64 || !devices.every((d) => typeof d === "string" && [...d].length <= 80)) return {};
  const lineage = new Map();
  // Ids whose list was present but invalid: pullPeer sends these to the legacy
  // path. SYNC-MERGE-A (Hive #5): not named `rejected`, which validateSnapshot
  // already returns (string[]); spreading both would overwrite it.
  const lineageRejected = new Set();
  const source = snapshot.lineage;
  if (source && typeof source === "object" && !Array.isArray(source)) {
    for (const id of Object.keys(source)) {
      const list = source[id];
      if (!storeable(id)) continue;
      if (!Array.isArray(list) || !list.length || list.length > LINEAGE_MAX) { lineageRejected.add(id); continue; }
      const out = [];
      const seen = new Set();
      let ok = true;
      for (const e of list) {
        const [vid, vh, by, at] = Array.isArray(e) && e.length === 4 ? e : [];
        if (typeof vid !== "string" || !VID.test(vid) || typeof vh !== "string" || !VH.test(vh)
          || !Number.isInteger(by) || by < 0 || by >= devices.length
          || !Number.isSafeInteger(at) || at < 0 || at > MAX_AT) { ok = false; break; }
        if (seen.has(vid)) continue;
        seen.add(vid);
        out.push([vid, vh, devices[by], at]);
      }
      if (ok) lineage.set(id, out);
      else lineageRejected.add(id);
    }
  }
  // SYNC-NOTICE fix (Hive #16, F4): merge receipts, { id -> [[losingVid, kinds, copyVid, mine]] }.
  const receipts = new Map();
  const rs = snapshot.receipts;
  if (rs && typeof rs === "object" && !Array.isArray(rs)) {
    for (const id of Object.keys(rs).slice(0, LIMIT_RECEIPT_IDS)) {
      // SYNC-NOTICE fix round 2 (Hive #16, R2-5): a receipt names an older
      // version (and the copy's source) in this object's own lineage, never its head.
      const l = lineage.get(id);
      if (!l || !Array.isArray(rs[id])) continue;
      const known = (vid) => l.some((e) => e[0] === vid);
      const ok = rs[id].slice(0, RECEIPTS_MAX).filter((x) => validReceipt(x) && x[0] !== l[0][0] && known(x[0]) && (!x[2] || known(x[2])));
      if (ok.length) receipts.set(id, ok);
    }
  }
  return { lineageV: 1, lineage, lineageRejected, receipts };
}

// SYNC-NOTICE fix (Hive #16, F4): a device whose published edit lost in a peer's
// merge only fast-forwards to that merge, so it never runs mergeObject itself.
// The merging device keeps, per object, what the losing version's device would
// have been told; it rides in the snapshot until that vid leaves the lineage.
const RECEIPT_KINDS = new Set(["restored", "kept-edit", "edit-in-trash", "moved", "archived"]);
const RECEIPTS_MAX = 4;
const LIMIT_RECEIPT_IDS = 5_000;
// copyVid (round 2, R2-3): the version the copy was made from, so copyId() finds
// the real copy object; "" when there is no copy. "mine" = the loser's own version.
const validReceipt = (x) => Array.isArray(x) && x.length === 4 && typeof x[0] === "string" && VID.test(x[0])
  && Array.isArray(x[1]) && x[1].length <= RECEIPT_KINDS.size && x[1].every((k) => RECEIPT_KINDS.has(k))
  && typeof x[2] === "string" && (x[2] === "" || (VID.test(x[2]) && x[3] === (x[2] === x[0]))) && typeof x[3] === "boolean"
  && (x[1].length > 0 || x[2] !== "");
/** Receipts still worth keeping: newest first, only for vids still in the lineage. */
const keepReceipts = (l, ...lists) => {
  const seen = new Set();
  return lists.flat().filter((x) => x && l.some((e) => e[0] === x[0]) && !seen.has(x[0]) && seen.add(x[0])).slice(0, RECEIPTS_MAX);
};

export const versionOf = (o, entry) => ({
  vid: entry[0], vh: entry[1], type: o.type, title: o.title, content: o.content, props: o.props,
  parent_id: o.parent_id ?? null, archived_at: o.archived_at ?? null, trashed_at: o.trashed_at ?? null,
});

/** A stored version, or null when missing, unreadable or not what the entry says. */
export async function loadVersion(store, id, entry) {
  try {
    const v = JSON.parse(await store.get(`v:${id}:${entry[0]}`));
    return v && v.vid === entry[0] && v.vh === entry[1] && objectHash(v) === entry[1] ? v : null;
  } catch {
    return null;
  }
}

/** UUID-shaped id that every device derives the same way for one losing version. */
export function copyId(objectId, vid) {
  const hex = [`${objectId}:${vid}`, `${vid}:${objectId}`, `${objectId}|${vid}`]
    .map((s) => parseInt(hash53(s), 36).toString(16).padStart(14, "0")).join("").slice(0, 32).split("");
  hex[12] = "4";
  hex[16] = "89ab"[parseInt(hex[16], 16) & 3];
  const h = hex.join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** The losing version as its own object; every field fixed by (objectId, entry). */
export function conflictCopy(objectId, loser, entry, stamp) {
  const [vid, , by, rawAt] = entry;
  // A bad stamp must not throw or differ between devices: no date, time 0.
  const at = Number.isSafeInteger(rawAt) && rawAt > 0 && rawAt <= MAX_AT ? rawAt : 0;
  const when = at ? `, ${new Date(at).toISOString().slice(0, 16).split("T").join(" ")} UTC` : "";
  const suffix = ` (conflict copy — ${by || "another device"}${when})`;
  const title = copyTitle(loser.title, suffix);
  const time = at || stamp;
  const object = {
    id: copyId(objectId, vid), type: loser.type,
    title,
    content: loser.content, props: loser.props, parent_id: loser.parent_id ?? null,
    archived_at: loser.archived_at ?? null, trashed_at: null, created_at: time, updated_at: time,
  };
  return { object, entry: ["k" + hash53(objectId + vid), objectHash(object), by, at] };
}

// ---------------------------------------------------------------- orchestration
// SYNC-MERGE-A (Hive #5): per-peer pull and the push, shared by both plugins
// so the simulator in sync-merge.check.mjs runs the real code. Spec §3.3-3.5
// (the spec's `planObjects` is `pullPeer` here: it also applies and verifies).

const VERSION_CAP = 4 * 1024 * 1024 - 1024;
const BATCH = 500;
const bytesOf = (s) => new TextEncoder().encode(s).length;
/** Same cap readLineage applies to a peer's `devices`: 80 code points. */
const deviceLabel = (name) => [...String(name ?? "")].slice(0, 80).join("");

async function inBatches(list, fn) {
  for (let i = 0; i < list.length; i += BATCH) await fn(list.slice(i, i + BATCH));
}

export async function resetLineage(store) {
  await store.deletePrefix("lin:");
  await store.deletePrefix("v:");
}

// SYNC-MERGE-A (Hive #5), fix round 3 (N1): a re-seed is salted so it never
// matches a pre-reset vid. Seeding after a reset with "c" + vh would mint, for
// content that went back to an earlier state, the very vid a peer holds deep in
// its lineage, and check 5 would take that seed as the merge base and drop the
// revert. A first upgrade has no marker and keeps "c" + vh, so devices that
// upgrade together still share their seed and merge their first divergence.
// Every path that wipes lineage and later re-seeds must call markReseed.
export async function markReseed(store) {
  await store.setMany([["reseed", randomVid()]]);
}

async function lineageOff(lin) {
  lin.off = true;
  lin.lin.clear();
  lin.pending.clear();
  try { await resetLineage(lin.store); await markReseed(lin.store); } catch { /* the store is what failed */ }
}

/**
 * Persist lineage for `ids`, store `versions` ([id, entry, object]) and drop
 * `purge` ids. Versions go first and a failure there only un-holds them; a
 * lineage write that fails turns lineage off for the session (legacy only).
 * `gc`: also drop versions outside "head + 2 newest held". Pulls pass false
 * and leave that to the push, so a version one peer's merge displaced is
 * still there when the next peer of the same cycle needs it as the ancestor.
 */
async function writeLineage(lin, ids, versions, purge, gc, orphans = []) {
  if (lin.off) return;
  const vEntries = [];
  for (const [id, entry, object] of versions) {
    const text = JSON.stringify(versionOf(object, entry));
    if (bytesOf(text) < VERSION_CAP) vEntries.push([`v:${id}:${entry[0]}`, text, id, entry[0]]);
    else lin.lin.get(id)?.h.delete(entry[0]);
  }
  await inBatches(vEntries, async (batch) => {
    try { await lin.store.setMany(batch.map(([k, v]) => [k, v])); } catch { for (const [, , id, vid] of batch) lin.lin.get(id)?.h.delete(vid); }
  });
  // `orphans`: v: keys the caller just took out of `h` (deleted after the lin: write).
  const drop = [...orphans];
  if (gc) { ids = [...ids, ...lin.pending]; lin.pending.clear(); } else for (const id of ids) lin.pending.add(id);
  for (const id of purge) lin.pending.delete(id);
  for (const id of gc ? new Set(ids) : []) {
    const rec = lin.lin.get(id);
    if (!rec) continue;
    // Keep the head plus the 2 newest other held versions.
    const keep = new Set(rec.l.filter((e, i) => rec.h.has(e[0]) && i === 0).map((e) => e[0]));
    for (const e of rec.l.slice(1)) if (rec.h.has(e[0]) && keep.size < (rec.h.has(rec.l[0][0]) ? 3 : 2)) keep.add(e[0]);
    for (const vid of rec.h) if (!keep.has(vid)) { rec.h.delete(vid); drop.push(`v:${id}:${vid}`); }
  }
  try {
    await inBatches([...new Set(ids)].filter((id) => lin.lin.has(id)), (batch) =>
      lin.store.setMany(batch.map((id) => { const r = lin.lin.get(id); return [`lin:${id}`, JSON.stringify({ l: r.l, h: [...r.h], ...(r.r?.length ? { r: r.r } : {}), ...(r.m ? { m: r.m } : {}) })]; })));
    for (const id of purge) {
      lin.lin.delete(id);
      await lin.store.deleteMany([`lin:${id}`]);
      await lin.store.deletePrefix(`v:${id}:`);
    }
  } catch {
    await lineageOff(lin);
    return;
  }
  try { await inBatches(drop, (batch) => lin.store.deleteMany(batch)); } catch { /* orphans cost space only */ }
}

const parseRecord = (text) => {
  try {
    const r = JSON.parse(text);
    if (!Array.isArray(r?.l) || !r.l.length || !Array.isArray(r.h)) return null;
    const rc = Array.isArray(r.r) ? r.r.filter(validReceipt) : [];
    const own = typeof r.m === "string" && VID.test(r.m) ? { m: r.m } : {};
    return rc.length ? { l: r.l, h: new Set(r.h), r: rc, ...own } : { l: r.l, h: new Set(r.h), ...own };
  } catch { return null; }
};

/** Load lineage once per plugin start; seed it on first use or after a wipe. */
export async function openLineage(store, objects) {
  const lin = { store, lin: new Map(), off: false, pending: new Set() };
  try {
    const keys = await store.keys("lin:");
    const values = keys.length ? await store.getMany(keys) : [];
    keys.forEach((k, i) => { const r = parseRecord(values[i]); if (r) lin.lin.set(k.slice(4), r); });
    if (!keys.length) {
      const versions = [];
      // SYNC-MERGE-A (Hive #5), final review (M1): an existing marker is
      // rotated before seeding and the seed uses the fresh value, so a copied
      // plugin store (same marker on two devices) can never share a salt.
      // SYNC-NO-LOSS (Hive #14, F1): every empty-store seed is salted. Core's
      // own wipe (restore, epoch change) deletes the marker with the rest, so
      // "no marker" cannot tell a first upgrade from a restored workspace, and
      // a "c" seed after a restore can match one deep in a peer's lineage.
      // Cost: a divergence before the first exchange takes the legacy path
      // (a copy) instead of a merge. The marker write stays for older code.
      const salt = randomVid();
      await store.setMany([["reseed", salt]]);
      for (const o of objects) {
        if (!storeable(o.id)) continue;
        const entry = seedEntry(objectHash(o), salt);
        lin.lin.set(o.id, { l: [entry], h: new Set([entry[0]]) });
        versions.push([o.id, entry, o]);
      }
      await writeLineage(lin, [...lin.lin.keys()], versions, [], true);
      // SYNC-MERGE-A (Hive #5), fix round 4 (R3-1): rotate the marker right
      // after every successful seeding, so any later seeding on this store is
      // salted with a never-used salt, whoever wiped lin: (lineageOff after a
      // store failure, a restore that keeps the plugin store, Task 9's resets).
      // lineageOff's own markReseed runs on the store that just failed, so it
      // is only a best-effort backup. A first upgrade has no marker yet and
      // still seeds "c" + vh.
      if (!lin.off) await markReseed(store);
    }
  } catch {
    await lineageOff(lin);
  }
  return lin;
}

/** SYNC-MERGE-A (Hive #5), fix round 1 (M6): same 80-code-point cap as mergeObject's notes. */
function shortTitle(title) {
  const shown = [...(title || "Untitled")];
  return shown.length > 80 ? `${shown.slice(0, 80).join("")}…` : shown.join("");
}

/** Pull one peer: decide per object (§3.3), apply, verify, write lineage, copies. */
export async function pullPeer(lin, io, peer) {
  const { validated, apply, deferredIds, bases, tables } = peer;
  const aware = !lin.off && validated.lineageV === 1;
  const rejected = validated.lineageRejected ?? new Set();
  const remoteLin = (R) => {
    // A list the peer sent but readLineage refused is not "implicitly a seed":
    // treating it as one could skip (check 3) or fast-forward past a real edit.
    if (!aware || !storeable(R.id) || rejected.has(R.id)) return null;
    const l = validated.lineage?.get(R.id) ?? [seedEntry(objectHash(R))];
    return l[0][1] === objectHash(R) ? l : null;
  };
  const legacy = [];
  const planned = []; // {object, vh, lin, held: [entry, object][], copy}
  const lineageOnly = [];
  const notes = [];
  const events = [];
  let merges = 0;
  // SYNC-NOTICE fix (Hive #16, F4): silent, unless the peer merged this
  // device's own published head and lost something of it on the way. A third
  // device that only carried that head is not the one whose edit lost.
  // SYNC-NOTICE fix round 2 (Hive #16, R2-1): "own" is the vid pushLineage minted here (`m`), not a
  // device name, which can be blank, shared or renamed.
  const receiptFor = (R, cur, head) => {
    if (!cur.m || cur.m !== head[0]) return [];
    const rc = validated.receipts?.get(R.id)?.find((x) => x[0] === head[0]);
    if (!rc) return [];
    const name = shortTitle(R.title);
    const said = rc[1].map((kind) => ({ kind, id: R.id, title: name }));
    if (rc[2]) said.push({ kind: "copy", id: R.id, title: name, copyId: copyId(R.id, rc[2]), mine: rc[3] });
    return said;
  };
  // SYNC-NOTICE fix round 2 (Hive #16, R2-3): a receipt's copy is told only if that copy exists here,
  // under its own current title.
  const tell = (said) => {
    for (const e of said ?? []) {
      if (!e.copyId) { events.push(e); continue; }
      const c = io.localById.get(e.copyId);
      if (c) events.push({ kind: "copy", id: e.id, title: e.title, copy: c.title, copyId: e.copyId, mine: e.mine });
    }
  };
  // SYNC-NOTICE fix round 2 (Hive #16, R2-2): a relay keeps the receipts it carries, or the loser that
  // pulls the relay first would never hear of them.
  const incoming = (id) => validated.receipts?.get(id) ?? [];

  for (const R of apply.objects) {
    const L = io.localById.get(R.id);
    const rlin = remoteLin(R);
    const cur = lin.lin.get(R.id);
    if (!rlin || (L && !cur)) { legacy.push(R); continue; }
    const vhR = objectHash(R);
    if (!L) { planned.push({ object: R, vh: vhR, lin: rlin, held: [[rlin[0], R]] }); continue; }       // 1
    const vhL = objectHash(L);
    const llin = cur.l;
    if (vhL === vhR) {                                                                                     // 2
      const h = llin[0][1] === vhL && byVid(llin[0][0], rlin[0][0]) < 0 ? llin[0] : rlin[0];
      // Only when it tells us something: a new head, or R's head unknown here.
      // A pure reorder is skipped: merged() of two lists read a round apart
      // is not a fixpoint (it re-cuts to 8), and two devices re-pushing
      // reordered lineage at each other never settle (§5).
      const write = h[0] !== llin[0][0] || !llin.some((e) => e[0] === rlin[0][0]);
      // SYNC-MERGE-A (Hive #5), fix round 1 (F-B): the adopted head is the
      // ancestor of the next divergence, so it must be held here. R's content
      // equals L's, so R is stored under h's vid.
      const hold = !cur.h.has(h[0]);
      // SYNC-NOTICE fix (Hive #16, F4): the peer's merge may equal this
      // device's text and still have dropped part of it (a copy, a placement).
      // Told the first time this device learns that merge's head.
      const said = llin.some((e) => e[0] === rlin[0][0]) ? [] : receiptFor(R, cur, llin[0]);
      if (write || hold) lineageOnly.push([R.id, write ? pin(h, merged(llin, rlin)) : llin, hold ? [h, R] : null, said]);
      continue;
    }
    // SYNC-MERGE-A (Hive #5), fix round 1 (F-C): a seed vid is "c" + content
    // hash, so a device that re-seeds (reset, restore, late upgrade) with
    // content that went back to an earlier state mints a vid that already
    // sits deep in a peer's lineage. Such a match proves nothing. A "c" seed
    // vid counts as ancestry proof in checks 3 and 4 only at position 0 of the
    // other side's lineage too; anywhere else the object takes the legacy path.
    // Fix round 4 (R3-2): a salted "r" re-seed is NOT restricted. Its salt is
    // used once per store (openLineage rotates the marker after seeding), so
    // the vid is unique and a deep match is real ancestry: treating it as
    // untrusted only sent stale or fast-forwardable R to the lossy legacy path.
    const cSeed = (e) => e[0] === "c" + e[1];
    const found = (list, e) => { const i = list.findIndex((x) => x[0] === e[0]); return i < 0 ? 0 : cSeed(e) && i > 0 ? -1 : 1; };
    const r3 = found(llin, rlin[0]);
    if (r3 < 0) { legacy.push(R); continue; }
    if (r3) continue;                                                                                      // 3
    const clean = vhL === llin[0][1];
    const r4 = clean ? found(rlin, llin[0]) : 0;
    if (r4 < 0) { legacy.push(R); continue; }
    if (r4) {                                                                                              // 4
      const object = R.updated_at > L.updated_at ? R : { ...R, updated_at: L.updated_at + 1 };
      planned.push({ object, vh: vhR, lin: pin(rlin[0], merged(rlin, llin)), held: [[rlin[0], R]], said: receiptFor(R, cur, llin[0]) });
      continue;
    }
    const top = clean ? null : [randomVid(), vhL, deviceLabel(io.deviceName), L.updated_at];               // 5
    const lfull = top ? [top, ...llin].slice(0, LINEAGE_MAX) : llin;
    const anc = ancestor(lfull, rlin);
    const base = anc && cur.h.has(anc[0]) ? await loadVersion(lin.store, R.id, anc) : null;
    const localNewer = L.updated_at !== R.updated_at ? L.updated_at > R.updated_at : vhL > vhR;
    const m = base && mergeObject(base, L, R, localNewer);
    if (!m) { legacy.push(R); continue; }
    const vhM = objectHash(m.object);
    const entry = [mergeVid(lfull[0][0], rlin[0][0], vhM), vhM, (localNewer ? lfull[0] : rlin[0])[2], m.object.updated_at];
    // R is held too: it arrived in full, and R's head is the likely ancestor
    // of the next divergence with that peer (case 18). Without it that
    // divergence takes the legacy path and makes a needless copy.
    const held = [[entry, m.object], [rlin[0], R]];
    if (top) held.push([top, L]);
    const copy = m.loser
      ? conflictCopy(R.id, m.loser === "L" ? L : R, m.loser === "L" ? lfull[0] : rlin[0], entry[3])
      : null;
    const name = shortTitle(m.object.title);
    // SYNC-NOTICE fix (Hive #16, F4): what R's device is told when it fast-forwards here.
    const theirs = mergeObject(base, R, L, !localNewer)?.events ?? [];
    const receipt = theirs.length || copy ? [rlin[0][0], theirs, copy ? (m.loser === "R" ? rlin[0] : lfull[0])[0] : "", m.loser === "R"] : null;
    // SYNC-NOTICE (Hive #11): told only once Core took the merge (a retry merges again).
    const said = m.events.map((kind) => ({ kind, id: R.id, title: name }));
    // SYNC-NOTICE fix (Hive #16, F3): the copy is told when Core took the copy
    // itself, which can happen on a cycle whose merged row goes to retry.
    if (copy) copy.descriptor = { originalId: R.id, copyId: copy.object.id, fields: m.fields };
    if (copy) copy.said = { kind: "copy", id: R.id, title: name, copy: copy.object.title, copyId: copy.object.id, mine: m.loser === "L" };
    planned.push({ object: m.object, vh: vhM, lin: [entry, ...merged(lfull, rlin)].slice(0, LINEAGE_MAX), held, copy, said, receipt });
    notes.push(...m.notes, `"${name}": edits from both devices merged${copy ? "; one clash kept as a conflict copy" : ""}.`);
    merges++;
  }

  const legacyPlan = planConflicts(legacy, io.localById, bases, tables, io.copyLabel);
  notes.push(...legacyPlan.notes);
  events.push(...legacyPlan.events);
  // SYNC-MERGE-A (Hive #5), fix round 1 (F-D/F-E): conflict copies ride in
  // the same apply as the merged rows. A second apply after the lineage write
  // could fail or be cut off, and the lineage would already say "merged", so
  // the copy would never be made again. copyId is fixed per (object, losing
  // vid), so making the same copy again on a retry is an idempotent upsert.
  const copies = planned.filter((p) => p.copy).map((p) => p.copy);
  const objects = [...planned.map((p) => p.object), ...copies.map((c) => c.object), ...legacyPlan.objects];
  // Hive #7: descriptors ride in the same Core transaction as their copies.
  const conflicts = copies.map(c => c.descriptor);
  for (const event of legacyPlan.events.filter(e => e.kind === "copy" && e.copyId)) {
    const loser = io.localById.get(event.id);
    const winner = legacyPlan.objects.find(o => o.id === event.id) ?? loser;
    if (loser && winner) {
      const fields = ["content", "title", "props", "parent_id", "type", "archived_at", "trashed_at"].filter(f => loser[f] !== winner[f]);
      conflicts.push({ originalId:event.id, copyId:event.copyId, fields:fields.length ? fields : ["content", "props"] });
    }
  }
  const incomingConflicts = readConflictDescriptors(apply);
  for (const descriptor of incomingConflicts) {
    conflicts.push(descriptor);
    // An unchanged copy still needs registering after an upgrade/relay.
    if (!objects.some(o => o.id === descriptor.copyId)) {
      const copy = io.localById.get(descriptor.copyId) ?? apply.objects.find(o => o.id === descriptor.copyId);
      if (copy) objects.push(copy);
    }
  }
  const before = new Map(objects.map((o) => [o.id, io.localById.get(o.id)]));
  // SYNC-NO-LOSS (Hive #14, F2): every decision above was made against
  // `localById`, an export taken before this apply. Core refuses (inside its
  // apply transaction) any row whose updated_at moved since -- the user saved
  // in between -- and that row is retried next cycle against the new text.
  const expected = Object.fromEntries(objects.map((o) => [o.id, before.get(o.id)?.updated_at ?? null]));
  const result = await io.apply({ objects, conflicts, relations: apply.relations, tombstones: apply.tombstones, relation_tombstones: apply.relationTombstones, expected });
  const stale = new Set(result.staleObjects ?? []);

  // Verify: Core's newest-wins may have kept a newer local row.
  const touched = new Set([...objects.map((o) => o.id), ...apply.tombstones.map((t) => t.object_id)]);
  const changed = objects.some((o) => { const l = before.get(o.id); return !l || objectHash(l) !== objectHash(o); }) || apply.tombstones.length;
  const after = changed ? await io.exportById(touched) : new Map(objects.map((o) => [o.id, io.localById.get(o.id) ?? o]));
  for (const id of touched) { const got = after.get(id); if (got) io.localById.set(id, got); else io.localById.delete(id); }

  const retryIds = new Set(stale);
  const ids = [];
  const versions = [];
  const purge = [...touched].filter((id) => !after.has(id) && lin.lin.has(id));
  // SYNC-MERGE-A (Hive #5), fix round 1 (F-A): versions that leave `h` here
  // are deleted, or nothing (not even the push's GC) would ever reach them.
  const orphans = [];
  const unhold = (id, prev, h) => { for (const vid of prev?.h ?? []) if (!h.has(vid)) orphans.push(`v:${id}:${vid}`); };
  for (const c of copies) {
    // Kept even when the merged row below goes to retry (F-E): the user may
    // have typed over the merge, and the retry merges that, not the loser.
    const got = after.get(c.object.id);
    // SYNC-NOTICE fix round 2 (Hive #16, R2-3): whether the copy exists, for the receipt below.
    c.ok = Boolean(got) && (lin.lin.has(c.object.id) || objectHash(got) === c.entry[1]);
    if (!got || objectHash(got) !== c.entry[1] || lin.lin.has(c.object.id)) continue;
    lin.lin.set(c.object.id, { l: [c.entry], h: new Set([c.entry[0]]) });
    ids.push(c.object.id);
    versions.push([c.object.id, c.entry, c.object]);
    events.push(c.said); // once: a copy already in the lineage was told when it was made
  }
  for (const p of planned) {
    const got = after.get(p.object.id);
    if (!got) continue;                                           // dropped on purpose
    if (objectHash(got) !== p.vh) { retryIds.add(p.object.id); continue; } // lost to a newer local edit
    tell(p.said);
    const prev = lin.lin.get(p.object.id);
    const h = new Set([...(prev?.h ?? [])].filter((vid) => p.lin.some((e) => e[0] === vid)));
    for (const [e] of p.held) h.add(e[0]);
    unhold(p.object.id, prev, h);
    const receipt = p.receipt && p.copy && !p.copy.ok ? (p.receipt[1].length ? [p.receipt[0], p.receipt[1], "", false] : null) : p.receipt;
    const r = keepReceipts(p.lin, [receipt], incoming(p.object.id), prev?.r ?? []);
    lin.lin.set(p.object.id, r.length ? { l: p.lin, h, r } : { l: p.lin, h });
    ids.push(p.object.id);
    for (const [e, o] of p.held) versions.push([p.object.id, e, o]);
  }
  if (!lin.off) {
    for (const [id, next, hold, said] of lineageOnly) {
      tell(said);
      const rec = lin.lin.get(id);
      rec.l = next;
      const r = keepReceipts(next, rec.r ?? [], incoming(id));
      if (r.length) rec.r = r; else delete rec.r;
      if (hold) { rec.h.add(hold[0][0]); versions.push([id, hold[0], hold[1]]); }
      ids.push(id);
    }
    // Lineage after a legacy apply (§3.5). Only when Core took what was
    // planned: a row the user typed during the cycle is a local edit, and
    // must reach the push as one (a new vid), never as a seed.
    const legacyHash = new Map(legacyPlan.objects.map((o) => [o.id, objectHash(o)]));
    for (const R of legacy) {
      const got = after.get(R.id);
      const prior = before.get(R.id);
      if (!got || !storeable(R.id) || (prior && objectHash(prior) === objectHash(got))) continue;
      const vh = objectHash(got);
      if (legacyHash.get(R.id) !== vh) continue;
      const rlin = remoteLin(R);
      const l = rlin && vh === rlin[0][1] ? pin(rlin[0], rlin) : [seedEntry(vh)];
      const h = new Set([l[0][0]]);
      unhold(R.id, lin.lin.get(R.id), h);
      lin.lin.set(R.id, { l, h });
      ids.push(R.id);
      versions.push([R.id, l[0], got]);
    }
    await writeLineage(lin, ids, versions, purge, false, orphans);
  }
  return {
    applied: result.appliedObjects,
    notes,
    events: events.map((e) => ({ ...e, device: validated.deviceName || "" })),
    conflicts: legacyPlan.conflicts + copies.length,
    merged: merges,
    retry: retryIds.size > 0,
    next: nextBases(validated.objects, bases, tables, new Set([...deferredIds, ...retryIds])),
  };
}

/** Advance lineage for local edits and return the snapshot fields. */
export async function pushLineage(lin, objects, deviceName) {
  if (lin.off) return {};
  const by = deviceLabel(deviceName);
  const ids = [];
  const versions = [];
  const live = new Set();
  for (const o of objects) {
    if (!storeable(o.id)) continue;
    live.add(o.id);
    const vh = objectHash(o);
    const rec = lin.lin.get(o.id);
    if (rec && rec.l[0][1] === vh) continue;
    const entry = [randomVid(), vh, by, o.updated_at];
    const l = [entry, ...(rec?.l ?? [])].slice(0, LINEAGE_MAX);
    const r = keepReceipts(l, rec?.r ?? []);
    lin.lin.set(o.id, { l, h: new Set([...(rec?.h ?? []), entry[0]]), ...(r.length ? { r } : {}), m: entry[0] });
    ids.push(o.id);
    versions.push([o.id, entry, o]);
  }
  const purge = [...lin.lin.keys()].filter((id) => !live.has(id));
  await writeLineage(lin, ids, versions, purge, true);
  if (lin.off) return {};
  const devices = [""];
  const index = new Map([["", 0]]);
  const at = (name) => {
    if (!index.has(name)) { if (devices.length === 64) return 0; index.set(name, devices.push(name) - 1); }
    return index.get(name);
  };
  const lineage = {};
  const receipts = {};
  let sent = 0;
  for (const o of objects) {
    const rec = lin.lin.get(o.id);
    if (rec && !isSeedOnly(rec.l)) lineage[o.id] = rec.l.map(([vid, vh, name, t]) => [vid, vh, at(deviceLabel(name)), t]);
    const r = rec ? keepReceipts(rec.l, rec.r ?? []) : [];
    // SYNC-NOTICE fix round 2 (Hive #16, R2-5): the same cap readLineage applies, so nothing is cut unseen.
    if (r.length && sent++ < LIMIT_RECEIPT_IDS) receipts[o.id] = r;
  }
  return { lineageV: 1, devices, lineage, ...(Object.keys(receipts).length ? { receipts } : {}) };
}

// ---------------------------------------------------------------- notices
// SYNC-NOTICE (Hive #11): one notice per sync cycle, never one per note.
// Whole sentences, so a translator controls the word order.
/** Core cuts a notice at 300 characters; a combined one stays under it. */
const NOTICE_CAP = 300;
const NOTICE = {
  restored: "Sync brought back '{title}': it was edited on {device} after you deleted it.",
  "kept-edit": "Sync kept your edit to '{title}': it had been deleted on {device}.",
  "edit-in-trash": "Sync kept your edit to '{title}', but {device} moved it to the trash.",
  moved: "'{title}' was moved on {device} too; that placement was kept.",
  archived: "'{title}' was archived or unarchived on {device} too; that change was kept.",
  copy: "'{title}' was changed on {device} too, so Sync kept your version as '{copy}'.",
  theirs: "'{title}' was changed on {device} too, so Sync kept that version as '{copy}'.",
};
// SYNC-NOTICE fix round 2 (Hive #20): several copies of one note from one device are one sentence.
const NOTICE_MANY = {
  copy: "'{title}' was changed on {device} too, so Sync kept your versions as {count} conflict copies, such as '{copy}'.",
  theirs: "'{title}' was changed on {device} too, so Sync kept those versions as {count} conflict copies, such as '{copy}'.",
};

/** One notice for a cycle's merge events: { message, id, left } (id: the note to open, or null;
 * left: the events that did not fit, to tell next time), or null. */
export function mergeNotice(events, t) {
  // SYNC-NOTICE fix round 3 (Hive #20): budgets are UTF-16 units, as Core's .slice(0, 300)
  // counts them, and a cut never splits a surrogate pair.
  const cut = (s, n) => {
    const str = String(s || "Untitled");
    if (str.length <= n) return str;
    let out = "";
    for (const ch of str) { if (out.length + ch.length > n) break; out += ch; }
    return `${out}…`;
  };
  const fit = (s) => (s.length <= NOTICE_CAP ? s : cut(s, NOTICE_CAP - 1));
  // SYNC-NOTICE fix (Hive #16, F5): every distinct outcome per note is kept,
  // and a conflict copy's name is never the one dropped.
  const byId = new Map();
  for (const e of events ?? []) {
    if (!NOTICE[e.kind]) continue;
    const kind = e.kind === "copy" && !e.mine ? "theirs" : e.kind;
    // SYNC-NOTICE fix (Hive #20): copies are told apart by id; two made within
    // one minute share a title.
    const key = e.copy ? `${kind}|${e.copyId ?? e.copy}` : kind;
    if (!byId.has(e.id)) byId.set(e.id, new Map());
    if (!byId.get(e.id).has(key)) byId.get(e.id).set(key, { ...e, kind, src: [] });
    byId.get(e.id).get(key).src.push(e);
  }
  const copyFirst = (list) => [...list].sort((a, b) => Number(Boolean(b.copy)) - Number(Boolean(a.copy)));
  if (!byId.size) return null;
  if (byId.size === 1) {
    const [[id, outcomes]] = byId;
    // Round 2 (Hive #20): copies of this note from one device fold into one counted sentence,
    // and a sentence that does not fit is left for the next notice, never dropped.
    const folded = new Map();
    for (const e of outcomes.values()) {
      const key = e.copy ? `${e.kind}|${e.device ?? ""}` : `${e.kind}|${e.copyId ?? ""}`;
      const had = folded.get(key);
      if (had) { had.count = (had.count ?? 1) + 1; had.src = [...had.src, ...e.src]; had.names.add(e.copy); } else folded.set(key, { ...e, names: new Set([e.copy]) });
    }
    const several = folded.size > 1;
    let message = "";
    const left = [];
    for (const e of copyFirst(folded.values())) {
      const device = e.device ? cut(e.device, 40) : t("another device");
      // Up to two distinct copy names; same-named copies are said once, with the count.
      const copy = e.count ? [...e.names].slice(0, 2).map((n) => cut(n, e.names.size > 1 ? 45 : several ? 70 : 100)).join("', '") : cut(e.copy, several ? 70 : 100);
      const line = t(e.count ? NOTICE_MANY[e.kind] : NOTICE[e.kind], { title: cut(e.title, several ? 40 : 60), device, copy, count: e.count });
      if (!message) message = fit(line);
      else if (message.length + 1 + line.length <= NOTICE_CAP) message += ` ${line}`;
      else left.push(...e.src);
    }
    return { message, id, left };
  }
  const notes = [...byId.values()].map((outcomes) => [...outcomes.values()]);
  const copies = notes.flat().filter((e) => e.copy);
  const names = notes.slice(0, 3).map((list) => `'${cut(list[0].title, copies.length ? 30 : 40)}'`).join(", ");
  let message = notes.length > 3
    ? t("Sync merged conflicting changes in {count} notes: {names} and {more} more.", { count: notes.length, names, more: notes.length - 3 })
    : t("Sync merged conflicting changes in {count} notes: {names}.", { count: notes.length, names });
  if (copies.length) {
    const shown = copies.slice(0, 2).map((e) => `'${cut(e.copy, 30)}'`).join(", ");
    message += " " + (copies.length > 2
      ? t("Conflict copies kept: {copies} and {more} more.", { copies: shown, more: copies.length - 2 })
      : t("Conflict copies kept: {copies}.", { copies: shown }));
  }
  return { message: fit(message), id: null, left: [] };
}

// Hive #7: optional, bounded and independent of note validation. No title inference.
export function readConflictDescriptors(snapshot) {
  const included = new Set((snapshot.objects ?? []).map(o => o.id)), seen = new Set();
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const fields = ["content", "title", "props", "parent_id", "type", "archived_at", "trashed_at"];
  return (Array.isArray(snapshot.conflicts) ? snapshot.conflicts : []).slice(0,included.size).filter(d => {
    if (!d || Object.keys(d).some(k => !["originalId","copyId","fields"].includes(k)) || !uuid.test(d.originalId) || !uuid.test(d.copyId)
      || d.originalId === d.copyId || !included.has(d.copyId) || seen.has(d.copyId)
      || !Array.isArray(d.fields) || !d.fields.length || d.fields.length > fields.length || d.fields.some(f=>!fields.includes(f))) return false;
    seen.add(d.copyId); return true;
  }).map(d=>({originalId:d.originalId,copyId:d.copyId,fields:[...new Set(d.fields)].sort()}));
}
// </sync-merge>
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

  async delete(fileId) {
    await this.api(`/drive/v3/files/${fileId}`, { method: "DELETE" });
  }
}

// ------------------------------------------------------------- shared folder

// SYNC-TRANSPORT (Hive #9): `Sync` talks to its remote through this shape
// only, so Google Drive is one implementation and a folder two agent
// sandboxes share is another:
//   signedIn() / signIn() / signOut()
//   folderId() / mediaFolderId()        -> opaque folder handles
//   list(folder?)                       -> [{ id, name, modifiedTime }]
//   download(id) -> Uint8Array          upload(name, bytes, existingId?, folder?) -> id
//   delete(id)
// The shared folder is flat, so a "folder" is a name prefix: snapshots and
// the key at the top, media under "media.". Core only offers it inside an
// agent sandbox started with --shared (docs/AGENT_SANDBOX.md); a real build
// refuses every call, so Google is what users ever get.

const toBase64 = (bytes) => {
  let text = "";
  for (let i = 0; i < bytes.length; i += 0x8000) text += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(text);
};
const fromBase64 = (text) => Uint8Array.from(atob(text), (c) => c.charCodeAt(0));

export class SharedFolder {
  constructor(folder) { this.folder = folder; }
  signedIn() { return true; }
  async signIn() {}
  async signOut() {}
  async folderId() { return ""; }
  async mediaFolderId() { return "media."; }
  async list(prefix = "") {
    return (await this.folder.list())
      .filter((file) => file.name.startsWith(prefix) && (prefix || !file.name.startsWith("media.")))
      .map((file) => ({ id: file.name, name: file.name.slice(prefix.length), modifiedTime: file.modified }));
  }
  async download(id) { return fromBase64(await this.folder.read(id)); }
  async upload(name, bytes, existingId, prefix = "") {
    const id = existingId ?? prefix + name;
    await this.folder.write(id, toBase64(bytes));
    return id;
  }
  async delete(id) { await this.folder.remove(id); }
}

// ------------------------------------------------------------------ the sync

export class Sync {
  constructor(context) {
    this.context = context;
    this.remote = new Google(context.storage, context.oauth);
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

  /** SYNC-NOTICE (Hive #11): one notice per cycle, never one per note; off in settings. */
  notifyMerges(events) {
    const { context } = this;
    // SYNC-NOTICE fix (Hive #16, F2): a batch waits here, deduplicated, until a
    // notice has actually been shown; one that failed to show goes out next run.
    const pending = (this.pendingNotices ??= new Map());
    // SYNC-NOTICE fix round 2 (Hive #16, R2-4): a copy is its own outcome; two copies of one note both stay.
    // SYNC-NOTICE fix (Hive #20): keyed by the copy's id, since two copies can share a title.
    for (const event of events) pending.set(JSON.stringify([event.kind, event.id, event.device, event.copyId ?? event.copy ?? "", Boolean(event.mine)]), event);
    if (context.storage.get("mergeNotices") === false) return void pending.clear();
    const t = (key, values) => context.i18n.t(key, values);
    const notice = mergeNotice([...pending.values()], t);
    if (notice) {
      // Hive #7: route only announced copies, never leftovers or a title guess.
      const left = new Set(notice.left ?? []);
      const copyIds = [...new Set([...pending.values()].filter(e=>e.kind === "copy" && e.copyId && !left.has(e)).map(e=>e.copyId))];
      const action = copyIds.length && typeof context.ui.openSyncConflicts === "function"
        ? { label: t(copyIds.length === 1 ? "Resolve conflict" : "Review conflicts"), onSelect: () => context.ui.openSyncConflicts(copyIds.length === 1 ? copyIds[0] : undefined) }
        : notice.id
        ? { label: t("Open"), onSelect: () => context.ui.openObject(notice.id) }
        : { label: t("Details"), onSelect: () => context.ui.openPluginSettings("notible.sync") };
      context.ui.notice(notice.message, { timeoutMs: 10_000, action });
    }
    // SYNC-NOTICE fix round 2 (Hive #20): what did not fit stays for the next notice.
    const left = new Set(notice?.left ?? []);
    for (const [key, event] of pending) if (!left.has(event)) pending.delete(key);
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
    void this.forgetLineage();
    return key;
  }

  usePairingKey(text) {
    const bytes = decodeKey(text);
    this.context.storage.set("key", encodeKey(bytes));
    void this.forgetLineage();
  }

  // SYNC-MERGE-A (Hive #5): a new Drive/key means a new exchange; start lineage over.
  async forgetLineage() {
    if (this.merge) this.merge.off = true; // stop the in-flight run() at its next lineage step
    // Wait for it: its last store batches must not land after the wipe. Never call this from inside run().
    if (this.applying) await this.running;
    // A run that was inside openLineage has installed a new lin by now: stop that one too.
    const lin = this.merge;
    this.merge = null;
    if (lin) lin.off = true; // an in-flight run() writes nothing after the wipe
    try { await resetLineage(this.context.store); await markReseed(this.context.store); } catch { /* re-seeded on the next run anyway */ }
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
    const folder = await this.remote.mediaFolderId();
    const remote = new Map((await this.remote.list(folder)).map((file) => [file.name, file.id]));

    let pulled = 0;
    for (const name of missing) {
      const id = remote.get(`${name}.bin`);
      // Not on Drive yet: the machine that pasted it has not run a cycle
      // since. Nothing is wrong and nothing needs saying.
      if (!id) continue;
      try {
        // `seal` JSON-encodes its payload, so what comes back out is the
        // base64 string that went in.
        const base64 = await unseal(key, await this.remote.download(id));
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
        await this.remote.upload(`${name}.bin`, await seal(key, base64), undefined, folder);
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
    // SYNC-MERGE-A (Hive #5): forgetLineage waits on this; it settles in the finally below and never rejects.
    this.running = new Promise((resolve) => { this.release = resolve; });
    // SYNC-NOTICE fix (Hive #16, F2): outside the try, so the finally can announce
    // merges already committed when a later step (export, media, upload) fails.
    const events = [];
    try {
      this.setStatus("busy", "Synchronising…");
      const key = this.keyBytes();
      const local = await this.context.data.sync.export();
      const files = await this.remote.list();
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

      // SYNC-MERGE-A (Hive #5): lineage, loaded once per plugin start.
      // `lin` is held for the whole run: forgetLineage may null this.merge mid-run.
      const lin = (this.merge ??= await openLineage(this.context.store, local.objects));
      const io = {
        deviceName: this.deviceName() || "",
        copyLabel,
        localById,
        apply: (input) => this.context.data.sync.apply({ cursor: local.cursor, ...input }),
        exportById: async (ids) => new Map((await this.context.data.sync.export()).objects.filter((o) => ids.has(o.id)).map((o) => [o.id, o])),
      };
      let merged = 0;

      for (const file of files) {
        if (file.name === mine) continue;
        if (file.modifiedTime && this.seen.get(file.id) === file.modifiedTime) continue;
        // One peer failing -- unreadable, or refused by the database -- must
        // not stop the others or this device's own push, and must never be
        // read as "that device deleted everything".
        try {
          const raw = await unseal(key, await this.remote.download(file.id));
          const validated = { ...validateSnapshot(raw, types), ...readLineage(raw) };
          peers[validated.deviceId] = {
            name: validated.deviceName || peers[validated.deviceId]?.name || "",
            writtenAt: validated.writtenAt,
          };
          if (validated.rejected.length) notes.push(`${file.name}: skipped ${validated.rejected.length} object(s)`);
          const { apply, deferred } = planApply(validated, this.openObjectId);
          skipped += deferred.length;
          const result = await pullPeer(lin, io, {
            validated,
            apply,
            deferredIds: new Set(deferred.map((object) => object.id)),
            bases: this.context.storage.get(`bases:${validated.deviceId}`) ?? {},
            tables: this.context.storage.get(`tableBases:${validated.deviceId}`) ?? {},
          });
          pulled += result.applied;
          conflicts += result.conflicts;
          merged += result.merged;
          notes.push(...result.notes);
          events.push(...result.events);
          // Only after a successful apply: a base must never run ahead of
          // what this device actually took in.
          this.context.storage.set(`bases:${validated.deviceId}`, result.next.bases);
          this.context.storage.set(`tableBases:${validated.deviceId}`, result.next.tables);
          // Held back (open note) or lost to a newer local edit: offer again.
          if (!deferred.length && !result.retry) this.seen.set(file.id, file.modifiedTime);
        } catch (error) {
          notes.push(`${file.name}: ${error.message}`);
        }
      }
      this.context.storage.set("peers", peers);

      // Push last, so what we upload already includes anything just pulled.
      const fresh = await this.context.data.sync.export();
      const media = await this.syncMedia(fresh, key, notes);
      const deviceName = this.deviceName();
      const lineage = await pushLineage(lin, fresh.objects, deviceName);
      const payload = {
        conflicts: fresh.conflicts ?? [],
        objects: fresh.objects,
        relations: fresh.relations,
        tombstones: fresh.tombstones,
        relationTombstones: fresh.relationTombstones,
        ...lineage,
      };
      const digest = await digestOf({ deviceName, ...payload });
      const existing = files.find((file) => file.name === mine)?.id;
      // Same content as this device's last upload (and the file is still
      // there): nothing to send. Memory only, so every start pushes once.
      const pushed = !existing || digest !== this.pushedDigest;
      if (pushed) {
        const sealed = await seal(key, { v: SNAPSHOT_VERSION, deviceId: fresh.deviceId, deviceName, writtenAt: Date.now(), ...payload });
        await this.remote.upload(mine, sealed, existing);
        this.pushedDigest = digest;
        this.context.storage.set("lastPush", Date.now());
      }

      this.context.storage.set("lastSync", Date.now());
      const detail = [
        `${pulled} change(s) in`,
        merged ? `${merged} merged` : null,
        conflicts ? `${conflicts} edited on both devices` : null,
        pushed ? `${fresh.objects.length} object(s) out` : "nothing new to send",
        media.pulled ? `${media.pulled} image(s) in` : null,
        media.pushed ? `${media.pushed} image(s) out` : null,
        skipped ? `${skipped} held back (note is open)` : null,
      ].filter(Boolean).join(", ");
      this.setStatus("ok", `${detail}.${notes.length ? ` ${notes.join(" ")}` : ""}`);
      return { pulled, skipped, notes, events, media, pushed, conflicts };
    } catch (error) {
      this.setStatus("error", error.message || String(error));
      throw error;
    } finally {
      this.applying = false;
      this.release();
      try { this.notifyMerges(events); } catch (error) { console.warn("[sync] merge notice failed", error); }
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
/* The app's own switch (Core's .core-switch), not the OS checkbox. */
.nsync-switch { position: relative; display: inline-flex; flex: 0 0 auto; width: 40px; height: 24px; }
.nsync .nsync-switch input { position: absolute; inset: 0; width: 100%; height: 100%; margin: 0; padding: 0; border: 0; background: transparent; opacity: 0; cursor: pointer; }
.nsync-switch span { display: block; width: 40px; height: 24px; box-sizing: border-box; border: 1px solid var(--notible-border); border-radius: 999px; background: var(--notible-hover); transition: background 160ms ease, border-color 160ms ease; }
.nsync-switch span::after { content: ""; display: block; width: 18px; height: 18px; margin: 2px; border-radius: 50%; background: var(--notible-raised); box-shadow: 0 1px 3px rgb(55 48 39 / 20%); transition: transform 160ms ease; }
.nsync-switch input:checked + span { border-color: var(--notible-accent); background: var(--notible-accent); }
.nsync-switch input:checked + span::after { transform: translateX(16px); }
.nsync-switch input:focus-visible + span { outline: 2px solid var(--notible-accent); outline-offset: 2px; }
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

/** A checkbox drawn as the app's switch. */
const switchFor = (input) => {
  input.setAttribute("role", "switch");
  return element("span", { className: "nsync-switch" }, [input, element("span", { ariaHidden: "true" })]);
};

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
    const signedIn = sync.remote.signedIn();
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
      out.onclick = async () => { await sync.remote.signOut(); await sync.forgetLineage(); render(); };
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
          await sync.remote.signIn();
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
        switchFor(toggle),
        element("label", { className: "nsync-schedule__label", htmlFor: "nsync-auto-toggle", textContent: "Synchronise automatically, and at least every" }),
        every,
        element("span", { className: "nsync-schedule__suffix", textContent: "minutes" }),
      ]),
      element("p", { className: "nsync-hint", textContent: "On by default: also runs when Notible starts and about a minute after you change something. Each run contacts Google." }),
    );
    body.append(auto);

    // --- merge notices (SYNC-NOTICE, Hive #11)
    const noticeStep = stepDetails("5");
    const noticeBadge = element("span", { className: "nsync-step__badge" });
    // SYNC-NOTICE fix (Hive #16, F7): this setting is translated with the notices.
    const tr = (key) => sync.context.i18n.t(key);
    const notices = element("input", { id: "nsync-notices-toggle", type: "checkbox", checked: sync.context.storage.get("mergeNotices") ?? true });
    notices.onchange = () => {
      sync.context.storage.set("mergeNotices", notices.checked);
      noticeBadge.textContent = tr(notices.checked ? "On" : "Off");
    };
    noticeBadge.textContent = tr(notices.checked ? "On" : "Off");
    noticeStep.append(element("summary", { className: "nsync-step__header" }, [
      element("div", { className: "nsync-step__heading" }, [
        element("span", { className: "nsync-step__number", textContent: "05" }),
        element("h4", { textContent: tr("Merge notices") }),
      ]),
      noticeBadge,
    ]),
      element("div", { className: "nsync-schedule" }, [
        switchFor(notices),
        element("label", { htmlFor: "nsync-notices-toggle", textContent: tr("Show sync merge notices") }),
      ]),
      element("p", { className: "nsync-hint", textContent: tr("A short notice after a sync that kept another device's version over yours, brought back a note you deleted, or saved a conflict copy.") }),
    );
    body.append(noticeStep);
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
    version: "0.4.7",
    apiVersion: "1.26",
    description: "Keep this workspace the same on your own computers through your Google Drive. Everything is encrypted on your computer first, so neither Notible nor Google can read it.",
    author: "Notible",
    permissions: ["data.sync", "data.read", "workspace.ui", "network"],
  },

  onload(context) {
    const sync = new Sync(context);
    this._sync = sync;
    // SYNC-TRANSPORT (Hive #9): in an agent sandbox with a shared folder,
    // sync through it instead of Google. Refused (false) everywhere else.
    context.data.sync.sandboxFolder?.available().then((shared) => {
      if (!shared) return;
      sync.remote = new SharedFolder(context.data.sync.sandboxFolder);
      sync.setStatus(sync.status.state, sync.status.text, sync.status.notes);
    }, () => {});
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
      name: "Secure Sync: sync now",
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
      if (!(context.storage.get("auto") ?? true) || !(sync.remote.signedIn() && Boolean(context.storage.get("key")))) return;
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
