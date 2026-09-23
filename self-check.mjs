/**
 * Runnable check for the parts of Notible Sync that can be wrong silently:
 * the key encoding, the sealed-snapshot round trip, and the validator that
 * stands between a peer's file and the database.
 *
 * node plugins/notible-sync/self-check.mjs
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import plugin, { encodeKey, decodeKey, seal, unseal, safeParse, validateSnapshot, planApply, gunzip, mediaNamesIn, mediaNamesOf, mergeTableProps, planConflicts, objectHash } from "./main.js";

// --- identity
// Core loads plugin.json, shows it to the user, then refuses the entry module
// if it claims to be something else. Forgetting `manifest` on the export
// altogether fails with "Cannot read properties of undefined (reading 'id')",
// which says nothing about the cause — so assert it here instead.
const declared = JSON.parse(readFileSync(new URL("./plugin.json", import.meta.url), "utf8"));
assert.ok(plugin.manifest, "the entry module must export a manifest, not just onload");
for (const field of ["id", "name", "version", "apiVersion", "description", "author"]) {
  assert.equal(plugin.manifest[field], declared[field], `${field} must match plugin.json`);
}
assert.deepEqual(plugin.manifest.permissions, declared.permissions);
assert.equal(typeof plugin.onload, "function");
assert.equal(typeof plugin.onunload, "function");

const object = (over = {}) => ({
  id: "a", type: "note", title: "T", content: "{}", props: "{}",
  created_at: 1, updated_at: 2, archived_at: null, trashed_at: null, parent_id: null, ...over,
});
const snapshot = (over = {}) => ({
  v: 1, deviceId: "dev-1", writtenAt: 1,
  objects: [object()], relations: [], tombstones: [], relationTombstones: [], ...over,
});
const types = new Set(["note", "project"]);

// --- key encoding
const raw = crypto.getRandomValues(new Uint8Array(32));
assert.deepEqual([...decodeKey(encodeKey(raw))], [...raw], "key must survive a round trip");
// A key read off one screen and typed into another: lower case, lost dashes,
// and the four letters Crockford maps onto digits.
const typed = encodeKey(raw).toLowerCase().replace(/-/g, "");
assert.deepEqual([...decodeKey(typed)], [...raw], "casing and dashes must not matter");
assert.throws(() => decodeKey("TOO-SHORT"), /32 bytes/, "a truncated key must be refused, not padded");

// --- sealed round trip
const key = crypto.getRandomValues(new Uint8Array(32));
const sealed = await seal(key, snapshot());
assert.deepEqual(await unseal(key, sealed), snapshot(), "a snapshot must survive seal/unseal");
assert.ok(!new TextDecoder().decode(sealed).includes("dev-1"), "the device id must not be readable in the ciphertext");

// The whole peer-authentication story rests on these two.
await assert.rejects(
  unseal(crypto.getRandomValues(new Uint8Array(32)), sealed),
  /not written by a paired device/,
  "a snapshot sealed under another key must be refused",
);
const tampered = Uint8Array.from(sealed);
tampered[tampered.length - 1] ^= 1;
await assert.rejects(unseal(key, tampered), /not written by a paired device/, "a flipped bit must be refused");

// --- dangerous keys are stripped
// Asserting on Object.prototype here would pass with a plain JSON.parse too,
// which makes it a test of nothing. What safeParse actually guarantees is
// that the keys never appear in the parsed value at all.
const source = '{"a":1,"__proto__":{"owned":true},"constructor":{"x":1},"prototype":{"y":1}}';
const cleaned = safeParse(source);
assert.equal(cleaned.a, 1);
for (const badKey of ["__proto__", "constructor", "prototype"]) {
  assert.ok(!Object.hasOwn(cleaned, badKey), `safeParse must drop ${badKey}`);
}
assert.ok(Object.hasOwn(JSON.parse(source), "__proto__"), "the plain parser keeps it — that is why safeParse exists");
// And a merge of the cleaned value cannot move a prototype anywhere.
const target = {};
Object.assign(target, cleaned);
assert.equal(Object.getPrototypeOf(target), Object.prototype, "merging a cleaned peer value must not reparent the target");

// --- validation
const clean = validateSnapshot(snapshot(), types);
assert.equal(clean.objects.length, 1);
assert.equal(clean.rejected.length, 0);

assert.throws(() => validateSnapshot(snapshot({ v: 2 }), types), /different version/);
assert.throws(() => validateSnapshot({ ...snapshot(), deviceId: "" }, types), /no device id/);

const mixed = validateSnapshot(snapshot({
  objects: [
    object({ id: "ok" }),
    object({ id: "weird", type: "notible.evil" }),
    object({ id: "nocontent", content: 42 }),
    object({ id: "huge", title: "x".repeat(5000) }),
    object({ id: "nostamp", updated_at: "yesterday" }),
    { nonsense: true },
  ],
}), types);
assert.deepEqual(mixed.objects.map((item) => item.id), ["ok"], "only the clean object may pass");
assert.equal(mixed.rejected.length, 5, "every dropped object must be reported, not swallowed");
assert.ok(mixed.rejected.some((line) => line.includes("unknown type")));

// Malformed relations and tombstones are dropped, never passed through: a
// tombstone with a bad timestamp reaching sync_apply would delete an object.
const junk = validateSnapshot(snapshot({
  relations: [{ from_id: "a", to_id: "b", kind: "in", created_at: 1 }, { from_id: "a" }],
  tombstones: [{ object_id: "x", deleted_at: 5 }, { object_id: "y" }, { deleted_at: 1 }],
  relationTombstones: [{ from_id: "a", to_id: "b", kind: "in", deleted_at: 3 }, {}],
}), types);
assert.equal(junk.relations.length, 1);
assert.equal(junk.tombstones.length, 1);
assert.equal(junk.relationTombstones.length, 1);

// --- the hardening that stands between a peer and an unrecoverable wipe.
// A tombstone erases the object AND its history and bars the id from ever
// being written again (db.rs), and it wins whenever `deleted_at` outranks the
// local `updated_at` — so a far-future or fractional stamp is a workspace
// wipe with no undo. Both used to pass: the check was `Number.isFinite`.
const farFuture = Date.UTC(9999, 0, 1);
// Inside the fixed ceiling and still a life sentence: a 2199 tombstone beats
// every edit this machine will ever make. Only "not from the future" catches it.
const justUnderTheCeiling = Date.UTC(2199, 0, 1);
const wipe = validateSnapshot(snapshot({
  tombstones: [
    { object_id: "doomsday", deleted_at: farFuture },
    { object_id: "ceiling", deleted_at: justUnderTheCeiling },
    { object_id: "float", deleted_at: 1.5 },
    { object_id: "negative", deleted_at: -1 },
    { object_id: "fine", deleted_at: 5 },
  ],
}), types);
assert.deepEqual(wipe.tombstones.map((item) => item.object_id), ["fine"],
  "only a tombstone with a plausible epoch-millisecond stamp may pass");
// Tomorrow is fine — two machines never agree on the clock to the second.
assert.equal(
  validateSnapshot(snapshot({ tombstones: [{ object_id: "skew", deleted_at: Date.now() + 60_000 }] }), types).tombstones.length,
  1, "a stamp a minute ahead is clock skew, not an attack");

// Same stamps on an object: year 9999 makes the row unbeatable by any local
// edit, and 1.5 is cast outside the error path in Rust and kills sync for good.
const stamps = validateSnapshot(snapshot({
  objects: [
    object({ id: "future", updated_at: farFuture }),
    object({ id: "fractional", updated_at: 1.5 }),
    object({ id: "ok" }),
  ],
}), types);
assert.deepEqual(stamps.objects.map((item) => item.id), ["ok"]);
assert.ok(stamps.rejected.every((line) => line.includes("bad timestamps")));
assert.equal(
  validateSnapshot(snapshot({ objects: [object({ archived_at: 1.5 })] }), types).objects.length, 0,
  "a nullable marker must be held to the same range",
);

// Every list is capped, the destructive one included.
const many = (count) => Array.from({ length: count }, (_, index) => ({ object_id: `x${index}`, deleted_at: 1 }));
assert.throws(() => validateSnapshot(snapshot({ tombstones: many(200_001) }), types), /refusing to apply/);
assert.doesNotThrow(() => validateSnapshot(snapshot({ tombstones: many(10) }), types));

// A decompression bomb has to die before the validator ever sees it: unseal
// inflates first, and gzip turns megabytes of zeros into a few kilobytes.
// Tested against a small explicit limit — the real one is 512 MB, which no
// test should allocate to prove the loop stops.
const zeros = new Uint8Array(1024 * 1024);
const squashed = new Uint8Array(await new Response(
  new Blob([zeros]).stream().pipeThrough(new CompressionStream("gzip")),
).arrayBuffer());
assert.ok(squashed.length < zeros.length / 100, "the fixture must actually be a bomb");
await assert.rejects(gunzip(squashed, 4096), /size limit/, "inflating past the limit must stop, not finish");
assert.equal((await gunzip(squashed)).length, zeros.length, "a payload under the limit still inflates whole");

// --- media names out of note content
// Names are how a note and its pictures agree on what a picture is called;
// getting this wrong means either missing images or asking Drive for files
// that do not exist.
const IMG = "1f2e3d4c-5b6a-4978-8899-aabbccddeeff.png";
assert.deepEqual(mediaNamesIn(`![](media/${IMG})`), [IMG]);
assert.deepEqual(mediaNamesIn(`<img src="media/${IMG}">`), [IMG]);
assert.deepEqual(mediaNamesIn(`two ![](media/${IMG}) and ![](media/${IMG})`), [IMG, IMG]);
assert.deepEqual(mediaNamesIn("no pictures"), []);
assert.deepEqual(mediaNamesIn(null), [], "content is not always a string");
// Pre-migration content and other people's servers are not our files.
assert.deepEqual(mediaNamesIn(`![](C:/Users/Sz/media/${IMG})`), [IMG],
  "a path ending in media/<uuid> still names our file");
assert.deepEqual(mediaNamesIn(`![](media/${IMG.replace(".png", ".exe")})`), [],
  "only extensions Core actually writes");

// The set is taken from the WHOLE local workspace, never from the objects a
// cycle happened to apply: a failed download leaves the object in the
// database, so a delta-based list would never mention its picture again.
const other = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee.webp";
assert.deepEqual(
  mediaNamesOf([
    { content: `![](media/${IMG})`, props: "{}" },
    { content: "plain", props: `{"cover":"media/${other}"}` },
    { content: `![](media/${IMG})`, props: "{}" },
  ]).sort(),
  [IMG, other].sort(),
  "props count too, and duplicates collapse",
);
assert.deepEqual(mediaNamesOf([]), []);
assert.deepEqual(mediaNamesOf(undefined), []);

// --- open-note deferral
const two = validateSnapshot(snapshot({ objects: [object({ id: "open" }), object({ id: "other" })] }), types);
const planned = planApply(two, "open");
assert.deepEqual(planned.apply.objects.map((item) => item.id), ["other"], "the open note must not be written under the caret");
assert.deepEqual(planned.deferred.map((item) => item.id), ["open"]);
assert.equal(planApply(two, null).deferred.length, 0, "nothing is deferred when no note is open");
assert.equal(planApply(two, "unrelated").apply.objects.length, 2);

// --- conflicts: a table merges cell by cell; anything else keeps the newer
// version and the device whose own version lost saves it as a copy.
{
  const props = (columns, rows) => JSON.stringify({ columns, rows });
  const base = props([{ id: "c1", name: "A", type: "text" }], [{ id: "r1", cells: { c1: "a" } }, { id: "r2", cells: { c1: "b" } }]);
  const mine = props([{ id: "c1", name: "A", type: "text" }, { id: "c2", name: "B", type: "text" }], [{ id: "r1", cells: { c1: "a", c2: "x" } }, { id: "r2", cells: { c1: "b", c2: "" } }]);
  const theirs = props([{ id: "c1", name: "A", type: "text" }], [{ id: "r1", cells: { c1: "a" } }, { id: "r2", cells: { c1: "edited" } }]);
  const clean = mergeTableProps(base, mine, theirs, false);
  const out = JSON.parse(clean.props);
  assert.deepEqual(out.columns.map((c) => c.id), ["c1", "c2"], "a column added on one side survives");
  assert.equal(out.rows[0].cells.c2, "x");
  assert.equal(out.rows[1].cells.c1, "edited", "a cell edited on the other side survives");
  assert.equal(clean.conflicts, 0);
  assert.equal(mergeTableProps(base, mine, theirs, true).props, clean.props, "both devices merge to the same bytes");

  const clash = mergeTableProps(base, props([{ id: "c1", name: "A", type: "text" }], [{ id: "r1", cells: { c1: "mine" } }, { id: "r2", cells: { c1: "b" } }]), props([{ id: "c1", name: "A", type: "text" }], [{ id: "r1", cells: { c1: "theirs" } }, { id: "r2", cells: { c1: "b" } }]), false);
  assert.equal(JSON.parse(clash.props).rows[0].cells.c1, "theirs", "same cell on both: newer wins");
  assert.equal(clash.localLost, true, "and this device owes a copy");
  assert.equal(mergeTableProps(base, "not json", theirs, true), null, "unreadable table falls back to a copy");

  const note = (content, updated_at) => ({ id: "n", type: "note", title: "N", content, props: "{}", created_at: 1, updated_at, archived_at: null, trashed_at: null, parent_id: null });
  const bases = { n: objectHash(note("old", 1)) };
  const lost = planConflicts([note("theirs", 3)], new Map([["n", note("mine", 2)]]), bases, {}, "Home");
  assert.equal(lost.conflicts, 1);
  assert.equal(lost.objects.length, 2, "remote applied + a copy of ours");
  assert.equal(lost.objects[1].content, "mine");
  assert.notEqual(lost.objects[1].id, "n");
  const won = planConflicts([note("theirs", 2)], new Map([["n", note("mine", 3)]]), bases, {}, "Home");
  assert.equal(won.objects.length, 0, "ours is newer: nothing applied, no copy (the other side copies)");
  assert.equal(planConflicts([note("theirs", 3)], new Map([["n", note("old", 1)]]), bases, {}, "Home").conflicts, 0, "one-sided edit is no conflict");
  assert.equal(planConflicts([note("theirs", 3)], new Map([["n", note("mine", 2)]]), {}, {}, "Home").objects.length, 1, "no base yet: plain newest-wins");
}

console.log("Notible Sync self-check passed.");
