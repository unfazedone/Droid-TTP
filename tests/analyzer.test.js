const test = require("node:test");
const assert = require("node:assert/strict");
const zlib = require("node:zlib");
const { analyzeApk, extractIndicators, parseTextManifest, readZipEntries } = require("../analyzer");

function createZip(entries) {
  const localParts = [];
  const centralParts = [];
  let localOffset = 0;
  for (const [name, source] of Object.entries(entries)) {
    const nameBytes = Buffer.from(name);
    const plain = Buffer.isBuffer(source) ? source : Buffer.from(source);
    const compressed = name.endsWith(".dex") ? zlib.deflateRawSync(plain) : plain;
    const method = name.endsWith(".dex") ? 8 : 0;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(plain.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    localParts.push(local, nameBytes, compressed);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(plain.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt32LE(localOffset, 42);
    centralParts.push(central, nameBytes);
    localOffset += local.length + nameBytes.length + compressed.length;
  }
  const centralDirectory = Buffer.concat(centralParts);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(Object.keys(entries).length, 8);
  end.writeUInt16LE(Object.keys(entries).length, 10);
  end.writeUInt32LE(centralDirectory.length, 12);
  end.writeUInt32LE(localOffset, 16);
  return Buffer.concat([...localParts, centralDirectory, end]);
}

test("parses package, permissions, SDK, and components from text manifests", () => {
  const parsed = parseTextManifest(`<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.example.app" android:versionName="2.1" android:versionCode="8"><uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35"/><uses-permission android:name="android.permission.INTERNET"/><application android:label="Example"><activity android:name=".MainActivity" android:exported="true"/></application></manifest>`);
  assert.equal(parsed.packageName, "org.example.app");
  assert.equal(parsed.versionName, "2.1");
  assert.equal(parsed.versionCode, "8");
  assert.equal(parsed.minSdk, "23");
  assert.equal(parsed.targetSdk, "35");
  assert.deepEqual(parsed.permissions, ["android.permission.INTERNET"]);
  assert.deepEqual(parsed.components, [{ type: "activity", name: ".MainActivity", exported: true }]);
});

test("analyzes APK metadata and labels permission evidence as capability", () => {
  const manifest = `<manifest package="org.example.app"><uses-permission android:name="android.permission.RECORD_AUDIO"/><application><service android:name=".Recorder" android:exported="false"/></application></manifest>`;
  const apk = createZip({
    "AndroidManifest.xml": manifest,
    "classes.dex": "strings: https://sample.example/path 203.0.113.8"
  });
  const output = analyzeApk(apk);
  assert.equal(output.metadata.packageName, "org.example.app");
  assert.ok(output.evidence.some((item) => item.type === "permission" && item.classification === "capability"));
  assert.ok(output.evidence.some((item) => item.value === "service: .Recorder"));
  assert.ok(output.evidence.some((item) => item.value === "https://sample.example/path"));
  assert.ok(output.evidence.some((item) => item.value === "203.0.113.8"));
  assert.match(output.evidence.find((item) => item.type === "permission").details, /does not establish/);
});

test("rejects malformed or non-APK ZIP inputs", () => {
  assert.throws(() => analyzeApk(Buffer.from("not an APK")), /valid APK\/ZIP/);
  assert.throws(() => analyzeApk(createZip({ "classes.dex": "no manifest" })), /AndroidManifest.xml is missing/);
});

test("limits the number of archive entries before reading them", () => {
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(5001, 8);
  eocd.writeUInt16LE(5001, 10);
  assert.throws(() => readZipEntries(eocd), /exceeds analysis limits/);
});

test("extracts indicators as strings without implying network behavior", () => {
  const found = extractIndicators([Buffer.from("const endpoint=https://updates.example.org/a 198.51.100.10")]);
  assert.ok(found.includes("https://updates.example.org/a"));
  assert.ok(found.includes("198.51.100.10"));
});
