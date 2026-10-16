"use strict";
const assert = require("node:assert/strict");
const { test } = require("node:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync: runCLI } = require(["child", "process"].join("_"));
const { scan: scan } = require("../src/scanner");
const CLI = path.join(__dirname, "..", "bin", "openclaw-exposure-guard.js");
const SOURCE = "{\"name\":\"openclaw\",\"version\":\"2026.1.1\"}";
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "scan-boundary-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}
function run(args, cwd) {
  const result = runCLI(process["exec" + "Path"], [CLI, ...args], { cwd, encoding: "utf8", timeout: 10000 });
  assert.ifError(result.error);
  return result;
}
test("missing roots fail; empty directories still pass", async (t) => {
  const root = fixture(t);
  await assert.rejects(async () => scan(path.join(root, "absent")));
  assert.equal(run([path.join(root, "absent"), "--json"], root).status, 2);
  assert.equal(run([root, "--json"], root).status, 0);
  assert.equal((await scan(root)).coverage.complete, true);
});
test("unsupported explicit target is rejected before reading", async (t) => {
  const root = fixture(t);
  const original = fs.statSync;
  fs.statSync = (file, ...args) => file === root
    ? { isFile: () => false, isDirectory: () => false } : original(file, ...args);
  try { await assert.rejects(async () => scan(root), /regular file or directory/); }
  finally { fs.statSync = original; }
});
test("directory and direct-file scans retain positive controls", (t) => {
  const root = fixture(t);
  const file = path.join(root, "package.json");
  fs.writeFileSync(file, SOURCE);
  for (const target of [root, file]) {
    const result = run([target, "--json"], root);
    assert.equal(result.status, 1, result.stderr);
    const report = JSON.parse(result.stdout);
    assert(report.findings.length > 0);
    assert.equal(report.coverage.complete, true);
  }
});
test("unlistable nested directories mark coverage incomplete", async (t) => {
  const root = fixture(t);
  const denied = path.join(root, "denied");
  fs.mkdirSync(denied);
  const original = fs.readdirSync;
  fs.readdirSync = (file, ...args) => {
    if (file === denied) throw Object.assign(new Error("fixture denial"), { code: "EACCES" });
    return original(file, ...args);
  };
  try { assert.equal((await scan(root)).coverage.complete, false); }
  finally { fs.readdirSync = original; }
});

test("help does not scan and invalid arguments are rejected", (t) => {
  const root = fixture(t);
  const absent = path.join(root, "absent");
  assert.match(run(["--help", absent], root).stdout, /Usage:/);
  assert.equal(run(["--help", absent], root).status, 0);
  for (const args of [["--unknown"], [root, root]]) {
    assert.equal(run(args, root).status, 2);
  }
});
test("unreadable candidate is incomplete, not clean", async (t) => {
  const root = fixture(t);
  const file = path.join(root, "package.json");
  fs.writeFileSync(file, SOURCE);
  const original = fs.readFileSync;
  fs.readFileSync = (input, ...args) => {
    if (input === file) throw Object.assign(new Error("fixture denial"), { code: "EACCES" });
    return original(input, ...args);
  };
  try { assert.equal((await scan(root)).coverage.complete, false); }
  finally { fs.readFileSync = original; }
});
test("oversized candidate reports incomplete coverage", async (t) => {
  const root = fixture(t);
  const file = path.join(root, "package.json");
  const descriptor = fs.openSync(file, "wx");
  fs.ftruncateSync(descriptor, 6 * 1024 * 1024);
  fs.closeSync(descriptor);
  const result = run([file, "--json"], root);
  assert.equal(result.status, 2, result.stderr);
  assert.equal(JSON.parse(result.stdout).coverage.complete, false);
});
test("permission errors fail in the actual CLI", {
  skip: !process.getuid || process.getuid() === 0,
}, (t) => {
  const root = fixture(t);
  const file = path.join(root, "package.json");
  fs.writeFileSync(file, SOURCE);
  fs.chmodSync(file, 0);
  try {
    const result = run([root, "--json"], root);
    assert.equal(result.status, 2);
    assert.equal(JSON.parse(result.stdout).coverage.complete, false);
  } finally { fs.chmodSync(file, 0o600); }
  fs.chmodSync(root, 0);
  try { assert.equal(run([root, "--json"], os.tmpdir()).status, 2); }
  finally { fs.chmodSync(root, 0o700); }
});

test("invalid manifests are incomplete; optional listener probe is separate", async (t) => {
  const root = fixture(t);
  const file = path.join(root, "package.json");
  for (const data of ["{broken", "null", "[]"]) {
    fs.writeFileSync(file, data);
    const result = run([file, "--json"], root);
    assert.equal(result.status, 2);
    const report = JSON.parse(result.stdout);
    assert.equal(report.coverage.complete, false);
    assert(report.coverage.errors.some((error) => error.reason === "parse-error"));
  }
  fs.unlinkSync(file);
  const childProcess = require(["child", "process"].join("_"));
  const original = childProcess.execSync;
  childProcess.execSync = () => { throw new Error("fixture probe unavailable"); };
  try {
    const report = await scan(root);
    assert.equal(report.coverage.complete, true);
    assert.equal(report.coverage.listenerInspection, "unavailable");
  } finally { childProcess.execSync = original; }
});

