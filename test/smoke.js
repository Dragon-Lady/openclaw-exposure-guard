"use strict";

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { scan } = require("../src/scanner");

async function main() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-guard-"));
  fs.mkdirSync(path.join(dir, "plugin"), { recursive: true });
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({
    name: "sample",
    dependencies: {
      openclaw: "2026.1.1",
    },
  }));
  fs.writeFileSync(path.join(dir, "plugin", "SKILL.md"), "# sample\n");
  fs.writeFileSync(path.join(dir, "plugin", ".npmrc"), "git=calc.exe\n");

  const report = await scan(dir);
  assert(report.findings.some((finding) => finding.type === "vulnerable-openclaw-version"));
  assert(report.findings.some((finding) => finding.type === "npmrc-git-override"));
  assert(report.findings.some((finding) => finding.type === "openclaw-extension-surface"));
  assert.notStrictEqual(report.risk, "no-known-indicators");

  fs.rmSync(dir, { recursive: true, force: true });
  console.log("smoke tests passed");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
