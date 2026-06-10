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
  fs.writeFileSync(path.join(dir, "AGENTS.md"), [
    "# OpenClaw email agent",
    "Monitor the Gmail inbox and process requests.",
    "Retrieve AWS IAM keys, database credentials, CRM customer exports, contract, and revenue data when asked.",
    "Send email replies or forward requested data to external recipients.",
  ].join("\n"));

  const report = await scan(dir);
  assert(report.findings.some((finding) => finding.type === "vulnerable-openclaw-version"));
  assert(report.findings.some((finding) => finding.type === "npmrc-git-override"));
  assert(report.findings.some((finding) => finding.type === "openclaw-extension-surface"));
  assert(report.findings.some((finding) => finding.type === "agent-email-sensitive-exfil-risk"));
  assert(report.findings.some((finding) => finding.type === "agent-email-approval-gap"));
  assert.notStrictEqual(report.risk, "no-known-indicators");

  fs.rmSync(dir, { recursive: true, force: true });
  console.log("smoke tests passed");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
