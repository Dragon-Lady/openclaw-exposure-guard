#!/usr/bin/env node
"use strict";

const path = require("path");
const { scan } = require("../src/scanner");

const args = process.argv.slice(2);

function help() {
  console.log(`OpenClaw Exposure Guard

Usage:
  openclaw-exposure-guard [target]
  openclaw-exposure-guard --json [target]

Read-only local checker for OpenClaw installs, vulnerable versions, risky
exposure settings, plugin/hook install-surface risks, and credential-adjacent
paths. It does not collect, save, or transmit user data.

Options:
  --json     Print JSON instead of text
  --help     Show this help
`);
}

if (args.includes("--help") || args.includes("-h")) {
  help();
  process.exit(0);
}

const json = args.includes("--json");
const targetArg = args.find((arg) => !arg.startsWith("-")) || ".";
const target = path.resolve(targetArg);

scan(target)
  .then((report) => {
    if (json) {
      console.log(JSON.stringify(report, null, 2));
      return;
    }
    printText(report);
  })
  .catch((error) => {
    console.error(`openclaw-exposure-guard error: ${error.message}`);
    process.exitCode = 2;
  });

function printText(report) {
  console.log("OpenClaw Exposure Guard");
  console.log(`Target: ${report.target}`);
  console.log(`Risk: ${report.risk}`);
  console.log(`Scanned: ${report.scannedFiles} files, ${report.packageManifests} package manifests`);
  console.log(`Findings: ${report.findings.length}`);
  console.log("");

  if (report.findings.length === 0) {
    console.log("No known OpenClaw exposure or vulnerable-version indicators were found by this guard.");
  } else {
    for (const finding of report.findings) {
      console.log(`[${finding.severity}] ${finding.type}: ${finding.message}`);
      if (finding.path) console.log(`  path: ${finding.path}`);
      if (finding.detail) console.log(`  detail: ${finding.detail}`);
      if (finding.source) console.log(`  source: ${finding.source}`);
    }
  }

  console.log("");
  console.log("Privacy: this tool reads local metadata only. It does not collect, save, upload, or transmit user data.");
  console.log("Caution: a clean result does not prove the host is clean; it only covers the checks this guard knows about.");
}
