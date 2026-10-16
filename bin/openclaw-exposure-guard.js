#!/usr/bin/env node
"use strict";

const path = require("path");
const { scan } = require("../src/scanner");

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

Exit codes: 0 no medium/high/critical findings; 1 findings requiring review;
2 usage/runtime error or incomplete target scan (takes precedence over 1).
`);
}

async function main(args) {
  try {
    let json = false;
    let showHelp = false;
    let target;
    for (const arg of args) {
      if (arg === "--help" || arg === "-h") showHelp = true;
      else if (arg === "--json") json = true;
      else if (arg.startsWith("-")) throw new Error(`Unknown argument: ${arg}`);
      else if (target !== undefined) throw new Error("Only one target path may be specified");
      else target = arg;
    }
    if (showHelp) { help(); return 0; }
    const report = await scan(path.resolve(target || "."));
    if (json) console.log(JSON.stringify(report, null, 2));
    else printText(report);
    if (!report.coverage.complete) return 2;
    return ["medium", "high", "critical"].includes(report.risk) ? 1 : 0;
  } catch (error) {
    console.error(`openclaw-exposure-guard error: ${error.message}`);
    return 2;
  }
}

function printText(report) {
  console.log("OpenClaw Exposure Guard");
  console.log(`Target: ${report.target}`);
  console.log(`Risk: ${report.risk}`);
  console.log(`Scanned: ${report.scannedFiles} files, ${report.packageManifests} package manifests`);
  console.log(`Findings: ${report.findings.length}`);
  if (!report.coverage.complete) {
    console.log("INCOMPLETE: some inputs could not be inspected; this is not a passed scan.");
    for (const error of report.coverage.errors) console.log(`  ${error.reason}: ${error.path}`);
  }
  console.log(`Optional local listener inspection: ${report.coverage.listenerInspection}`);
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

if (require.main === module) main(process.argv.slice(2)).then((code) => { process.exitCode = code; });
module.exports = { main };
