"use strict";

const childProcess = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const advisories = require("../data/advisories.json");

const IGNORE_DIRS = new Set([
  ".git",
  "node_modules",
  ".cache",
  ".next",
  "dist",
  "build",
  "coverage",
  "__pycache__",
]);

const CONFIG_NAMES = new Set([
  "openclaw.json",
  "openclaw.config.json",
  "config.json",
  "settings.json",
  ".env",
  ".env.local",
]);

const CREDENTIAL_ADJACENT = [
  ".env",
  ".npmrc",
  ".pypirc",
  "id_rsa",
  "id_ed25519",
  "credentials",
  "credentials.json",
  "service-account.json",
  "token.json",
];

async function scan(target) {
  const report = {
    target,
    risk: "no-known-indicators",
    scannedFiles: 0,
    packageManifests: 0,
    findings: [],
  };

  walk(target, report, (file) => inspectFile(file, report));
  inspectListening(report);
  rank(report);
  return report;
}

function walk(root, report, onFile) {
  let entries;
  try {
    entries = fs.readdirSync(root, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    const full = path.join(root, entry.name);
    if (entry.isDirectory()) {
      if (!IGNORE_DIRS.has(entry.name)) walk(full, report, onFile);
      continue;
    }
    if (!entry.isFile()) continue;
    report.scannedFiles += 1;
    onFile(full);
  }
}

function inspectFile(file, report) {
  const base = path.basename(file);
  const lower = base.toLowerCase();

  if (lower === "package.json") inspectPackage(file, report);
  if (lower === ".npmrc") inspectNpmrc(file, report);
  if (CONFIG_NAMES.has(lower)) inspectConfig(file, report);
  if (lower === "skill.md" || lower === "hook.md") {
    add(report, "info", "openclaw-extension-surface", "OpenClaw skill or hook metadata found; review this directory before trusting it.", file);
  }
  if (CREDENTIAL_ADJACENT.includes(lower)) {
    add(report, "info", "credential-adjacent-path", "Credential-adjacent file name observed. The guard reports the path only and does not read or print secrets.", file);
  }
}

function inspectPackage(file, report) {
  report.packageManifests += 1;

  let pkg;
  try {
    pkg = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    add(report, "medium", "malformed-package-json", "package.json could not be parsed.", file);
    return;
  }

  if (pkg.name === "openclaw") {
    add(report, "info", "openclaw-package", `OpenClaw package manifest found at version ${pkg.version || "unknown"}.`, file);
    inspectVersion(pkg.version, file, report);
  }

  const depVersion = dependencyVersion(pkg, "openclaw");
  if (depVersion) {
    add(report, "info", "openclaw-dependency", `Project depends on openclaw version spec ${depVersion}.`, file);
    inspectVersion(depVersion, file, report);
  }

  if (pkg.openclaw) {
    add(report, "info", "openclaw-plugin-or-hook", "Manifest declares OpenClaw plugin/hook metadata; review package source before installing or enabling.", file);
  }

  const deps = Object.assign({}, pkg.dependencies, pkg.optionalDependencies);
  for (const [name, spec] of Object.entries(deps)) {
    if (typeof spec === "string" && spec.startsWith("git")) {
      add(report, "medium", "git-dependency", `Git dependency observed: ${name}. Review before OpenClaw plugin/hook installation.`, file);
    }
  }
}

function inspectVersion(version, file, report) {
  const parsed = normalizeVersion(version);
  if (!parsed) return;

  for (const advisory of advisories) {
    if (versionLessThan(parsed, advisory.fixedVersion)) {
      add(
        report,
        advisory.severity,
        "vulnerable-openclaw-version",
        `OpenClaw ${version} is below fixed version ${advisory.fixedVersion} for ${advisory.id}.`,
        file,
        advisory.title,
        advisory.url,
      );
    }
  }
}

function inspectNpmrc(file, report) {
  let text = "";
  try {
    text = fs.readFileSync(file, "utf8");
  } catch {
    return;
  }
  if (/^\s*git\s*=/mi.test(text)) {
    add(report, "high", "npmrc-git-override", ".npmrc overrides the git executable. This is risky for local OpenClaw plugin/hook install flows.", file);
  }
}

function inspectConfig(file, report) {
  let text = "";
  try {
    text = fs.readFileSync(file, "utf8");
  } catch {
    return;
  }

  if (/\b(0\.0\.0\.0|\[::\]|::)\b/.test(text)) {
    add(report, "high", "public-bind-config", "Config appears to bind a service to all interfaces.", file);
  }
  if (/\b(auth|authentication|requireAuth)\b\s*[:=]\s*(false|0|off|disabled)/i.test(text)) {
    add(report, "high", "weak-auth-config", "Config appears to disable authentication.", file);
  }
  if (/\b(allow|allowed)\w*\b\s*[:=]\s*(\*|\"?\*\"?)/i.test(text)) {
    add(report, "medium", "broad-allow-config", "Config appears to allow all origins/hosts/tools.", file);
  }
}

function inspectListening(report) {
  const command = os.platform() === "win32" ? "netstat -ano -p tcp" : "sh -c \"ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null\"";
  let output = "";
  try {
    output = childProcess.execSync(command, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 3000 });
  } catch {
    return;
  }

  for (const line of output.split(/\r?\n/)) {
    const localAddress = localBindAddress(line);
    if (localAddress && /^(0\.0\.0\.0|\[::\]|:::)/.test(localAddress) && /\bLISTEN(?:ING)?\b/i.test(line)) {
      add(report, "info", "public-listener", "A TCP listener is bound to all interfaces. Confirm OpenClaw gateway/agent surfaces are not public.", null, line.trim());
    }
  }
}

function localBindAddress(line) {
  const trimmed = line.trim();
  if (!trimmed) return null;

  const parts = trimmed.split(/\s+/);
  if (parts[0] === "TCP" || parts[0] === "tcp" || parts[0] === "tcp6") {
    return parts[1] || null;
  }
  if (parts[0] === "LISTEN") {
    return parts[3] || null;
  }
  return null;
}

function dependencyVersion(pkg, name) {
  for (const group of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
    if (pkg[group] && pkg[group][name]) return pkg[group][name];
  }
  return null;
}

function normalizeVersion(version) {
  if (typeof version !== "string") return null;
  const match = version.match(/(\d{4})\.(\d{1,2})\.(\d{1,2})/);
  if (!match) return null;
  return match.slice(1).map((part) => Number.parseInt(part, 10));
}

function versionLessThan(left, right) {
  const parsedRight = normalizeVersion(right);
  if (!parsedRight) return false;
  for (let i = 0; i < 3; i += 1) {
    if (left[i] < parsedRight[i]) return true;
    if (left[i] > parsedRight[i]) return false;
  }
  return false;
}

function add(report, severity, type, message, file, detail, source) {
  report.findings.push({ severity, type, message, path: file || undefined, detail: detail || undefined, source: source || undefined });
}

function rank(report) {
  const order = ["no-known-indicators", "info", "medium", "high", "critical"];
  let risk = "no-known-indicators";
  for (const finding of report.findings) {
    if (order.indexOf(finding.severity) > order.indexOf(risk)) risk = finding.severity;
  }
  report.risk = risk;
}

module.exports = { scan };
