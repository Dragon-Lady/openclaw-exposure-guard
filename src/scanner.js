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

const AGENT_POLICY_NAMES = new Set([
  "agents.md",
  "agent.md",
  "agents.json",
  "agent.json",
  "openclaw.agents.md",
  "openclaw.agents.json",
]);

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
      const normalizedDir = full.replace(/\\/g, "/");
      if (normalizedDir.endsWith(".openclaw/.cache/runtime") || normalizedDir.includes(".openclaw/.cache/runtime/")) {
        add(report, "critical", "memtensor-runtime-path", `Path matches a MemTensor runtime directory. ${MEMTENSOR_NOTE}`, full);
      }
      const underOpenClawState = normalizedDir.includes("/.openclaw/");
      if (!IGNORE_DIRS.has(entry.name) || underOpenClawState) walk(full, report, onFile);
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
  inspectMemtensor(file, report);
  if (lower === ".npmrc") inspectNpmrc(file, report);
  if (CONFIG_NAMES.has(lower)) inspectConfig(file, report);
  if (AGENT_POLICY_NAMES.has(lower)) inspectAgentPolicy(file, report);
  if (lower === "skill.md" || lower === "hook.md") {
    add(report, "info", "openclaw-extension-surface", "OpenClaw skill or hook metadata found; review this directory before trusting it.", file);
  }
  if (CREDENTIAL_ADJACENT.includes(lower)) {
    add(report, "info", "credential-adjacent-path", "Credential-adjacent file name observed. The guard reports the path only and does not read or print secrets.", file);
  }
}

function inspectAgentPolicy(file, report) {
  let text = "";
  try {
    text = fs.readFileSync(file, "utf8");
  } catch {
    return;
  }

  const emailAccess = /\b(gmail|google\s+workspace|inbox|email|mailbox)\b/i.test(text);
  const outboundMail = /\b(send|forward|reply|email)\b.{0,80}\b(email|mail|message|recipient|external)\b/i.test(text);
  const sensitiveAccess = /\b(aws|iam|ssh|database|db\s+credential|credential|secret|token|crm|customer\s+export|customer\s+records?|contract|revenue|qbr)\b/i.test(text);
  const identityGate = /\b(verify|validate|confirm|authenticate)\b.{0,80}\b(sender|identity|requester|colleague|employee|domain|address)\b/i.test(text);
  const approvalGate = /\b(human|user|operator|manager|admin)\b.{0,80}\b(approval|approve|confirm|consent|authorize)\b/i.test(text);
  const firstTouchGate = /\b(first[-\s]?time|new|unknown|unverified|external)\b.{0,80}\b(recipient|sender|address|domain|contact|communication)\b/i.test(text);

  if (emailAccess && outboundMail && sensitiveAccess) {
    add(
      report,
      "high",
      "agent-email-sensitive-exfil-risk",
      "Agent policy combines inbox/email access, outbound mail capability, and sensitive-data access. Require identity verification and human approval before sensitive or external sends.",
      file,
      "Varonis/BleepingComputer OpenClaw phishing research showed this architecture can leak credentials or CRM exports under plausible urgent requests.",
    );
  }

  if (emailAccess && outboundMail && !(identityGate && approvalGate && firstTouchGate)) {
    add(
      report,
      "medium",
      "agent-email-approval-gap",
      "Email-capable agent policy does not clearly require sender identity verification, human approval, and first-time/external recipient gating.",
      file,
    );
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

  inspectMemtensorPackage(pkg, file, report);

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
      add(report, "info", "public-listener", "A TCP listener is bound to all interfaces. Confirm OpenClaw gateway/agent surfaces are not public.", null, `local=${localAddress}`);
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

const MEMTENSOR_PLUGIN = "@memtensor/memos-cloud-openclaw-plugin";
const MEMTENSOR_BAD_VERSIONS = new Set(["0.1.21", "0.1.23", "0.1.25"]);
const MEMTENSOR_NOTE = "MemTensor supplychain.local (Aikido, Socket, SafeDep): exact npm versions 0.1.21, 0.1.23, and 0.1.25 are malicious. 0.1.22 and 0.1.24 are clean. It runs on invocation, not install-only. Do not load this plugin. If it ran, preserve evidence and treat credentials reachable from the host or CI runner as exposed; rotate them from a clean machine. Notify-only.";
const MEMTENSOR_STRINGS = ["sckit.runtime.v1", "supplychain.local", "SCKIT_EVENT_TEXT", ".sckit", "cloud-openclaw-semi-nuclear"];
const MEMTENSOR_TEXT_EXTENSIONS = new Set([".js", ".cjs", ".mjs", ".json", ".md", ".txt", ".yml", ".yaml", ".toml", ".py"]);

function inspectMemtensorPackage(pkg, file, report) {
  const groups = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];
  for (const group of groups) {
    const spec = pkg[group] && pkg[group][MEMTENSOR_PLUGIN];
    if (typeof spec !== "string") continue;
    const versions = Array.from(spec.matchAll(/(\d+)\.(\d+)\.(\d+)/g), (match) => match.slice(1).map((part) => Number.parseInt(part, 10)));
    if (versions.length === 0) {
      add(report, "high", "memtensor-plugin-unpinned", `${group} names ${MEMTENSOR_PLUGIN} without a dotted version. Only 0.1.21, 0.1.23, and 0.1.25 are reported malicious. ${MEMTENSOR_NOTE}`, file, spec);
      continue;
    }
    for (const version of versions) {
      const dotted = version.join(".");
      if (MEMTENSOR_BAD_VERSIONS.has(dotted)) {
        add(report, "critical", "memtensor-plugin-version", `${group} requests ${MEMTENSOR_PLUGIN} ${dotted}, one of the reported malicious versions 0.1.21, 0.1.23, and 0.1.25. ${MEMTENSOR_NOTE}`, file, dotted);
      }
    }
  }
}

function inspectMemtensor(file, report) {
  const normalized = file.replace(/\\/g, "/");
  if (normalized.includes(".openclaw/.cache/runtime") || /(^|\/)sckit(\.exe)?$/i.test(normalized)) {
    add(report, "critical", "memtensor-runtime-path", `Path matches a MemTensor runtime artifact. ${MEMTENSOR_NOTE}`, file);
  }

  if (!MEMTENSOR_TEXT_EXTENSIONS.has(path.extname(file).toLowerCase())) return;
  let text = "";
  try {
    const stat = fs.statSync(file);
    if (stat.size > 1024 * 1024) return;
    text = fs.readFileSync(file, "utf8");
  } catch {
    return;
  }
  for (const indicator of MEMTENSOR_STRINGS) {
    if (text.includes(indicator)) {
      add(report, "critical", "memtensor-indicator", `File references MemTensor indicator ${indicator}. ${MEMTENSOR_NOTE}`, file, indicator);
    }
  }
}

function compareTriple(left, right) {
  for (let i = 0; i < 3; i += 1) {
    if (left[i] > right[i]) return 1;
    if (left[i] < right[i]) return -1;
  }
  return 0;
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
