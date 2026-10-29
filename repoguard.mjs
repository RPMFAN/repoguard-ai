#!/usr/bin/env node
/**
 * RepoGuard AI — heuristic security & CI-reliability scanner (MVP, v1.1.0)
 *
 * What it is: a fast pattern-based first pass. Every finding is a LEAD that a
 * reviewer must confirm; it is not proof of a vulnerability. Paid audits add a
 * manual review of each lead and written fix suggestions.
 *
 * Usage: node repoguard.mjs <repoDir> [--name "<label>"] [--out <dir>]
 * Writes: audit-report.json, audit-report.md into --out (default: cwd)
 */
import fs from "node:fs";
import path from "node:path";

const MAX_PER_RULE_PER_FILE = 3;

const RULES = [
  { id: "RG-SEC-001", severity: "HIGH", category: "Code injection",
    pattern: /\beval\s*\(|new Function\s*\(|setTimeout\s*\(\s*["'`]/,
    description: "Dynamic code evaluation; dangerous if any user input reaches it.",
    remediation: "Remove eval/new Function; parse input explicitly (e.g. JSON.parse, parseInt) and validate it." },
  { id: "RG-SEC-002", severity: "HIGH", category: "Command injection",
    pattern: /child_process\.exec\(|\bexecSync\(|subprocess\.(Popen|call|run)\([^)]*shell\s*=\s*True|os\.system\(|exec\.Command\("(sh|bash)"/,
    description: "Shell command execution; risk of command injection if arguments are not sanitized.",
    remediation: "Use argument arrays (execFile/spawn, subprocess without shell=True) and an allowlist of inputs." },
  { id: "RG-SEC-003", severity: "HIGH", category: "Hard-coded secret",
    pattern: /(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*["'][^"'\s]{6,}["']|AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC )?PRIVATE KEY-----/i,
    description: "Possible credential committed to source control.",
    remediation: "Move secrets to environment variables or a secret manager and rotate the exposed value." },
  { id: "RG-SEC-004", severity: "MEDIUM", category: "Weak cryptography",
    pattern: /createHash\(\s*["'](md5|sha1)["']|hashlib\.(md5|sha1)\(|crypto\/md5|Math\.random\(\).*(token|secret|password|id)/i,
    description: "Weak hash or non-cryptographic randomness used where security may depend on it.",
    remediation: "Use bcrypt/argon2 for passwords, SHA-256+ for integrity, crypto.randomBytes for tokens." },
  { id: "RG-SEC-005", severity: "MEDIUM", category: "Database injection",
    pattern: /\$where|(query|execute)\s*\(\s*["'`][^"'`]*(SELECT|INSERT|UPDATE|DELETE)[^"'`]*["'`]\s*\+|\$\{[^}]+\}[^`]*(FROM|WHERE)/i,
    description: "Query built from string concatenation or $where; risk of SQL/NoSQL injection.",
    remediation: "Use parameterized queries / query builders and never pass user input into $where." },
  { id: "RG-SEC-006", severity: "MEDIUM", category: "Insecure session / cookie config",
    pattern: /httpOnly\s*:\s*false|secure\s*:\s*false|rejectUnauthorized\s*:\s*false|verify\s*=\s*False|InsecureSkipVerify:\s*true/,
    description: "Cookie or TLS security flag explicitly disabled.",
    remediation: "Enable httpOnly/secure cookies and TLS certificate verification in production." },
  { id: "RG-OPS-007", severity: "MEDIUM", category: "Container isolation",
    pattern: /network_mode:\s*["']?host|privileged:\s*true|--net(work)?=host|--privileged/i,
    description: "Host networking or privileged container weakens isolation.",
    remediation: "Use explicit port mappings and drop privileges/capabilities." },
  { id: "RG-OPS-008", severity: "LOW", category: "CI supply chain",
    pattern: /uses:\s*[\w.-]+\/[\w.-]+@(main|master|latest)\b|curl[^|\n]*\|\s*(ba)?sh/,
    description: "CI step pinned to a moving branch, or a pipe-to-shell install.",
    remediation: "Pin actions to a commit SHA and download-then-verify scripts before running them." },
  { id: "RG-REL-009", severity: "LOW", category: "Network call without visible timeout",
    pattern: /\bfetch\(|axios\.(get|post|put|delete)\(|http\.Get\(|requests\.(get|post)\((?![^)]*timeout)/,
    description: "Outbound network call; check that a timeout and retry limit exist.",
    remediation: "Set explicit timeouts (AbortSignal.timeout, requests timeout=) and bounded retries." },
];

const EXT = /\.(rs|go|ts|tsx|js|jsx|mjs|cjs|py|sol|yml|yaml|sh|env)$/i;
const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", "target", "vendor", "coverage", "__pycache__"]);

function walkFiles(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(e.name)) continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) walkFiles(full, out);
    else if (EXT.test(e.name) || /^Dockerfile/i.test(e.name) || /^docker-compose/i.test(e.name)) {
      if (/\.min\.js$/i.test(e.name)) continue;
      if (fs.statSync(full).size > 1_000_000) continue;
      out.push(full);
    }
  }
  return out;
}

export function scanRepository(targetDir, repoName = path.basename(path.resolve(targetDir))) {
  const files = walkFiles(targetDir);
  const findings = [];
  for (const file of files) {
    const lines = fs.readFileSync(file, "utf8").split("\n");
    const rel = path.relative(targetDir, file);
    for (const rule of RULES) {
      let n = 0;
      for (let i = 0; i < lines.length && n < MAX_PER_RULE_PER_FILE; i++) {
        if (lines[i].length > 2000 || /^\s*(\/\/|#|\*|\/\*)/.test(lines[i])) continue;
        if (rule.pattern.test(lines[i])) {
          n++;
          findings.push({ ruleId: rule.id, severity: rule.severity, category: rule.category,
            file: rel, line: i + 1, snippet: lines[i].trim().slice(0, 160),
            description: rule.description, remediation: rule.remediation, status: "unconfirmed lead" });
        }
      }
    }
  }
  const count = (s) => findings.filter((f) => f.severity === s).length;
  const order = { HIGH: 0, MEDIUM: 1, LOW: 2 };
  findings.sort((a, b) => order[a.severity] - order[b.severity] || a.file.localeCompare(b.file) || a.line - b.line);
  return { tool: "RepoGuard AI heuristic scanner v1.1.0", repoName, scannedAt: new Date().toISOString(),
    filesScanned: files.length, totalFindings: findings.length,
    high: count("HIGH"), medium: count("MEDIUM"), low: count("LOW"),
    note: "Automated pattern matches. Each item is a lead to be confirmed by manual review; false positives are expected.",
    findings };
}

function arg(flag, def) { const i = process.argv.indexOf(flag); return i > 0 ? process.argv[i + 1] : def; }
const isMain = import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith("repoguard.mjs");
if (isMain) {
  const target = process.argv[2];
  if (!target || target.startsWith("--") || !fs.existsSync(target)) {
    console.error('Usage: node repoguard.mjs <repoDir> [--name "<label>"] [--out <dir>]');
    process.exit(2);
  }
  const outDir = arg("--out", process.cwd());
  const report = scanRepository(target, arg("--name", undefined));
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, "audit-report.json"), JSON.stringify(report, null, 2));
  const esc = (s) => s.replace(/\|/g, "\\|").replace(/`/g, "'");
  const md = [
    `# RepoGuard AI — automated scan report`,
    `- **Target:** \`${report.repoName}\``,
    `- **Scanned at (UTC):** \`${report.scannedAt}\``,
    `- **Files scanned:** ${report.filesScanned} · **Leads:** ${report.totalFindings} (High ${report.high}, Medium ${report.medium}, Low ${report.low})`,
    ``,
    `> ${report.note}`,
    ``,
    `| Rule | Severity | Location | Category | Matched code | Suggested fix |`,
    `| :--- | :---: | :--- | :--- | :--- | :--- |`,
    ...report.findings.map((f) => `| ${f.ruleId} | ${f.severity} | \`${f.file}:${f.line}\` | ${f.category} | \`${esc(f.snippet)}\` | ${f.remediation} |`),
  ];
  fs.writeFileSync(path.join(outDir, "audit-report.md"), md.join("\n") + "\n");
  console.log(`[RepoGuard] ${report.repoName}: ${report.filesScanned} files, ${report.totalFindings} leads (H${report.high}/M${report.medium}/L${report.low}) -> ${outDir}`);
}
