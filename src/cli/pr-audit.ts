import { LiteScanner } from '../core/lite/lite_scanner';
import { createHash } from 'crypto';
import { readFileSync, existsSync, writeFileSync } from 'fs';
import { execFileSync } from 'child_process';

interface PrAuditOptions {
  repo: string;
  prNumber: number;
  diffFile?: string;
  diff?: string;
  author?: string;
  outputFile?: string;
  comment?: boolean;
  checkRun?: boolean;
}

const RISK_EXPLANATIONS: Record<string, string> = {
  UNSAFE_EVAL: 'Executes arbitrary code from a string. If an attacker controls the input, they can execute system commands (RCE).',
  OS_CAPABILITY: 'Imports OS process-spawning capabilities (spawn, exec, execSync). Allows running system commands — escalates to RCE if arguments are dynamic.',
  NETWORK_ACTIVITY: 'Makes outbound HTTP/HTTPS requests. Can exfiltrate secrets, download payloads, or phone home to a C2 server.',
  ENV_ACCESS: 'Reads environment variables that may hold tokens, API keys, or production secrets. If compromised, all env-scoped secrets are exfiltrable.',
  POTENTIAL_SECRET: 'Base64-decodes data — a common obfuscation technique for hiding payloads, credentials, or configuration.',
  DOM_INJECTION: 'Inserts raw HTML into the DOM without sanitization. Enables Cross-Site Scripting (XSS): an attacker can inject arbitrary scripts in the user session.',
  SANDBOX_ESCAPE: 'Executes code inside a VM/sandbox context. May allow sandbox escape if the sandboxed code accesses prototypes or globals.',
  SECRET_ENV_FILE: 'Exposes a .env file in the repository. Contains environment secrets such as tokens, API keys, and passwords.',
  SECRET_CREDENTIALS_FILE: 'Exposes a credential or service-account file. Grants direct access to cloud services.',
  SECRET_SSH_KEY_FILE: 'Exposes an SSH private key. Grants password-less SSH access to servers.',
  SECRET_AWS_KEY_ID: 'Exposes an AWS Access Key ID in plain text. Enables AWS API authentication.',
  SECRET_AWS_SECRET: 'Exposes an AWS Secret Access Key. Combined with the Key ID, grants full AWS API access.',
  SECRET_GITHUB_TOKEN: 'Exposes a GitHub personal access token. Grants access to repositories, Actions, and the GitHub API.',
  SECRET_STRIPE_KEY: 'Exposes a Stripe live API key. Enables charges and access to payment data.',
  SECRET_SENDGRID_KEY: 'Exposes a SendGrid API key. Enables impersonated email sending.',
  SECRET_SSH_KEY: 'Exposes a private cryptographic key. Enables data signing and identity impersonation.',
  SECRET_SLACK_TOKEN: 'Exposes a Slack API token. Grants access to channels, messages, and files.',
  SECRET_SLACK_WEBHOOK: 'Exposes a Slack webhook URL. Enables posting fake messages to channels.',
  SECRET_JWT: 'Exposes a JWT signing secret. Enables forging valid authentication tokens.',
  SECRET_DB_PASSWORD: 'Exposes a database password. Grants direct database access.',
  SECRET_ENCRYPTION_KEY: 'Exposes an encryption key. Enables decrypting protected data.',
  SECRET_API_KEY: 'Exposes a generic API key. Grants access to external services.',
  DARKNET_ADDRESS: 'References a .onion darknet address. May indicate communication with darknet services.',
  SECRET_HARDCODED_PASSWORD: 'Hardcodes a password in source code. Exposed to everyone with repository access.',
  SECRET_HARDCODED_TOKEN: 'Hardcodes an authentication token in source code. Exposed to everyone with repository access.',
};

interface FindingOutput {
  type: string;
  intent: string;
  file: string;
  line: number;
  severity: string;
  description: string;
  snippet: string;
  risk: string;
}

interface PrAuditResult {
  scanId: string;
  repo: string;
  prNumber: number;
  author: string;
  findings: FindingOutput[];
  filesAnalyzed: number;
  correlations: number;
  threatIntel: {
    knownAuthor: boolean;
    authorThreatCount: number;
    authorRiskLevel: string | null;
    patternMatches: number;
  };
  verdict: {
    band: string;
    decision: string;
    summary: string;
  };
  contentHash: string;
  error?: string;
}

function parseUnifiedDiff(raw: string): { filename: string; patch: string }[] {
  const parts = raw.split(/(?=^diff --git )/m);
  const files: { filename: string; patch: string }[] = [];

  for (const part of parts) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const m = trimmed.match(/^diff --git a\/\S+ b\/(.+)$/m);
    if (m) {
      files.push({ filename: m[1].trim(), patch: trimmed });
    }
  }

  if (files.length === 0 && raw.trim()) {
    const m = raw.match(/^\+\+\+ b\/(.+)$/m);
    const filename = m ? m[1].trim() : 'PR.diff';
    files.push({ filename, patch: raw });
  }

  return files;
}

function runGh(args: string[], input?: string): string {
  try {
    const opts: any = {
      timeout: 30000,
      encoding: 'utf-8',
      maxBuffer: 50 * 1024 * 1024,
      windowsHide: true,
    };
    if (input !== undefined) {
      opts.input = input;
    }
    return execFileSync('gh', args, opts).trim();
  } catch (e: any) {
    return e.stdout?.trim() || e.stderr?.trim() || e.message;
  }
}

function correlateThreats(author: string): {
  knownAuthor: boolean;
  authorThreatCount: number;
  authorRiskLevel: string | null;
  patternMatches: number;
} {
  try {
    const dbPath = require('path').join(
      process.env.HOME || process.env.USERPROFILE || '.',
      '.sentinel', 'threats.db'
    );
    if (!existsSync(dbPath)) {
      return { knownAuthor: false, authorThreatCount: 0, authorRiskLevel: null, patternMatches: 0 };
    }
    const Database = require('better-sqlite3');
    const db = new Database(dbPath);
    db.pragma('journal_mode = WAL');

    const authorRow = db.prepare('SELECT * FROM threat_authors WHERE author = ?').get(author);
    const knownAuthor = !!authorRow;
    const authorThreatCount = authorRow ? (authorRow as any).threat_count || 0 : 0;
    const authorRiskLevel = authorRow ? (authorRow as any).risk_level || null : null;

    const threats = db.prepare('SELECT COUNT(*) as cnt FROM threats WHERE author = ?').get(author);
    const patternMatches = threats ? (threats as any).cnt || 0 : 0;

    db.close();
    return { knownAuthor, authorThreatCount, authorRiskLevel, patternMatches };
  } catch {
    return { knownAuthor: false, authorThreatCount: 0, authorRiskLevel: null, patternMatches: 0 };
  }
}

function verdictAction(decision: string, band: string): string {
  if (decision === 'BLOCK') {
    return `**Action: DO NOT MERGE** — Risk band ${band}. The changeset is rejected.`;
  }
  if (decision === 'REVIEW') {
    return `**Action: REQUIRES HUMAN REVIEW** — Risk band ${band}. A human must evaluate each finding before merging.`;
  }
  return `**Action: SAFE TO PROCEED** — No security threats detected.`;
}

function buildMarkdown(result: PrAuditResult): string {
  const headerIcon = result.verdict.decision === 'BLOCK' ? '🔴' :
    result.verdict.decision === 'REVIEW' ? '🟡' : '🟢';
  const headerText = result.verdict.decision === 'BLOCK' ? 'Blocked' :
    result.verdict.decision === 'REVIEW' ? 'Needs Review' : 'Approved';

  let body = `## ${headerIcon} Sentinel PR Audit — ${headerText}\n\n`;

  body += `${verdictAction(result.verdict.decision, result.verdict.band)}\n\n`;

  body += `| | |\n|---|---|\n`;
  body += `| **Repository** | \`${result.repo}\` |\n`;
  body += `| **PR** | #${result.prNumber} by \`${result.author}\` |\n`;
  body += `| **Files Analyzed** | ${result.filesAnalyzed} |\n`;
  body += `| **Total Findings** | ${result.findings.length} |\n`;
  body += `| **Risk Band** | ${result.verdict.band} |\n`;
  body += `| **Decision** | ${result.verdict.decision} |\n`;

  if (result.threatIntel.knownAuthor) {
    body += `| **Author Risk** | ${result.threatIntel.authorRiskLevel || 'UNKNOWN'} (${result.threatIntel.authorThreatCount} prior threats) |\n`;
  }

  body += '\n';

  if (result.findings.length === 0) {
    body += '### ✅ No security threats detected\n\n';
    body += `---\n`;
    body += `_Scanned by Sentinel CLI | Hash: \`${result.contentHash.substring(0, 12)}\`_`;
    return body;
  }

  const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  for (const sev of severities) {
    const sevFindings = result.findings.filter(f => f.severity === sev);
    if (sevFindings.length === 0) continue;

    const icon = sev === 'CRITICAL' ? '🔴' : sev === 'HIGH' ? '🟠' : sev === 'MEDIUM' ? '🟡' : '🔵';
    body += `### ${icon} ${sev} (${sevFindings.length})\n\n`;

    for (let i = 0; i < sevFindings.length; i++) {
      const f = sevFindings[i];
      const snippet = (f.snippet || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      body += `<details${i === 0 ? ' open' : ''}>\n`;
      body += `<summary><code>${f.file}:${f.line}</code> — <strong>${f.type}</strong></summary>\n\n`;
      body += `**Detection:** ${f.description}  \n`;
      body += `**Risk:** ${f.risk}  \n\n`;
      body += '```\n' + snippet + '\n```\n\n';
      body += `</details>\n\n`;
    }
  }

  body += `---\n`;
  body += `_Scanned by Sentinel CLI | Hash: \`${result.contentHash.substring(0, 12)}\`_`;

  return body;
}

export async function runPrAudit(options: PrAuditOptions): Promise<PrAuditResult> {
  let rawDiff: string;

  if (options.diff) {
    rawDiff = options.diff;
  } else if (options.diffFile) {
    if (!existsSync(options.diffFile)) {
      return {
        scanId: '',
        repo: options.repo,
        prNumber: options.prNumber,
        author: options.author || 'unknown',
        findings: [],
        filesAnalyzed: 0,
        correlations: 0,
        threatIntel: { knownAuthor: false, authorThreatCount: 0, authorRiskLevel: null, patternMatches: 0 },
        verdict: { band: 'ERROR', decision: 'BLOCK', summary: `Diff file not found: ${options.diffFile}` },
        contentHash: '',
        error: `Diff file not found: ${options.diffFile}`,
      };
    }
    rawDiff = readFileSync(options.diffFile, 'utf8');
  } else {
    rawDiff = runGh(['pr', 'diff', String(options.prNumber), '--repo', options.repo]);
    if (!rawDiff || rawDiff.startsWith('Run')) {
      return {
        scanId: '',
        repo: options.repo,
        prNumber: options.prNumber,
        author: options.author || 'unknown',
        findings: [],
        filesAnalyzed: 0,
        correlations: 0,
        threatIntel: { knownAuthor: false, authorThreatCount: 0, authorRiskLevel: null, patternMatches: 0 },
        verdict: { band: 'ERROR', decision: 'BLOCK', summary: 'Failed to fetch PR diff. Is gh CLI installed and authenticated?' },
        contentHash: '',
        error: 'Failed to fetch PR diff',
      };
    }
  }

  if (!options.author) {
    const prInfo = runGh(['pr', 'view', String(options.prNumber), '--repo', options.repo, '--json', 'author', '--jq', '.author.login']);
    options.author = prInfo || 'unknown';
  }

  const contentHash = createHash('sha256').update(rawDiff, 'utf8').digest('hex');
  const files = parseUnifiedDiff(rawDiff);
  const scanner = new LiteScanner();
  const result = await scanner.auditPR(options.repo, options.prNumber, options.author || 'unknown', files);
  const threatIntel = correlateThreats(options.author || 'unknown');

  const output: PrAuditResult = {
    scanId: result.scanId,
    repo: options.repo,
    prNumber: options.prNumber,
    author: options.author || 'unknown',
    findings: result.findings.map(f => ({
      type: f.type,
      intent: f.intent,
      file: f.file,
      line: f.line,
      severity: f.severity,
      description: f.description,
      snippet: f.snippet.substring(0, 200),
      risk: RISK_EXPLANATIONS[f.type] || 'Unknown risk — see detection description.',
    })),
    filesAnalyzed: files.length,
    correlations: result.correlations.length,
    threatIntel,
    verdict: { ...result.verdict, summary: result.verdict.band + ' — ' + result.verdict.decision },
    contentHash,
  };

  if (options.outputFile) {
    writeFileSync(options.outputFile, JSON.stringify(output, null, 2), 'utf8');
  }

  if (options.comment) {
    const markdown = buildMarkdown(output);
    const tempFile = require('path').join(
      require('os').tmpdir(),
      `sentinel-pr-${options.prNumber}-${Date.now()}.md`
    );
    writeFileSync(tempFile, markdown, 'utf8');
    runGh(['pr', 'comment', String(options.prNumber), '--repo', options.repo, '--body-file', tempFile]);
    try { require('fs').unlinkSync(tempFile); } catch {}
  }

  if (options.checkRun) {
    const conclusion = output.verdict.decision === 'BLOCK' ? 'failure' :
      output.verdict.decision === 'REVIEW' ? 'neutral' : 'success';
    const title = output.verdict.decision === 'BLOCK' ? 'Sentinel blocked this PR' :
      output.verdict.decision === 'REVIEW' ? 'Sentinel found issues' : 'Sentinel passed this PR';

    const headSha = runGh(['pr', 'view', String(options.prNumber), '--repo', options.repo, '--json', 'headRefOid', '--jq', '.headRefOid']);
    if (headSha && headSha.length === 40) {
      const checkInput = JSON.stringify({
        name: 'Sentinel Security Audit',
        head_sha: headSha,
        status: 'completed',
        conclusion,
        output: {
          title,
          summary: `${output.verdict.band} — ${output.verdict.decision}`,
          text: JSON.stringify(output, null, 2),
        },
      });

      runGh(['api', '-X', 'POST', `/repos/${options.repo}/check-runs`, '--input', '-'], checkInput);
    }
  }

  return output;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const repo = process.env.SENTINEL_REPO || '';
  const prNumber = parseInt(process.env.SENTINEL_PR || args[0], 10);
  const author = process.env.SENTINEL_AUTHOR || '';

  if (!repo || !prNumber) {
    console.log(JSON.stringify({ error: 'Usage: SENTINEL_REPO=owner/repo SENTINEL_PR=<number> [SENTINEL_AUTHOR=<login>] node pr-audit.js' }));
    process.exit(1);
  }

  const result = await runPrAudit({
    repo,
    prNumber,
    author,
    comment: !!process.env.SENTINEL_COMMENT,
    outputFile: process.env.SENTINEL_OUTPUT,
  });

  console.log(JSON.stringify(result, null, 2));

  if (result.verdict.decision === 'BLOCK') {
    process.exit(1);
  }
}

if (require.main === module) {
  main().catch(err => {
    console.log(JSON.stringify({ error: err.message }));
    process.exit(1);
  });
}

export { buildMarkdown, parseUnifiedDiff, main as runPrAuditMain };
