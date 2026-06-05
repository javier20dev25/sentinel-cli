import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { LiteScanner, LiteFinding } from '../core/lite/lite_scanner';
import { SupplyChainShield } from '../cli/intelligence/supply_chain_shield';
import { SystemAuditor } from '../cli/intelligence/system_auditor';
import { IntegrityManager } from '../cli/intelligence/integrity_manager';
import { MemoryManager } from '../cli/intelligence/memory_manager';
import { readClassifiedDb } from '../cli/classify';
import { getThreatsByAuthor, correlateFindings } from './threat_db';

function sanitizePath(input: string): string {
  return input.replace(/[^a-zA-Z0-9_\-./\\:]/g, '').replace(/\.\./g, '').trim();
}

function sanitizePkg(input: string): string {
  const match = input.match(/^@?[a-zA-Z0-9._\-\/]+(@\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?)?$/);
  return match ? match[0] : input.replace(/[^a-zA-Z0-9._\-@\/]/g, '');
}

function runGh(ghArgs: string[]): string {
  try {
    return execFileSync('gh', ghArgs, {
      timeout: 30000, encoding: 'utf-8',
      maxBuffer: 10 * 1024 * 1024, windowsHide: true,
    }).trim();
  } catch (e: any) {
    return e.stdout?.trim() || e.stderr?.trim() || e.message;
  }
}

async function captureConsoleAsync(fn: () => Promise<void>): Promise<string> {
  const chunks: string[] = [];
  const origLog = console.log;
  const origErr = console.error;
  console.log = (...args: any[]) => chunks.push(args.map(a => typeof a === 'object' ? JSON.stringify(a, null, 2) : String(a)).join(' '));
  console.error = (...args: any[]) => chunks.push(args.map(a => typeof a === 'object' ? JSON.stringify(a, null, 2) : String(a)).join(' '));
  try { await fn(); } finally { console.log = origLog; console.error = origErr; }
  return chunks.join('\n');
}

function walkDir(dir: string, results: string[], depth = 0): void {
  if (!fs.existsSync(dir) || depth > 8) return;
  const list = fs.readdirSync(dir);
  for (const file of list) {
    if (file.startsWith('.') || file === 'node_modules' || file === '.git') continue;
    const full = path.resolve(dir, file);
    if (!full.startsWith(path.resolve(dir))) continue;
    try {
      if (fs.lstatSync(full).isSymbolicLink()) continue;
      const stat = fs.statSync(full);
      if (stat.isDirectory()) {
        walkDir(full, results, depth + 1);
      } else if (file.endsWith('.js') || file.endsWith('.ts') || file.endsWith('.mjs') || file.endsWith('.cjs') || file.endsWith('.json')) {
        results.push(full);
      }
    } catch (_) {}
  }
}

function scanPath(target: string): string {
  const absTarget = path.resolve(target);
  if (!fs.existsSync(absTarget)) return `Error: path not found: ${target}`;
  const scanner = new LiteScanner();
  const allFindings: LiteFinding[] = [];
  if (fs.statSync(absTarget).isDirectory()) {
    const files: string[] = [];
    walkDir(absTarget, files);
    for (const file of files) {
      try {
        const content = fs.readFileSync(file, 'utf8');
        const relPath = path.relative(absTarget, file);
        const patch = `@@ -0,0 +1,1 @@\n+${content.split('\n').join('\n+')}`;
        const findings = scanner.scanPatch(relPath, patch);
        allFindings.push(...findings);
      } catch (_) {}
    }
  } else {
    try {
      const content = fs.readFileSync(absTarget, 'utf8');
      const patch = `@@ -0,0 +1,1 @@\n+${content.split('\n').join('\n+')}`;
      const findings = scanner.scanPatch(absTarget, patch);
      allFindings.push(...findings);
    } catch (e: any) {
      return `Error reading file: ${e.message}`;
    }
  }
  if (allFindings.length === 0) return 'No threats detected.';
  const lines: string[] = [];
  for (const f of allFindings) {
    lines.push(`[${f.severity}] ${f.type} in ${f.file}:${f.line}`);
    lines.push(`  ${f.description}`);
  }
  return lines.join('\n');
}

export async function runMcpTool(name: string, args: Record<string, string>): Promise<string> {
  const toolArgs: Record<string, string> = args || {};

  switch (name) {
    case 'scan': {
      const target = sanitizePath(toolArgs.path || '.');
      return scanPath(target);
    }

    case 'verify-pkg': {
      const pkg = sanitizePkg(toolArgs.package || '');
      if (!pkg) return 'Error: invalid package name';
      try {
        const shield = new SupplyChainShield();
        const result = await shield.analyzePackage(pkg);
        const lines = [
          `Package: ${result.pkg}`,
          `Tarball Size: ${(result.sizeBytes / 1024).toFixed(1)} KB`,
          `Files Analyzed: ${result.fileCount}`,
          `Scan Time: ${result.scanTimeMs}ms`,
          `Memory: ${result.memoryMB} MB`,
          `Verdict: ${result.verdict}`,
        ];
        if (result.findings.length > 0) {
          lines.push(`\nFindings (${result.findings.length}):`);
          for (const f of result.findings) {
            lines.push(`  [${f.severity}] ${f.type} in ${f.file}:${f.line}`);
            lines.push(`    ${f.description}`);
          }
        } else {
          lines.push('\nNo threats detected.');
        }
        return lines.join('\n');
      } catch (e: any) {
        return `Error: ${e.message}`;
      }
    }

    case 'doctor': {
      const originalCwd = process.cwd();
      const p = sanitizePath(toolArgs.path || '');
      if (p && fs.existsSync(path.resolve(p))) process.chdir(path.resolve(p));
      try {
        const auditor = new SystemAuditor();
        return await captureConsoleAsync(() => auditor.runDoctor(toolArgs.deep === '--deep'));
      } catch (e: any) {
        return `Error: ${e.message}`;
      } finally {
        if (p) process.chdir(originalCwd);
      }
    }

    case 'check-classified': {
      try {
        const db = readClassifiedDb();
        return JSON.stringify(db, null, 2);
      } catch (e: any) {
        return `Error: ${e.message}`;
      }
    }

    case 'integrity': {
      try {
        const manager = new IntegrityManager();
        const { level, reasons } = await manager.checkIntegrity();
        const lines = [`Integrity Level: ${level}`];
        if (reasons.length > 0) {
          lines.push('Issues found:');
          for (const r of reasons) lines.push(`  - ${r}`);
        }
        return lines.join('\n');
      } catch (e: any) {
        return `Integrity check error: ${e.message}`;
      }
    }

    case 'memory': {
      try {
        const mem = new MemoryManager();
        const status = mem.getStatus();
        const lines = [
          `Signal Vault Status:`,
          `  Signals: ${status.signals}`,
          `  Scans: ${status.scans}`,
          `  Findings: ${status.findings}`,
          `  Repos: ${status.repos}`,
          `  Authors: ${status.authors}`,
        ];
        const action = toolArgs.action || '';
        if (action === '--threats' || action === '--findings') {
          const analysis = mem.getThresholdAnalysis(3);
          if (analysis.length > 0) {
            lines.push(`\nThreshold Analysis (repos with >= 3 signals):`);
            for (const entry of analysis) {
              lines.push(`  ${entry.repo}: ${entry.signalCount} signals, trend: ${entry.riskTrend}`);
            }
          }
        }
        return lines.join('\n');
      } catch (e: any) {
        return `Error: ${e.message}`;
      }
    }

    case 'threat-query': {
      const author = toolArgs.author || '';
      const threats = getThreatsByAuthor(author);
      return JSON.stringify(
        threats.length > 0 ? threats : { message: 'No threats found for this author', author },
        null, 2
      );
    }

    case 'threat-correlate': {
      const corr = correlateFindings(
        toolArgs.author || undefined,
        toolArgs.findings || undefined,
        toolArgs.diffHash || undefined
      );
      return JSON.stringify(corr, null, 2);
    }

    case 'gh-pr-list': {
      const repo = toolArgs.repo || '';
      const limit = toolArgs.limit || '10';
      const state = toolArgs.state || 'open';
      const args = ['pr', 'list', '--limit', limit, '--state', state];
      if (repo) args.push('--repo', repo);
      return runGh(args);
    }

    case 'gh-pr-view': {
      const number = toolArgs.number || '';
      const repo = toolArgs.repo || '';
      const args = ['pr', 'view', number, '--json', 'number,title,state,body,author,headRefName,baseRefName,createdAt,mergedAt,mergeable'];
      if (repo) args.push('--repo', repo);
      return runGh(args);
    }

    case 'gh-pr-diff': {
      const number = toolArgs.number || '';
      const repo = toolArgs.repo || '';
      const args = ['pr', 'diff', number];
      if (repo) args.push('--repo', repo);
      return runGh(args);
    }

    case 'gh-repo-list': {
      const owner = toolArgs.owner || '';
      const limit = toolArgs.limit || '20';
      const args = ['repo', 'list', '--limit', limit, '--json', 'nameWithOwner,description,isPrivate'];
      if (owner) args.push(owner);
      return runGh(args);
    }

    default:
      return `Unknown tool: ${name}`;
  }
}
