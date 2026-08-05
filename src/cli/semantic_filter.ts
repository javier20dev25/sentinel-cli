import { readFileSync } from 'fs';

/**
 * Semantic false-positive filter for `sentinel scan --staged`.
 *
 * The lite scanner is regex/lexical: it flags attack patterns anywhere on a
 * line, including inside test fixtures, string literals (data, not execution),
 * comments, and the scanner's own detection regexes. For the pre-commit hook
 * that meant real commits were blocked over self-matches (the ChainDrop
 * hardening commit needed `--no-verify`). This module decides per-finding
 * whether the flagged line still contains an attack keyword OUTSIDE
 * strings/comments. If not, the match lived in data and the finding is dropped.
 * Secrets and filename-based findings are never dropped on that basis.
 */

export interface SemanticFinding {
  type?: string;
  category?: string;
  file?: string;
  line?: number;
  severity?: string;
  snippet?: string;
}

const TEST_SEGMENTS = new Set([
  '__tests__', '__mocks__', '__snapshots__', 'test', 'tests',
  'fixtures', 'mocks', 'examples', 'example', 'benchmarks',
]);

const TEST_FILE_RE = /\.(test|spec|fixture|stories?)\./i;

export function isTestPath(p?: string): boolean {
  if (!p) return false;
  const segs = String(p).split(/[\\/]/);
  return segs.some((s) => TEST_SEGMENTS.has(s.toLowerCase())) || TEST_FILE_RE.test(p);
}

/** Rule families whose match must survive string/comment masking to be real. */
const CONTENT_TYPES = new Set([
  'NETWORK_ACTIVITY', 'WORKFLOW_RISK', 'OS_CAPABILITY', 'OS_COMMAND',
  'UNSAFE_EVAL', 'LIFECYCLE_CURL_BASH', 'SHELL_PIVOT', 'DYNAMIC_CODE',
  'EXEC_RISK', 'PERSISTENCE', 'MALICIOUS', 'INJECTION', 'SUSPICIOUS',
]);

export function isContentSignal(type?: string): boolean {
  return CONTENT_TYPES.has(String(type || '').toUpperCase());
}

export function isSecret(f: SemanticFinding): boolean {
  const cat = String(f.category || '').toLowerCase();
  const type = String(f.type || '').toUpperCase();
  if (cat === 'secret' || cat === 'secrets' || cat === 'token') return true;
  if (/^(SECRET|TOKEN|CREDENTIAL|PASSWORD|API_?KEY|ENV_FILE|SSH)/.test(type)) return true;
  return false;
}

export function isDetectorDef(line: string): boolean {
  if (/\bregex\s*:/.test(line)) return true;
  if (/new\s+RegExp\s*\(|\bRegExp\s*\(/.test(line)) return true;
  return false;
}

export function isBenignEnvRead(f: SemanticFinding, line: string): boolean {
  if (!/ENV/.test(String(f.type || '').toUpperCase())) return false;
  if (!/process\.env\.[A-Za-z_][A-Za-z0-9_]*/.test(line)) return false;
  if (/console\.(log|error|warn)\s*\(|fetch\s*\(|\.writeFile|exec\s*\(|spawn\s*\(/.test(line)) return false;
  return true;
}

const ATTACK_KEYWORDS = [
  'curl', 'wget', 'eval', 'exec', 'execSync', 'execFile', 'execFileSync',
  'execFileAsync', 'spawn', 'spawnSync', 'spawnAsync', 'popen', 'subprocess',
  'system(', 'fork(', 'fetch', 'axios', 'http.', 'https.', 'net.', 'websocket',
  'xmlhttprequest', 'bash', 'sh', 'powershell', 'cmd.exe', 'cmd /c', 'iwr',
  'invoke-webrequest', 'child_process', 'require(', 'node -e', 'function(',
  'base64', 'fromcharcode', 'readfile', 'writefile', 'unlink', 'screenshot',
  'clipboard', 'smtp',
];

export function hasAttackKeyword(masked: string): boolean {
  return ATTACK_KEYWORDS.some((k) => {
    if (k.endsWith('(') || k.endsWith('.')) return masked.toLowerCase().includes(k);
    return new RegExp('\\b' + k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b', 'i').test(masked);
  });
}

/**
 * Replace string/comment characters with spaces, preserving length. Handles
 * line comments, block comments, single/double quotes, backtick templates (per
 * line) and `#` YAML comments at line start.
 */
export function maskStringsAndComments(line: string): string {
  const out = line.split('');
  const n = line.length;
  let state: 'code' | 's' | 'd' | 't' | 'lc' | 'bc' = 'code';
  let blockDepth = 0;
  let i = 0;
  while (i < n) {
    const c = line[i];
    const nx = line[i + 1];
    if (state === 'code') {
      if (c === '/' && nx === '/') { out[i] = ' '; state = 'lc'; i++; continue; }
      if (c === '/' && nx === '*') { out[i] = ' '; out[i + 1] = ' '; state = 'bc'; blockDepth = 1; i += 2; continue; }
      if (c === '#' && (i === 0 || line[i - 1] === ' ' || line[i - 1] === '\t')) { out[i] = ' '; state = 'lc'; i++; continue; }
      if (c === "'" || c === '"' || c === '`') { state = c as 's' | 'd' | 't'; out[i] = ' '; i++; continue; }
      if (c === '\\') { i += 2; continue; }
      i++;
    } else if (state === 'bc') {
      out[i] = ' ';
      if (c === '/' && nx === '*') { blockDepth++; i += 2; continue; }
      if (c === '*' && nx === '/') { blockDepth--; out[i + 1] = ' '; i += 2; if (blockDepth === 0) state = 'code'; continue; }
      i++;
    } else if (state === 'lc') {
      out[i] = ' ';
      i++;
    } else {
      out[i] = ' ';
      if (c === '\\') { if (i + 1 < n) out[i + 1] = ' '; i += 2; continue; }
      if (c === state) state = 'code';
      i++;
    }
  }
  return out.join('');
}

export interface ClassifyResult {
  keep: boolean;
  reason: string;
}

export function classifyFinding(f: SemanticFinding, srcLines: string[] | null): ClassifyResult {
  if (isTestPath(f.file)) return { keep: false, reason: 'test/fixture/example path' };

  if (isSecret(f)) return { keep: true, reason: 'secret' };
  if (!f.line || !srcLines) return { keep: true, reason: 'filename-based or unreadable source' };

  const line = srcLines[f.line - 1] || '';
  if (!line.trim()) return { keep: true, reason: 'line unavailable (keep conservative)' };

  if (isDetectorDef(line)) return { keep: false, reason: 'detector rule definition' };
  if (isBenignEnvRead(f, line)) return { keep: false, reason: 'benign process.env read' };

  if (isContentSignal(f.type)) {
    const masked = maskStringsAndComments(line);
    if (!hasAttackKeyword(masked)) return { keep: false, reason: 'attack keyword only inside string/comment' };
  }
  return { keep: true, reason: 'code context' };
}

export function loadFileLines(file: string): string[] | null {
  try {
    return readFileSync(file, 'utf8').split('\n');
  } catch {
    return null;
  }
}
