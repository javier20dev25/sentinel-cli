'use strict';

import {
  NetworkFlow, ProcessEvent, FileAccessEvent, GitCommandEvent,
  Artifact, Behavior, BehaviorType, generateId
} from './types';

// Note: 'continue' intentionally omitted — it's a common keyword in
// JavaScript/Python/PowerShell and causes false positives in command lines.
const AI_AGENT_PROCESSES = [
  'grok', 'grok-build', 'cursor', 'copilot', 'claude', 'codex',
  'gemini', 'github-copilot', 'copilot-agent', 'claude-code',
  'tabby', 'tabnine', 'supermaven', 'codeium',
  'windsurf', 'aider', 'open-interpreter', 'swe-agent',
  'devin', 'factory', 'poolside', 'mutable', 'replit-agent'
];

const SENSITIVE_GIT_COMMANDS = [
  'git bundle create', 'git archive', 'git rev-list --all',
  'git pack-objects', 'git pack-objects --all',
  'git clone --mirror', 'git clone --bare'
];

const PREPARATION_GIT_COMMANDS = [
  'git cat-file', 'git rev-list', 'git ls-tree',
  'git count-objects', 'git show-ref', 'git for-each-ref',
  'git diff --cached', 'git stash list', 'git stash',
  'git bundle list-heads'
];

const SUSPICIOUS_HOST_PATTERNS = [
  '.grok.com', '.x.ai', '.openai.com', '.anthropic.com',
  '.googleapis.com', 'storage.googleapis.com',
  '.cloud.google.com', 's3.amazonaws.com',
  '.githubcopilot.com', '.cursor.sh', '.claude.ai',
  'api.github.com',
  'pastebin.com', 'transfer.sh', 'file.io', 'mega.nz', 'gist.github.com',
  'discord.com', 'httpbin.org', 'webhook.site', 'requestbin.com',
  'pipedream.com', 'ngrok.io', 'hookbin.com',
  'beacon.this', 'canarytokens.com',
];

export const AI_PROMPT_API_PATHS = [
  '/v1/chat/completions', '/v1/messages', '/v1/complete',
  '/v1/completions', '/api/generate', '/api/chat',
  '/v1/responses', '/chat/completions',
];

const SECRET_PATH_FRAGMENTS = [
  '.env', 'secrets', 'credentials', 'api_key', 'private_key',
  '.pem', '.p12', '.pfx', 'password', 'passwd',
  'token', 'auth_key', '.ssh', 'id_rsa', 'id_ed25519',
  '.npmrc', '.netrc',
];

const MONITOR_DETECTION_COMMANDS = [
  'procexp', 'wireshark', 'tcpview', 'process monitor', 'processmonitor',
  'sentinel', 'debugger', 'isdebuggerpresent', 'checkremotedebugger',
  'vmwaretools', 'virtualbox', 'vboxservice', 'isvm',
  'get-process -name', 'tasklist | find', 'ps aux | grep',
];

export function classifyFlow(flow: NetworkFlow): Behavior | null {
  const evidence: string[] = [];
  const artifacts: Artifact[] = [];
  let type: BehaviorType | null = null;

  const isKnownAiHost = flow.hostname != null && SUSPICIOUS_HOST_PATTERNS.some(h => flow.hostname!.includes(h));
  const isAiPromptPath = flow.path != null && AI_PROMPT_API_PATHS.some(p => flow.path!.includes(p));

  if (isKnownAiHost) {
    // Large upload supersedes suspicious_connection and ai_prompt_sent
    if (flow.bytesSent > 1024 * 1024) {
      type = 'code_upload';
      evidence.push(`Large upload (${(flow.bytesSent / 1024 / 1024).toFixed(1)} MB) to ${flow.hostname}`);
    } else if (isAiPromptPath) {
      type = 'ai_prompt_sent';
      evidence.push(`AI prompt API call: ${flow.method ?? 'POST'} ${flow.path} → ${flow.hostname}`);
    } else {
      type = 'suspicious_connection';
      evidence.push(`Connection to AI/cloud host: ${flow.hostname}`);
    }
  } else if (isAiPromptPath) {
    type = flow.bytesSent > 50 * 1024 ? 'code_upload' : 'ai_prompt_sent';
    const label = flow.bytesSent > 50 * 1024
      ? `Large payload (${(flow.bytesSent / 1024).toFixed(0)} KB) to AI API path`
      : `AI prompt API call: ${flow.method ?? 'POST'} ${flow.path}`;
    evidence.push(`${label} → ${flow.hostname ?? flow.destAddr}`);
  }

  if (flow.bodyPreview && flow.bodyPreview.includes('git bundle')) {
    type = 'git_bundle_uploaded';
    evidence.push('Git bundle detected in HTTP body');
    artifacts.push({
      type: 'git-bundle',
      name: 'inline-bundle',
      sizeBytes: flow.bytesSent,
      detectedAt: new Date(),
      confidence: 0.95,
      sourceFlowId: flow.id,
      detail: 'Git bundle header found in request body'
    });
  }

  if (flow.dnsQuery && SUSPICIOUS_HOST_PATTERNS.some(h => flow.dnsQuery!.includes(h))) {
    type = 'dns_suspicious';
    evidence.push(`DNS lookup to AI domain: ${flow.dnsQuery}`);
  }

  if (flow.sni && SUSPICIOUS_HOST_PATTERNS.some(h => flow.sni!.includes(h))) {
    type = 'tls_suspicious';
    evidence.push(`TLS handshake to AI host: ${flow.sni}`);
  }

  if (!type) return null;

  return {
    id: generateId(),
    sessionId: flow.sessionId,
    type,
    confidence: computeConfidence(evidence.length, artifacts.length, flow),
    evidence,
    artifacts,
    timestamp: new Date(),
    source: 'connection'
  };
}

function computeConfidence(
  evidenceCount: number, artifactCount: number, flow: NetworkFlow
): number {
  let base = 0.5;
  base += evidenceCount * 0.15;
  base += artifactCount * 0.1;
  if (flow.bytesSent > 1048576) base += 0.15;
  if (flow.bytesSent > 10485760) base += 0.1;
  if (flow.tlsVersion) base += 0.05;
  return Math.min(base, 0.99);
}

export function classifyCanaryEvent(
  event: { type: string; canaryName: string; confidence: number; timestamp: Date; sessionId: string; processName?: string }
): Behavior | null {
  const typeMap: Record<string, BehaviorType> = {
    decoy_file_read: 'canary_read',
    decoy_file_modified: 'canary_modified',
    fake_secret_read: 'fake_secret_read',
    contaminated_git_read: 'contaminated_git_read',
    decoy_exfiltrated: 'canary_exfiltrated',
  };

  const bt = typeMap[event.type];
  if (!bt) return null;

  return {
    id: generateId(),
    sessionId: event.sessionId,
    type: bt,
    confidence: event.confidence,
    evidence: [`Canary '${event.canaryName}' triggered: ${event.type}`],
    artifacts: [],
    timestamp: event.timestamp,
    source: 'file',
  };
}

const PREPARATION_SYSTEM_COMMANDS = [
  'whoami', 'ipconfig', 'netstat', 'hostname', 'arp', 'route', 'systeminfo',
  'nslookup',
];

export function classifyPreparationCommands(proc: ProcessEvent): Behavior | null {
  const cmdLower = proc.commandLine.toLowerCase();
  const allPrep = [...PREPARATION_GIT_COMMANDS, ...PREPARATION_SYSTEM_COMMANDS];
  for (const prepCmd of allPrep) {
    if (cmdLower.includes(prepCmd)) {
      return {
        id: generateId(),
        sessionId: '',
          // 'pre_operational_snapshot_detected' is reserved for evidence chain results.
        type: 'preparation_detected',
        confidence: 0.8,
        evidence: [`Preparation command: ${prepCmd}`],
        artifacts: [],
        timestamp: proc.timestamp,
        source: 'process',
      };
    }
  }
  return null;
}

export function classifyProcess(proc: ProcessEvent): Behavior | null {
  const evidence: string[] = [];
  let type: BehaviorType | null = null;

  const cmdLower = proc.commandLine.toLowerCase();
  const nameLower = proc.name.toLowerCase();

  // Skip Sentinel's own acquisition infrastructure to avoid self-detection false positives
  // Use nameLower check to avoid skipping parent shell processes whose command line
  // references the recorder but are not themselves the recorder (e.g. powershell.exe launching node)
  if (nameLower.includes('node.exe') && (cmdLower.includes('dist/cli/main.js') || cmdLower.includes('scripts/record-session.js'))) {
    return null;
  }

  // Skip legitimate system processes that happen to have AI-adjacent names
  // (e.g. Microsoft Copilot proxy service is a system component, not an adversarial AI agent)
  if (nameLower.includes('mscopilot') || cmdLower.includes('\\microsoft\\copilot\\')) {
    return null;
  }

  const isAiAgent = AI_AGENT_PROCESSES.some(
    a => new RegExp('\\b' + a.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b', 'i').test(nameLower) ||
         new RegExp('\\b' + a.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b', 'i').test(cmdLower)
  );
  if (isAiAgent) {
    evidence.push(`AI agent process detected: ${proc.name}`);
    type = 'process_suspicious';
  }

  // Check for monitor termination attempts (must precede monitor_awareness check)
  if (!type) {
    const sentinelPid = process.pid;
    if (
      cmdLower.includes('taskkill') || cmdLower.includes('stop-process') || cmdLower.includes('wmic process')
    ) {
      const targetsSentinel = cmdLower.includes('sentinel') || cmdLower.includes(String(sentinelPid));
      if (targetsSentinel) {
        type = 'monitor_disabled';
        evidence.push(`Monitor termination attempt detected: command targets sentinel process`);
      }
    }
  }

  // Only applies to non-AI-agent and non-kill processes to avoid false positives on IDE internals.
  // Single-word patterns match as standalone tokens (avoiding 'sentinel' in 'sentinel-cli').
  // Multi-word patterns use exact substring match (they're specific enough to avoid FPs).
  if (!type && !isAiAgent) {
    let matched: string | undefined;

    // Check process name first (most reliable)
    matched = MONITOR_DETECTION_COMMANDS.find(m => nameLower.includes(m));

    if (!matched) {
      const multiWord = MONITOR_DETECTION_COMMANDS.filter(m => m.includes(' '));
      const singleWord = MONITOR_DETECTION_COMMANDS.filter(m => !m.includes(' '));

      // Multi-word patterns: exact substring match
      matched = multiWord.find(m => cmdLower.includes(m));

      // Single-word patterns: standalone token match only
      if (!matched) {
        const cmdTokens = cmdLower.split(/[\s,;|&"'()=/\\]+/).filter(Boolean);
        matched = singleWord.find(m => cmdTokens.some(t => t === m));
      }
    }

    if (matched) {
      type = 'monitor_awareness_detected';
      evidence.push(`Monitor/debugger detection command: ${proc.commandLine.substring(0, 120)}`);
      evidence.push(`Matched pattern: '${matched}'`);
    }
  }

  for (const gitCmd of SENSITIVE_GIT_COMMANDS) {
    if (cmdLower.includes(gitCmd)) {
      const gitAction = gitCmd.includes('bundle') ? 'git_bundle_created' :
                        gitCmd.includes('archive') ? 'git_archive_created' :
                        'repo_indexed';
      type = gitAction as BehaviorType;
      evidence.push(`Suspicious git command: ${gitCmd}`);
    }
  }

  // Detect curl sending data (--data-binary, -d, --data, -F, -T)
  if (cmdLower.includes('curl') && /--data-binary|-(?:d|f|t)\b|--data(?:-raw)?\b|--upload-file\b/.test(cmdLower)) {
    type = 'code_upload';
    evidence.push(`Data upload via curl: ${proc.commandLine.substring(0, 160)}`);
  }

  // Detect DNS tunneling via nslookup TXT queries
  if (cmdLower.includes('nslookup') && (cmdLower.includes('-type=txt') || cmdLower.includes('-t=txt') || /nslookup\s+.*\.(?:attacker|exfil|tunnel)/i.test(cmdLower))) {
    type = 'dns_suspicious';
    evidence.push(`DNS tunneling via nslookup: ${proc.commandLine.substring(0, 160)}`);
  }

  // Detect tar archiving .git directory
  if (cmdLower.includes('tar') && cmdLower.includes('.git') && (cmdLower.includes('-czf') || cmdLower.includes('-zcf') || cmdLower.includes('--create'))) {
    type = 'git_archive_created';
    evidence.push(`Git archive via tar: ${proc.commandLine.substring(0, 160)}`);
  }

  if (!type) return null;

  return {
    id: generateId(),
    sessionId: '',
    type,
    confidence: type === 'monitor_awareness_detected' ? 0.85 : type === 'monitor_disabled' ? 0.9 : 0.8,
    evidence,
    artifacts: [],
    timestamp: new Date(),
    source: 'process'
  };
}

export function classifyFileAccess(access: FileAccessEvent): Behavior | null {
  const evidence: string[] = [];
  const artifacts: Artifact[] = [];
  let type: BehaviorType | null = null;

  const pathLower = access.filePath.toLowerCase();

  if (pathLower.includes('.git') && pathLower.includes('objects')) {
    type = 'git_objects_read';
    evidence.push(`Git objects accessed by ${access.processName}`);
  }

  if (pathLower.includes('.git') && (pathLower.includes('logs') || pathLower.includes('index') || pathLower.includes('config') || pathLower.includes('head'))) {
    type = 'git_history_read';
    evidence.push(`Git history/metadata accessed by ${access.processName}`);
  }

  if (pathLower.endsWith('.bundle') || pathLower.endsWith('.gitbundle')) {
    type = 'git_bundle_created';
    evidence.push(`Bundle file created: ${access.filePath}`);
    artifacts.push({
      type: 'git-bundle',
      name: access.filePath.split(/[/\\]/).pop() || 'unknown.bundle',
      sizeBytes: access.bytesRead || 0,
      detectedAt: new Date(),
      confidence: 0.9,
      detail: 'Git bundle file detected on filesystem'
    });
  }

  // Only classify if no stronger git-related type was already set,
  // so git object reads are not downgraded to secrets_scanned.
  if (!type && SECRET_PATH_FRAGMENTS.some(f => pathLower.includes(f))) {
    type = 'secrets_scanned';
    evidence.push(`Sensitive file accessed: ${access.filePath}`);
  }

  if (!type) return null;

  return {
    id: generateId(),
    sessionId: '',
    type,
    confidence: 0.85,
    evidence,
    artifacts,
    timestamp: new Date(),
    source: 'file'
  };
}

export function classifyGitCommand(cmd: GitCommandEvent): Behavior | null {
  const evidence: string[] = [];
  let type: BehaviorType | null = null;
  const lower = cmd.commandLine.toLowerCase();

  switch (cmd.action) {
    case 'bundle':
      type = 'git_bundle_created';
      evidence.push(`Git bundle command: ${cmd.commandLine}`);
      break;
    case 'archive':
      type = 'git_archive_created';
      evidence.push(`Git archive command: ${cmd.commandLine}`);
      break;
    case 'rev-list':
      type = 'git_history_read';
      evidence.push(`Git history enumeration: ${cmd.commandLine}`);
      break;
    case 'log':
      type = 'git_history_read';
      evidence.push(`Git log command: ${cmd.commandLine}`);
      break;
    case 'diff':
    case 'status':
    case 'add':
    case 'commit':
    case 'checkout':
    case 'branch':
    case 'merge':
    case 'rebase':
    case 'init':
    case 'config':
    case 'remote':
    case 'rev-parse':
    case 'stash':
    case 'tag':
    case 'reset':
    case 'revert':
    case 'cherry-pick':
    case 'clean':
    case 'submodule':
    case 'worktree':
    case 'gc':
    case 'fsck':
    case 'pull':
      // Normal git operations — not suspicious
      break;
    case 'push':
      if (lower.includes('--mirror') || lower.includes('--all') || lower.includes('--force')) {
        type = 'full_repo_snapshot';
        evidence.push(`Full repo push detected: ${cmd.commandLine}`);
      }
      break;
    case 'cat-file':
    case 'ls-tree':
    case 'show-ref':
    case 'for-each-ref':
      type = 'git_objects_read';
      evidence.push(`Git objects/prep command: ${cmd.commandLine}`);
      break;
    case 'clone':
    case 'fetch':
    case 'pull':
      // Normal network operations, not suspicious per se
      break;
  }

  if (!type) return null;

  return {
    id: generateId(),
    sessionId: '',
    type,
    confidence: 0.9,
    evidence,
    artifacts: [{
      type: type === 'git_bundle_created' ? 'git-bundle' : 'git-object',
      name: `git-${cmd.action}`,
      sizeBytes: 0,
      detectedAt: new Date(),
      confidence: 0.9,
    }],
    timestamp: new Date(),
    source: 'git'
  };
}

export function computeMassReadBehavior(
  events: FileAccessEvent[], windowMs: number = 5000
): Behavior | null {
  if (events.length < 100) return null;

  const now = Date.now();
  const recent = events.filter(e => now - e.timestamp.getTime() < windowMs);
  if (recent.length < 50) return null;

  const uniqueFiles = new Set(recent.map(e => e.filePath));
  if (uniqueFiles.size < 20) return null;

  return {
    id: generateId(),
    sessionId: '',
    type: 'mass_file_read',
    confidence: Math.min(0.5 + recent.length * 0.002, 0.95),
    evidence: [
      `${recent.length} file reads in ${windowMs / 1000}s`,
      `${uniqueFiles.size} unique files accessed`
    ],
    artifacts: [],
    timestamp: new Date(),
    source: 'file'
  };
}

export function computeEmbeddingBehavior(
  events: FileAccessEvent[], windowMs: number = 10000
): Behavior | null {
  if (events.length < 200) return null;

  const patterns = analyzeAccessPattern(events, windowMs);
  if (!patterns.isEmbedding) return null;

  return {
    id: generateId(),
    sessionId: '',
    type: 'embeddings_generated',
    confidence: patterns.confidence,
    evidence: [
      `${events.length} files read in ${windowMs / 1000}s`,
      'Pattern: open→read→close repeated across many files',
      'Consistent inter-read interval detected'
    ],
    artifacts: [],
    timestamp: new Date(),
    source: 'file'
  };
}

function analyzeAccessPattern(
  events: FileAccessEvent[], windowMs: number
): { isEmbedding: boolean; confidence: number } {
  if (events.length < 5) return { isEmbedding: false, confidence: 0 };

  const intervals: number[] = [];
  for (let i = 1; i < events.length; i++) {
    intervals.push(
      events[i].timestamp.getTime() - events[i - 1].timestamp.getTime()
    );
  }

  if (intervals.length === 0) return { isEmbedding: false, confidence: 0 };

  const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
  const variance = intervals.reduce(
    (a, b) => a + (b - avgInterval) ** 2, 0
  ) / intervals.length;
  const stdDev = Math.sqrt(variance);

  const isRegular = stdDev < avgInterval * 0.5;
  const isManyFiles = events.length > 100;
  const confidence = (isRegular ? 0.4 : 0) + (isManyFiles ? 0.4 : 0) + 0.1;

  return {
    isEmbedding: isRegular && isManyFiles,
    confidence: Math.min(confidence, 0.95)
  };
}
