import * as fs from 'fs'
import * as path from 'path'
import * as crypto from 'crypto'
import { FileReadEvent, BuildNetEvent, BuildProcessEvent, SecretAccess, SecretFlow as SecretFlowResult, SecretFlowChain } from './build-types'

const SECRET_PATTERNS: { regex: RegExp; type: string; severity: 'critical' | 'high' | 'medium' }[] = [
  { regex: /sk-live-[0-9a-zA-Z]{24,}/g, type: 'stripe_live_key', severity: 'critical' },
  { regex: /sk-proj-[0-9a-zA-Z]{24,}/g, type: 'openai_project_key', severity: 'critical' },
  { regex: /(?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36,}/g, type: 'github_token', severity: 'critical' },
  { regex: /AKIA[0-9A-Z]{16}/g, type: 'aws_access_key', severity: 'critical' },
  { regex: /-----BEGIN\s+(RSA|OPENSSH|EC|DSA|PRIVATE)\s+PRIVATE\s+KEY-----/g, type: 'private_key', severity: 'critical' },
  { regex: /-----BEGIN\s+(PGP|GPG)\s+(PRIVATE|PUBLIC)\s+KEY\s+BLOCK-----/g, type: 'pgp_key', severity: 'critical' },
  { regex: /xox[baprs]-[0-9a-zA-Z-]{24,}/g, type: 'slack_token', severity: 'critical' },
  { regex: /AIza[0-9A-Za-z_-]{35}/g, type: 'gcp_api_key', severity: 'high' },
  { regex: /CAA[0-9A-Za-z_-]{30,}/g, type: 'facebook_access_token', severity: 'high' },
  { regex: /ghb_[0-9a-zA-Z]{36,}/g, type: 'github_codespaces_token', severity: 'critical' },
  { regex: /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g, type: 'jwt_token', severity: 'high' },
  { regex: /(?:api|api_key|apikey|token|secret|password|passwd)\s*[=:]\s*['"][^'"]{8,}['"]/gi, type: 'generic_secret_assignment', severity: 'medium' },
  { regex: /mongodb(?:\+srv)?:\/\/[^\s'"]+/g, type: 'mongodb_connection_string', severity: 'high' },
  { regex: /postgresql:\/\/[^\s'"]+/g, type: 'postgres_connection_string', severity: 'high' },
  { regex: /mysql:\/\/[^\s'"]+/g, type: 'mysql_connection_string', severity: 'high' },
  { regex: /redis:\/\/[^\s'"]+/g, type: 'redis_connection_string', severity: 'high' },
  { regex: /jdbc:[^\s'"]+/g, type: 'jdbc_connection_string', severity: 'high' },
  { regex: /-----BEGIN CERTIFICATE-----/g, type: 'certificate', severity: 'medium' },
  { regex: /(?:AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID)\s*=\s*\S+/g, type: 'aws_env_credential', severity: 'critical' },
]

const SENSITIVE_FILE_PATTERNS = [
  /\.env$/i, /\.env\.\w+$/i,
  /credentials/i, /secret/i, /token/i, /key\./i,
  /\.pem$/, /\.p12$/, /\.pfx$/, /\.key$/, /\.cert$/,
  /\.htpasswd$/, /\.netrc$/, /_rsa$/, /_dsa$/, /_ecdsa$/,
  /vault\./, /\.kubeconfig/, /kubeconfig-/,
  /service-account/, /\.service-account-key/,
]

const SENSITIVE_ENV_KEYS = new Set([
  'AWS_SECRET_ACCESS_KEY', 'AWS_ACCESS_KEY_ID', 'AWS_SESSION_TOKEN',
  'AZURE_CLIENT_SECRET', 'AZURE_TENANT_ID', 'AZURE_CLIENT_ID',
  'GCP_SERVICE_ACCOUNT_KEY', 'GOOGLE_APPLICATION_CREDENTIALS',
  'GITHUB_TOKEN', 'GITLAB_TOKEN', 'NPM_TOKEN',
  'DOCKER_PASSWORD', 'DOCKER_TOKEN',
  'SLACK_TOKEN', 'SLACK_BOT_TOKEN',
  'OPENAI_API_KEY', 'ANTHROPIC_API_KEY',
  'STRIPE_API_KEY', 'STRIPE_SECRET_KEY',
  'DB_PASSWORD', 'DATABASE_URL', 'REDIS_URL',
  'SECRET_KEY', 'SECRET_KEY_BASE', 'ENCRYPTION_KEY',
  'JWT_SECRET', 'SESSION_SECRET',
  'API_KEY', 'API_SECRET', 'APP_SECRET',
  'SENTRY_DSN', 'DATADOG_API_KEY', 'NEW_RELIC_LICENSE_KEY',
  'SSH_PRIVATE_KEY', 'DEPLOY_KEY',
])

function detectSecretsInContent(content: Buffer, filePath: string): SecretAccess[] {
  const secrets: SecretAccess[] = []
  const text = content.toString('utf-8')
  const lines = text.split('\n')

  for (const { regex, type, severity } of SECRET_PATTERNS) {
    for (const match of text.matchAll(regex)) {
      const lineNum = getLineNumber(lines, match.index!)
      const context = getContextLine(lines, lineNum)
      const matchStart = Math.max(0, match.index! - 20)
      const snippet = text.substring(matchStart, Math.min(text.length, match.index! + match[0].length + 20))

      secrets.push({
        type,
        severity,
        filePath,
        match: match[0].substring(0, 40) + (match[0].length > 40 ? '...' : ''),
        line: lineNum,
        context,
        snippet: snippet.substring(0, 120),
        sha256: crypto.createHash('sha256').update(match[0]).digest('hex'),
      })
    }
  }

  return secrets
}

function getLineNumber(lines: string[], index: number): number {
  let charCount = 0
  for (let i = 0; i < lines.length; i++) {
    charCount += lines[i].length + 1
    if (charCount > index) return i + 1
  }
  return lines.length
}

function getContextLine(lines: string[], lineNum: number): string {
  const idx = lineNum - 1
  if (idx >= 0 && idx < lines.length) {
    return lines[idx].trim().substring(0, 150)
  }
  return ''
}

function isSensitiveFilePath(filePath: string): boolean {
  return SENSITIVE_FILE_PATTERNS.some(p => p.test(filePath))
}

export function scanFileForSecrets(filePath: string): SecretAccess[] {
  try {
    const absPath = path.resolve(filePath)
    if (!fs.existsSync(absPath)) return []
    const stat = fs.statSync(absPath)
    if (!stat.isFile()) return []
    if (stat.size > 5 * 1024 * 1024) return []

    const content = fs.readFileSync(absPath)
    return detectSecretsInContent(content, filePath)
  } catch { return [] }
}

export function scanProcessReadsForSecrets(
  readEvents: FileReadEvent[],
  readFiles?: FileReadEvent[],
): SecretAccess[] {
  const allReads = [...readEvents, ...(readFiles || [])]
  const seen = new Set<string>()
  const secrets: SecretAccess[] = []

  for (const r of allReads) {
    if (seen.has(r.filePath)) continue
    seen.add(r.filePath)

    if (isSensitiveFilePath(r.filePath)) {
      const found = scanFileForSecrets(r.filePath)
      for (const s of found) {
        s.pid = r.pid
        s.processName = r.processName
        s.timestamp = r.timestamp
      }
      secrets.push(...found)
    }
  }

  return secrets
}

export function scanEnvForSecrets(env: Record<string, string>): SecretAccess[] {
  const secrets: SecretAccess[] = []

  for (const [key, value] of Object.entries(env)) {
    if (SENSITIVE_ENV_KEYS.has(key) && value && value.length > 3) {
      secrets.push({
        type: 'env_variable',
        severity: SENSITIVE_ENV_KEYS.has(key) ? 'critical' : 'high',
        filePath: '(environment)',
        match: `${key}=${value.substring(0, 3)}...`,
        line: 0,
        context: `Environment variable ${key} set`,
        snippet: `${key}=${value.substring(0, 8)}...`,
        sha256: crypto.createHash('sha256').update(`${key}=${value}`).digest('hex'),
        processName: 'system',
      })
    }
  }

  return secrets
}

export function buildSecretFlowChains(
  secretAccesses: SecretAccess[],
  processes: BuildProcessEvent[],
  networkEvents: BuildNetEvent[],
): SecretFlowChain[] {
  const chains: SecretFlowChain[] = []

  const secretsWithPid = secretAccesses.filter(s => s.pid !== undefined)
  const pidToProcess = new Map(processes.map(p => [p.pid, p]))
  const pidToSecrets = new Map<number, SecretAccess[]>()
  const pidToNetwork = new Map<number, BuildNetEvent[]>()

  for (const s of secretsWithPid) {
    if (!pidToSecrets.has(s.pid!)) pidToSecrets.set(s.pid!, [])
    pidToSecrets.get(s.pid!)!.push(s)
  }

  for (const n of networkEvents) {
    for (const [pid] of pidToSecrets) {
      if (!pidToNetwork.has(pid)) pidToNetwork.set(pid, [])
      pidToNetwork.get(pid)!.push(n)
    }
  }

  for (const [pid, secrets] of pidToSecrets) {
    const proc = pidToProcess.get(pid)
    const netEvents = pidToNetwork.get(pid) || []
    const netAfterSecret = netEvents.filter(n => {
      const secretTime = Math.min(...secrets.map(s => s.timestamp || 0))
      return n.timestamp > secretTime
    })

    const severity = netAfterSecret.length > 0
      ? (secrets.some(s => s.severity === 'critical') ? 'critical' : 'high')
      : secrets.some(s => s.severity === 'critical') ? 'high' : 'medium'

    chains.push({
      processName: proc?.name || 'unknown',
      pid,
      processCmdline: proc?.cmdline || '',
      secrets,
      networkEvents: netAfterSecret,
      hasExfilRisk: netAfterSecret.length > 0,
      severity,
    })
  }

  return chains.sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3 }
    return (order[a.severity] || 0) - (order[b.severity] || 0)
  })
}

export function computeHermeticScore(
  processCount: number,
  networkCount: number,
  unknownToolCount: number,
  totalTools: number,
  pathChanges: number,
  contractViolations: number,
  ephemeralCount: number,
  secretCount: number,
): number {
  let score = 100

  score -= Math.min(networkCount * 8, 30)
  score -= Math.min(unknownToolCount * 5, 20)
  score -= Math.min(pathChanges * 5, 15)
  score -= Math.min(contractViolations * 10, 20)
  score -= Math.min(ephemeralCount * 2, 10)
  score -= Math.min(secretCount * 15, 30)

  return Math.max(0, Math.min(100, score))
}

export function computeReproducibilityScore(
  currentFingerprint: string,
  previousFingerprint: string | null,
  currentArtifacts: { sha256: string }[],
  previousArtifacts: { sha256: string }[] | null,
): { score: number; sameInputs: boolean; sameArtifacts: boolean; sameToolchain: boolean } {
  if (!previousFingerprint || !previousArtifacts) {
    return { score: 0, sameInputs: true, sameArtifacts: true, sameToolchain: true }
  }

  const sameInputs = currentFingerprint === previousFingerprint
  const currentArtMap = new Map(currentArtifacts.map(a => [a.sha256, true]))
  const prevArtSet = new Set(previousArtifacts.map(a => a.sha256))
  const sameArtifacts = currentArtifacts.length === previousArtifacts.length &&
    currentArtifacts.every(a => prevArtSet.has(a.sha256))

  let score = 100
  if (!sameInputs) score -= 30
  if (!sameArtifacts) score -= 40

  return { score: Math.max(0, score), sameInputs, sameArtifacts, sameToolchain: sameInputs }
}

export function renderSecretFlowChains(chains: SecretFlowChain[]): string[] {
  if (chains.length === 0) return ['No secret flows detected']

  const lines: string[] = ['Secret Flow Analysis', '====================']

  for (const chain of chains) {
    const icon = chain.severity === 'critical' ? '!' : chain.severity === 'high' ? '~' : '·'
    lines.push(`  ${icon} [${chain.severity.toUpperCase()}] ${chain.processName} (PID ${chain.pid}): ${chain.secrets.length} secret(s)`)
    if (chain.processCmdline) {
      lines.push(`      cmdline: ${chain.processCmdline.substring(0, 120)}`)
    }
    for (const s of chain.secrets.slice(0, 5)) {
      lines.push(`      ${s.type}: ${s.match} (line ${s.line})`)
    }
    if (chain.secrets.length > 5) {
      lines.push(`      ... and ${chain.secrets.length - 5} more secrets`)
    }
    if (chain.hasExfilRisk) {
      lines.push(`      ⚠ Exfiltration risk: ${chain.networkEvents.length} network event(s) after secret access`)
      for (const n of chain.networkEvents.slice(0, 3)) {
        if (n.type === 'tcp') {
          lines.push(`        TCP ${n.host}:${n.port || '?'}`)
        } else {
          lines.push(`        DNS ${n.host}`)
        }
      }
    }
  }

  return lines
}

export function renderHermeticScore(score: number): string[] {
  const bar = '█'.repeat(Math.round(score / 10)) + '░'.repeat(10 - Math.round(score / 10))
  const label = score >= 90 ? 'Hermetic' : score >= 70 ? 'Mostly Hermetic' : score >= 50 ? 'Partially Open' : 'Non-Hermetic'
  return [
    'Hermetic Build Score',
    '===================',
    `  ${bar} ${score}/100 — ${label}`,
  ]
}

export function renderReproducibilityScore(
  result: ReturnType<typeof computeReproducibilityScore>,
): string[] {
  const bar = '█'.repeat(Math.round(result.score / 10)) + '░'.repeat(10 - Math.round(result.score / 10))
  const lines: string[] = [
    'Reproducibility Score',
    '====================',
    `  ${bar} ${result.score}/100`,
    `  Same inputs: ${result.sameInputs ? 'Yes' : 'No'}`,
    `  Same artifacts: ${result.sameArtifacts ? 'Yes' : 'No'}`,
    `  Same toolchain: ${result.sameToolchain ? 'Yes' : 'No'}`,
  ]
  return lines
}
