import { LiteFinding } from './lite/lite_scanner'

export interface AgencyDriver {
  subcode: string
  title: string
  category: string
  riskScore: number
  contribution: number
  confidence: string
  file: string
  line: number
}

export interface AgencyCorrelation {
  description: string
  bonus: number
  involved: string[]
}

export interface AgencyScoreResult {
  agencyScore: number
  blastRadius: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  verdict: 'PASS' | 'REVIEW' | 'BLOCK'
  drivers: AgencyDriver[]
  correlations: AgencyCorrelation[]
  totalFindings: number
  criticalCount: number
  highCount: number
  recommendation: string
}

const DIMINISHING_MULTIPLIERS = [1.0, 0.5, 0.25, 0.125, 0.0625, 0.03125, 0.015625, 0.0078125, 0.00390625, 0.001953125]

const CATEGORY_MULTIPLIERS: Record<string, number> = {
  obfuscation: 1.3,
  malware: 1.5,
  'ci-cd': 1.2,
  'ci-supply-chain': 1.2,
  secrets: 1.0,
  'supply-chain': 1.4,
  injection: 1.2,
  misconfig: 1.0,
  'ci-evasion': 1.3,
  agent: 1.3,
  workflow: 1.2,
  token: 1.1,
  generic: 1.0,
}

function getVerdict(score: number): AgencyScoreResult['verdict'] {
  if (score >= 70) return 'BLOCK'
  if (score >= 30) return 'REVIEW'
  return 'PASS'
}

function getBlastRadius(score: number): AgencyScoreResult['blastRadius'] {
  if (score >= 75) return 'CRITICAL'
  if (score >= 50) return 'HIGH'
  if (score >= 25) return 'MEDIUM'
  return 'LOW'
}

export function detectCorrelations(findings: LiteFinding[]): AgencyCorrelation[] {
  const correlations: AgencyCorrelation[] = []
  if (findings.length === 0) return correlations

  const threatTypes = new Set(findings.map(f => f.type).filter(Boolean))
  const fileCategories = new Map<string, Set<string>>()

  for (const f of findings) {
    const cat = f.category || 'generic'
    const file = f.file || 'unknown'
    if (!fileCategories.has(file)) fileCategories.set(file, new Set())
    fileCategories.get(file)!.add(cat)
  }

  const categoryFiles = new Map<string, Set<string>>()
  Array.from(fileCategories.entries()).forEach(([file, cats]) => {
    Array.from(cats).forEach(cat => {
      if (!categoryFiles.has(cat)) categoryFiles.set(cat, new Set())
      categoryFiles.get(cat)!.add(file)
    })
  })

  Array.from(categoryFiles.entries()).forEach(([cat, files]) => {
    if (files.size >= 2) {
      const bonus = (files.size - 1) * -5
      correlations.push({
        description: `Same category "${cat}" in ${files.size} files`,
        bonus,
        involved: Array.from(files),
      })
    }
  })

  if (findings.some(f => f.type === 'TOKEN_RISK' || f.category === 'supply-chain') &&
      findings.some(f => f.category === 'obfuscation' || f.type === 'HIGH_ENTROPY')) {
    correlations.push({
      description: 'Supply-chain risk with obfuscation — potential exfiltration pattern',
      bonus: -12,
      involved: ['supply-chain', 'obfuscation'],
    })
  }

  const obfuscationTypes = ['HIGH_ENTROPY', 'OBFUSCATED_HEX_PAYLOAD', 'OBF-ENTROPY']
  const hasObfuscation = findings.some(f => obfuscationTypes.includes(f.type) || f.category === 'obfuscation')
  const hasMalware = findings.some(f => f.category === 'malware')
  if (hasObfuscation && hasMalware) {
    correlations.push({
      description: 'Obfuscation with malware patterns — potential evasion',
      bonus: -10,
      involved: ['obfuscation', 'malware'],
    })
  }

  const ciEvasionCount = findings.filter(f =>
    f.subcode && (f.subcode.startsWith('WF-') || f.subcode.startsWith('TOK-'))
  ).length
  if (ciEvasionCount >= 2) {
    correlations.push({
      description: `Multiple CI/CD risk indicators (${ciEvasionCount})`,
      bonus: -9,
      involved: findings.filter(f => f.subcode && (f.subcode.startsWith('WF-') || f.subcode.startsWith('TOK-'))).map(f => f.subcode as string),
    })
  }

  Array.from(fileCategories.entries()).forEach(([file, cats]) => {
    if (cats.size >= 3) {
      correlations.push({
        description: `File "${file}" triggers ${cats.size} different categories`,
        bonus: -10,
        involved: Array.from(cats),
      })
    }
  })

  return correlations
}

export function generateRecommendation(findings: LiteFinding[], drivers: AgencyDriver[]): string {
  const steps: string[] = []

  if (drivers.some(d => d.category === 'malware')) {
    steps.push('Remove or refactor code flagged for malware patterns')
  }

  if (drivers.some(d => d.category === 'secret' || d.category === 'secrets')) {
    steps.push('Remove hardcoded secrets and use environment variables or vault')
  }

  if (drivers.some(d => d.category === 'ci-cd' || d.category === 'ci-supply-chain')) {
    steps.push('Pin workflow actions to commit SHAs and remove write-all permissions')
  }

  if (drivers.some(d => d.category === 'workflow')) {
    steps.push('Review workflow configuration for supply chain risks')
  }

  if (drivers.some(d => d.category === 'obfuscation')) {
    steps.push('Deobfuscate code and ensure transparency')
  }

  if (drivers.some(d => d.category === 'supply-chain')) {
    steps.push('Audit dependencies and verify registry integrity')
  }

  if (drivers.some(d => d.category === 'agent')) {
    steps.push('Review agent configuration for dangerous capabilities')
  }

  if (drivers.some(d => d.category === 'token')) {
    steps.push('Restrict token permissions to minimum required scope')
  }

  if (findings.some(f => f.type === 'INJECTION_DYNAMIC_EXEC')) {
    steps.push('Avoid dynamic code execution (eval, Function, exec) with untrusted input')
  }

  if (steps.length === 0) {
    return 'No action required'
  }

  return steps.join('; ')
}

export function calculateAgencyScore(findings: LiteFinding[]): AgencyScoreResult {
  const scored = findings.filter(f => f.riskScore && f.riskScore > 0)

  if (scored.length === 0) {
    return {
      agencyScore: 0,
      blastRadius: 'LOW',
      verdict: 'PASS',
      drivers: [],
      correlations: [],
      totalFindings: 0,
      criticalCount: 0,
      highCount: 0,
      recommendation: 'No action required',
    }
  }

  const sorted = [...scored].sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0))

  let total = 0
  const drivers: AgencyDriver[] = []

  for (let i = 0; i < sorted.length && i < DIMINISHING_MULTIPLIERS.length; i++) {
    const f = sorted[i]
    const riskScore = f.riskScore || 0
    const category = f.category || 'generic'
    const catMult = CATEGORY_MULTIPLIERS[category] || 1.0
    const mult = DIMINISHING_MULTIPLIERS[i]
    const contribution = Math.round(riskScore * mult * catMult)
    total += contribution
    drivers.push({
      subcode: f.subcode || '',
      title: f.title || '',
      category,
      riskScore,
      contribution,
      confidence: f.confidence || 'high',
      file: f.file || '',
      line: f.line || 0,
    })
  }

  const correlations = detectCorrelations(findings)
  for (const corr of correlations) {
    total += corr.bonus
  }

  total = Math.max(0, Math.min(100, Math.round(total)))

  const recommendation = generateRecommendation(findings, drivers)

  return {
    agencyScore: total,
    blastRadius: getBlastRadius(total),
    verdict: getVerdict(total),
    drivers,
    correlations,
    totalFindings: scored.length,
    criticalCount: scored.filter(f => f.severity === 'CRITICAL').length,
    highCount: scored.filter(f => f.severity === 'HIGH').length,
    recommendation,
  }
}
