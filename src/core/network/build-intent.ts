import { BuildRecord, BuildIntentStep, BuildIntentFlow, ProcessIntent } from './build-types'

const INTENT_MAP: Record<string, ProcessIntent> = {
  configure: 'configure',
  autoconf: 'configure',
  automake: 'configure',
  cmake: 'configure',
  meson: 'configure',
  './configure': 'configure',
  gcc: 'compile',
  'g++': 'compile',
  clang: 'compile',
  'clang++': 'compile',
  cc: 'compile',
  'c++': 'compile',
  rustc: 'compile',
  javac: 'compile',
  ld: 'link',
  'ld.lld': 'link',
  'lld-link': 'link',
  link: 'link',
  'link.exe': 'link',
  ar: 'archive',
  'lib.exe': 'archive',
  ranlib: 'archive',
  curl: 'download',
  wget: 'download',
  fetch: 'download',
  python: 'script',
  python3: 'script',
  node: 'script',
  ruby: 'script',
  perl: 'script',
  bash: 'script',
  sh: 'script',
  zsh: 'script',
  make: 'package',
  ninja: 'package',
  cargo: 'package',
  go: 'package',
  npm: 'install',
  npx: 'install',
  pip: 'install',
  pip3: 'install',
  yarn: 'install',
  pnpm: 'install',
  nuget: 'install',
  dotnet: 'package',
}

const STAGE_ORDER: ProcessIntent[] = [
  'configure',
  'compile',
  'archive',
  'link',
  'download',
  'package',
  'script',
  'test',
  'install',
]

const COMPILERS = new Set(['gcc', 'g++', 'clang', 'clang++', 'cc', 'c++', 'rustc', 'javac'])
const LINKERS = new Set(['ld', 'ld.lld', 'lld-link', 'link', 'link.exe'])
const DOWNLOADERS = new Set(['curl', 'wget', 'fetch'])
const SCRIPTS = new Set(['python', 'python3', 'node', 'ruby', 'perl', 'bash', 'sh', 'zsh'])

export function classifyIntent(toolName: string, cmdline: string): ProcessIntent {
  if (INTENT_MAP[toolName]) return INTENT_MAP[toolName]

  if (DOWNLOADERS.has(toolName)) return 'download'
  if (COMPILERS.has(toolName)) return 'compile'
  if (LINKERS.has(toolName)) return 'link'
  if (SCRIPTS.has(toolName)) return 'script'

  if (cmdline.includes('configure')) return 'configure'
  if (cmdline.includes('-c') && COMPILERS.has(toolName)) return 'compile'
  if (cmdline.includes('-o')) {
    if (LINKERS.has(toolName)) return 'link'
    if (COMPILERS.has(toolName)) return 'compile'
  }

  return 'unknown'
}

export function buildIntentFlow(record: BuildRecord): BuildIntentFlow {
  const steps: BuildIntentStep[] = record.processes
    .filter(p => p.exitTime)
    .map(p => ({
      tool: p.name,
      intent: classifyIntent(p.name, p.cmdline),
      timestamp: p.timestamp,
      durationMs: p.exitTime! - (p.startTime || p.timestamp),
    }))
    .sort((a, b) => a.timestamp - b.timestamp)

  const observed = steps.map(s => s.intent)
  const uniqueObserved = [...new Set(observed)]

  const expected = STAGE_ORDER.filter(s => {
    const matching = steps.some(step => step.intent === s)
    if (matching) return true
    if (s === 'configure' && record.inputIdentity?.inputs.some(i => i.category === 'build_system')) return true
    return false
  })

  const deviations: string[] = []

  for (let i = 0; i < observed.length - 1; i++) {
    const curr = observed[i]
    const next = observed[i + 1]
    const currIdx = STAGE_ORDER.indexOf(curr)
    const nextIdx = STAGE_ORDER.indexOf(next)

    if (currIdx >= 0 && nextIdx >= 0 && nextIdx < currIdx) {
      deviations.push(`Unexpected order: "${curr}" followed by "${next}" (expected ${expected.join(' → ')})`)
    }
  }

  const unexpected = uniqueObserved.filter(s => !expected.includes(s))
  for (const u of unexpected) {
    if (u !== 'unknown') {
      deviations.push(`Unexpected stage: "${u}" not in expected flow (${expected.join(' → ')})`)
    }
  }

  return { expected, observed: uniqueObserved, deviations }
}

export function renderIntentFlow(flow: BuildIntentFlow): string[] {
  const lines: string[] = [
    'Build Intent Flow',
    '================',
    `Expected: ${flow.expected.join(' → ')}`,
    `Observed: ${flow.observed.join(' → ')}`,
  ]

  if (flow.deviations.length > 0) {
    lines.push('', 'Deviations:')
    for (const d of flow.deviations) {
      lines.push(`  ⚠ ${d}`)
    }
  } else {
    lines.push('', '  ✓ Flow matches expectations')
  }

  return lines
}
