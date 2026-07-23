import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import { execFileSync } from 'child_process'

interface ValidationProject {
  name: string
  repo: string
  buildCommand: string
  buildArgs: string[]
  expectedTools: string[]
  expectedArtifacts: string[]
  maxDurationMs: number
}

interface ValidationResult {
  project: string
  success: boolean
  durationMs: number
  hermeticScore: number
  trustScore: number
  toolsDetected: string[]
  anomalies: string[]
  artifactCount: number
  error?: string
}

const PROJECTS: ValidationProject[] = [
  {
    name: 'redis',
    repo: 'https://github.com/redis/redis.git',
    buildCommand: 'make',
    buildArgs: ['-j4'],
    expectedTools: ['gcc', 'make', 'ld'],
    expectedArtifacts: ['redis-server', 'redis-cli'],
    maxDurationMs: 300_000,
  },
  {
    name: 'busybox',
    repo: 'https://github.com/mirror/busybox.git',
    buildCommand: 'make',
    buildArgs: ['-j4'],
    expectedTools: ['gcc', 'make', 'ld', 'ar'],
    expectedArtifacts: ['busybox'],
    maxDurationMs: 300_000,
  },
  {
    name: 'libsodium',
    repo: 'https://github.com/jedisct1/libsodium.git',
    buildCommand: 'make',
    buildArgs: ['-j4'],
    expectedTools: ['gcc', 'make', 'ld', 'ar', 'ranlib'],
    expectedArtifacts: ['libsodium.a', 'libsodium.so'],
    maxDurationMs: 300_000,
  },
  {
    name: 'hello-node',
    repo: 'https://github.com/mikenye/hello-node.git',
    buildCommand: 'npm',
    buildArgs: ['install'],
    expectedTools: ['node', 'npm'],
    expectedArtifacts: [],
    maxDurationMs: 120_000,
  },
]

const PROJECTS_DIR = path.join(os.homedir(), '.sentinel', 'validation-projects')
const RESULTS_DIR = path.join(os.homedir(), '.sentinel', 'validation-results')

fs.mkdirSync(PROJECTS_DIR, { recursive: true })
fs.mkdirSync(RESULTS_DIR, { recursive: true })

function ensureProject(project: ValidationProject): string {
  const projectDir = path.join(PROJECTS_DIR, project.name)

  if (!fs.existsSync(projectDir) || !fs.readdirSync(projectDir).length) {
    console.log(`  Cloning ${project.repo}...`)
    fs.mkdirSync(projectDir, { recursive: true })
    execFileSync('git', ['clone', '--depth=1', project.repo, projectDir], {
      stdio: 'pipe', timeout: 120_000, encoding: 'utf8',
    })
  }

  return projectDir
}

async function validateProject(project: ValidationProject): Promise<ValidationResult> {
  const startTime = Date.now()
  console.log(`\nValidating ${project.name}...`)
  console.log(`  Command: ${project.buildCommand} ${project.buildArgs.join(' ')}`)

  const projectDir = ensureProject(project)
  if (!fs.existsSync(path.join(projectDir, 'Makefile')) && !fs.existsSync(path.join(projectDir, 'CMakeLists.txt')) && !fs.existsSync(path.join(projectDir, 'package.json'))) {
    return {
      project: project.name,
      success: false,
      durationMs: Date.now() - startTime,
      hermeticScore: 0,
      trustScore: 0,
      toolsDetected: [],
      anomalies: ['No build files found'],
      artifactCount: 0,
      error: 'No build files found',
    }
  }

  try {
    const { recordBuild } = await import('../src/cli/build/build-recorder')
    const record = await recordBuild(project.buildCommand, project.buildArgs, projectDir, project.maxDurationMs)

    const toolsFound = record.summary.uniqueProcesses
    const missingTools = project.expectedTools.filter(t => !toolsFound.includes(t))
    const artifactsFound = record.artifactHashes.map(a => a.filePath.split(/[/\\]/).pop() || '')
    const missingArtifacts = project.expectedArtifacts.filter(a => !artifactsFound.some(f => f.includes(a)))
    const anomalies = record.summary.anomalies
    const hermeticScore = record.hermetricScore || 0
    const trustScore = record.trustResult?.overallTrust || 0

    if (missingTools.length > 0) {
      anomalies.push(`Expected tools not found: ${missingTools.join(', ')}`)
    }
    if (missingArtifacts.length > 0) {
      anomalies.push(`Expected artifacts not found: ${missingArtifacts.join(', ')}`)
    }

    const durationMs = Date.now() - startTime
    const success = missingTools.length === 0 && record.summary.anomalies.length <= 3

    console.log(`  Result: ${success ? 'PASS' : 'FAIL'}`)
    console.log(`  Duration: ${durationMs}ms`)
    console.log(`  Hermetic Score: ${hermeticScore}/100`)
    console.log(`  Trust Score: ${trustScore}/100`)
    console.log(`  Anomalies: ${anomalies.length}`)

    return {
      project: project.name,
      success,
      durationMs,
      hermeticScore,
      trustScore,
      toolsDetected: toolsFound,
      anomalies,
      artifactCount: record.artifactHashes.length,
    }
  } catch (e: any) {
    console.log(`  Error: ${e.message}`)
    return {
      project: project.name,
      success: false,
      durationMs: Date.now() - startTime,
      hermeticScore: 0,
      trustScore: 0,
      toolsDetected: [],
      anomalies: [e.message],
      artifactCount: 0,
      error: e.message,
    }
  }
}

async function main() {
  console.log('Sentinel External Validation Framework')
  console.log('=====================================')
  console.log(`Projects directory: ${PROJECTS_DIR}`)
  console.log(`Results directory: ${RESULTS_DIR}`)
  console.log(`Projects: ${PROJECTS.length}`)
  console.log()

  const results: ValidationResult[] = []
  for (const project of PROJECTS) {
    const result = await validateProject(project)
    results.push(result)
  }

  const summaryPath = path.join(RESULTS_DIR, `validation-${Date.now()}.json`)
  fs.writeFileSync(summaryPath, JSON.stringify({ results, timestamp: new Date().toISOString() }, null, 2))

  console.log('\n\nValidation Summary')
  console.log('=================')
  const passed = results.filter(r => r.success).length
  const failed = results.filter(r => !r.success).length

  for (const r of results) {
    const icon = r.success ? '✓' : '✗'
    console.log(`  ${icon} ${r.project}: ${r.success ? 'PASS' : 'FAIL'} (hermetic=${r.hermeticScore}/100, trust=${r.trustScore}/100, ${r.durationMs}ms)`)
  }

  console.log(`\nPassed: ${passed}/${results.length}, Failed: ${failed}/${results.length}`)
  console.log(`Results saved to: ${summaryPath}`)
}

main().catch(console.error)
