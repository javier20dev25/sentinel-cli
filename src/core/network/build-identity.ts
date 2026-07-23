import * as os from 'os'
import * as fs from 'fs'
import * as crypto from 'crypto'
import { execFileSync } from 'child_process'
import { BuildIdentity, ToolIdentity } from './build-types'

export function captureBuildIdentity(): BuildIdentity {
  const toolVersions: Record<string, string> = {}
  const tools = ['gcc', 'g++', 'clang', 'clang++', 'ld', 'make', 'cmake', 'node', 'python', 'python3', 'rustc', 'cargo', 'go', 'javac', 'git']

  for (const tool of tools) {
    const v = tryToolVersion(tool)
    if (v) toolVersions[tool] = v
  }

  const hostname = os.hostname()
  const platform = os.platform()
  const arch = os.arch()
  const kernel = os.type()
  const kernelVersion = os.release()
  const cpus = os.cpus().length
  const memoryGb = Math.round((os.totalmem() / (1024 * 1024 * 1024)) * 10) / 10
  const uptimeHours = Math.round(os.uptime() / 3600 * 10) / 10

  const container = detectContainer()
  const ci = detectCi()
  const dockerImage = process.env['DOCKER_IMAGE'] || process.env['IMAGE_NAME'] || null

  let osVersion = kernelVersion
  try {
    if (platform === 'linux') {
      const r = execFileSync('cat', ['/etc/os-release'], { stdio: 'pipe', timeout: 3000, encoding: 'utf8' })
      const m = r.match(/PRETTY_NAME="(.+?)"/)
      if (m) osVersion = m[1]
    } else if (platform === 'win32') {
      const r = execFileSync('powershell', ['-Command', '(Get-CimInstance Win32_OperatingSystem).Caption'], { stdio: 'pipe', timeout: 3000, encoding: 'utf8' })
      osVersion = r.trim()
    } else if (platform === 'darwin') {
      const r = execFileSync('sw_vers', ['-productVersion'], { stdio: 'pipe', timeout: 3000, encoding: 'utf8' })
      osVersion = `macOS ${r.trim()}`
    }
  } catch {}

  const toolIdentities: ToolIdentity[] = []
  for (const tool of tools) {
    const ti = resolveToolIdentity(tool)
    if (ti) toolIdentities.push(ti)
  }

  const builderProcess = process.argv0 || process.title || 'unknown'

  return {
    hostname, platform, arch, kernel, kernelVersion,
    container, osVersion, cpus, memoryGb, uptimeHours,
    builderProcess,
    ciProvider: ci.provider,
    ciRunId: ci.runId,
    ciRunNumber: ci.runNumber,
    ciRepository: ci.repository,
    ciRef: ci.ref,
    ciSha: ci.sha,
    runnerName: ci.runnerName,
    runnerArch: ci.runnerArch,
    dockerImage,
    toolVersions,
    toolIdentities,
  }
}

function resolveToolIdentity(tool: string): ToolIdentity | null {
  const winTool = process.platform === 'win32' ? `${tool}.exe` : tool
  try {
    const which = process.platform === 'win32' ? 'where' : 'which'
    const r = execFileSync(which, [winTool], { stdio: 'pipe', timeout: 3000, encoding: 'utf8' })
    const resolved = r.split('\n')[0]?.trim()
    if (!resolved || !fs.existsSync(resolved)) return null

    const realPath = fs.realpathSync(resolved)
    const stat = fs.statSync(realPath)
    const buf = fs.readFileSync(realPath)
    const sha256 = crypto.createHash('sha256').update(buf).digest('hex')
    const version = tryToolVersion(tool)

    return {
      name: tool,
      realPath,
      sha256,
      size: stat.size,
      version,
      mtime: stat.mtime.toISOString(),
    }
  } catch {
    return null
  }
}

function tryToolVersion(tool: string): string | null {
  const winTool = process.platform === 'win32' ? `${tool}.exe` : tool
  const flags = ['--version', '-v', 'version']
  for (const flag of flags) {
    try {
      const r = execFileSync(winTool, [flag], { stdio: 'pipe', timeout: 3000, encoding: 'utf8', maxBuffer: 4096 })
      const line = r.split('\n')[0]?.trim()
      if (line && line.length < 200) return line
    } catch {}
  }
  try {
    const r = execFileSync(winTool, ['--version'], { stdio: 'pipe', timeout: 3000, encoding: 'utf8', maxBuffer: 4096 })
    const line = r.split('\n')[0]?.trim()
    if (line && line.length < 200) return line
  } catch {}
  return null
}

function detectContainer(): string | null {
  if (process.env['DOCKER_CONTAINER_ID']) return process.env['DOCKER_CONTAINER_ID']
  if (process.env['CONTAINER_ID']) return process.env['CONTAINER_ID']
  if (process.env['HOSTNAME'] && process.env['HOSTNAME']!.length === 12) return process.env['HOSTNAME']!
  try {
    if (process.platform === 'linux') {
      const r = execFileSync('cat', ['/proc/1/cgroup'], { stdio: 'pipe', timeout: 3000, encoding: 'utf8' })
      if (r.includes('docker') || r.includes('containerd') || r.includes('kubepods')) return 'container'
    }
  } catch {}
  return null
}

function detectCi(): { provider: string | null; runId: string | null; runNumber: string | null; repository: string | null; ref: string | null; sha: string | null; runnerName: string | null; runnerArch: string | null } {
  const env = process.env
  const result = { provider: null as string | null, runId: null as string | null, runNumber: null as string | null, repository: null as string | null, ref: null as string | null, sha: null as string | null, runnerName: null as string | null, runnerArch: null as string | null }

  if (env['GITHUB_ACTIONS']) {
    result.provider = 'github-actions'
    result.runId = env['GITHUB_RUN_ID'] || null
    result.runNumber = env['GITHUB_RUN_NUMBER'] || null
    result.repository = env['GITHUB_REPOSITORY'] || null
    result.ref = env['GITHUB_REF'] || null
    result.sha = env['GITHUB_SHA'] || null
    result.runnerName = env['RUNNER_NAME'] || null
    result.runnerArch = env['RUNNER_ARCH'] || null
  } else if (env['GITLAB_CI']) {
    result.provider = 'gitlab-ci'
    result.runId = env['CI_PIPELINE_ID'] || null
    result.runNumber = env['CI_JOB_ID'] || null
    result.repository = env['CI_PROJECT_PATH'] || null
    result.ref = env['CI_COMMIT_REF_NAME'] || null
    result.sha = env['CI_COMMIT_SHA'] || null
    result.runnerName = env['CI_RUNNER_DESCRIPTION'] || null
  } else if (env['JENKINS_URL']) {
    result.provider = 'jenkins'
    result.runId = env['BUILD_ID'] || null
    result.runNumber = env['BUILD_NUMBER'] || null
    result.repository = env['JOB_NAME'] || null
    result.ref = env['BRANCH_NAME'] || null
    result.sha = env['GIT_COMMIT'] || null
  } else if (env['CIRCLECI']) {
    result.provider = 'circleci'
    result.runId = env['CIRCLE_BUILD_NUM'] || null
    result.runNumber = env['CIRCLE_BUILD_NUM'] || null
    result.repository = env['CIRCLE_REPOSITORY_URL'] || null
    result.ref = env['CIRCLE_BRANCH'] || null
    result.sha = env['CIRCLE_SHA1'] || null
  } else if (env['TF_BUILD']) {
    result.provider = 'azure-devops'
    result.runId = env['BUILD_BUILDID'] || null
    result.runNumber = env['BUILD_BUILDNUMBER'] || null
    result.repository = env['BUILD_REPOSITORY_NAME'] || null
    result.ref = env['BUILD_SOURCEBRANCH'] || null
    result.sha = env['BUILD_SOURCEVERSION'] || null
  }

  return result
}
