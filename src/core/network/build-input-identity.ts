import * as fs from 'fs'
import * as path from 'path'
import * as crypto from 'crypto'
import {
  BuildInput, BuildInputCategory, BuildInputIdentity, InputChange,
  ScriptIdentity,
} from './build-types'

interface InputPattern {
  pattern: string
  category: BuildInputCategory
}

const BUILD_SYSTEM_FILES: InputPattern[] = [
  { pattern: 'Makefile', category: 'build_system' },
  { pattern: 'GNUmakefile', category: 'build_system' },
  { pattern: 'configure', category: 'build_system' },
  { pattern: 'configure.ac', category: 'build_system' },
  { pattern: 'config.status', category: 'build_system' },
  { pattern: 'CMakeLists.txt', category: 'build_system' },
  { pattern: 'meson.build', category: 'build_system' },
  { pattern: 'meson_options.txt', category: 'build_system' },
  { pattern: 'SConstruct', category: 'build_system' },
  { pattern: 'build.ninja', category: 'build_system' },
  { pattern: 'BUILD.bazel', category: 'build_system' },
  { pattern: 'WORKSPACE', category: 'build_system' },
]

const LANG_CONFIG_FILES: InputPattern[] = [
  { pattern: 'Cargo.toml', category: 'language_config' },
  { pattern: 'Cargo.lock', category: 'language_config' },
  { pattern: 'build.rs', category: 'language_config' },
  { pattern: 'go.mod', category: 'language_config' },
  { pattern: 'go.sum', category: 'language_config' },
  { pattern: 'pom.xml', category: 'language_config' },
  { pattern: 'build.gradle', category: 'language_config' },
  { pattern: 'build.gradle.kts', category: 'language_config' },
  { pattern: 'gradle.properties', category: 'language_config' },
  { pattern: 'settings.gradle', category: 'language_config' },
  { pattern: 'settings.gradle.kts', category: 'language_config' },
  { pattern: 'package.json', category: 'language_config' },
  { pattern: 'package-lock.json', category: 'language_config' },
  { pattern: 'pnpm-lock.yaml', category: 'language_config' },
  { pattern: 'yarn.lock', category: 'language_config' },
  { pattern: 'npm-shrinkwrap.json', category: 'language_config' },
  { pattern: 'requirements.txt', category: 'language_config' },
  { pattern: 'requirements.lock', category: 'language_config' },
  { pattern: 'pyproject.toml', category: 'language_config' },
  { pattern: 'setup.py', category: 'language_config' },
  { pattern: 'setup.cfg', category: 'language_config' },
  { pattern: 'Pipfile', category: 'language_config' },
  { pattern: 'Pipfile.lock', category: 'language_config' },
  { pattern: 'Cargo.lock', category: 'language_config' },
]

const CI_CONFIG_PREFIXES: InputPattern[] = [
  { pattern: '.github/workflows/', category: 'ci_config' },
  { pattern: '.gitlab-ci.yml', category: 'ci_config' },
  { pattern: 'azure-pipelines.yml', category: 'ci_config' },
  { pattern: '.circleci/', category: 'ci_config' },
  { pattern: 'Jenkinsfile', category: 'ci_config' },
  { pattern: 'Jenkinsfile.*', category: 'ci_config' },
  { pattern: '.woodpecker/', category: 'ci_config' },
  { pattern: '.drone.yml', category: 'ci_config' },
]

const SHELL_SCRIPT_EXTS = new Set(['.sh', '.ps1', '.bat', '.cmd', '.bash', '.zsh', '.fish'])

const NON_INPUT_DIRS = new Set(['.git', 'node_modules', 'target', 'build', 'dist', 'out', 'docs', '.vscode', '.idea', '__pycache__', '.venv', 'venv'])
const NON_INPUT_FILES = new Set(['README', 'README.md', 'README.rst', 'LICENSE', 'LICENSE.md', 'CHANGELOG', 'CHANGELOG.md', 'CONTRIBUTING.md', '.gitignore', '.gitattributes', '.editorconfig', '.prettierrc', '.eslintrc', '.eslintrc.json'])

export function categorizeFile(filePath: string, cwd: string): BuildInputCategory | null {
  const basename = path.basename(filePath)
  const relPath = path.relative(cwd, filePath).replace(/\\/g, '/')

  if (NON_INPUT_FILES.has(basename)) return null

  const allPatterns = [...BUILD_SYSTEM_FILES, ...LANG_CONFIG_FILES, ...CI_CONFIG_PREFIXES]
  for (const p of allPatterns) {
    if (relPath.endsWith(p.pattern) || basename === p.pattern) {
      return p.category
    }
  }

  const ext = path.extname(basename).toLowerCase()
  if (SHELL_SCRIPT_EXTS.has(ext)) return 'shell_script'

  if (relPath.startsWith('.github/workflows/') && (basename.endsWith('.yml') || basename.endsWith('.yaml'))) return 'ci_config'

  return null
}

export function isNonInputDir(dirName: string): boolean {
  const lower = dirName.toLowerCase()
  return NON_INPUT_DIRS.has(lower) || NON_INPUT_DIRS.has(dirName)
}

export function isNonInputFile(basename: string): boolean {
  return NON_INPUT_FILES.has(basename) || NON_INPUT_FILES.has(basename.toLowerCase())
}

export function scanBuildInputs(cwd: string): BuildInput[] {
  const inputs: BuildInput[] = []
  const seen = new Set<string>()

  walkForInputs(cwd, cwd, inputs, seen, 0)

  inputs.sort((a, b) => a.filePath.localeCompare(b.filePath))
  return inputs
}

function walkForInputs(dir: string, root: string, inputs: BuildInput[], seen: Set<string>, depth: number): void {
  if (depth > 6) return

  let entries: string[] = []
  try { entries = fs.readdirSync(dir) } catch { return }

  for (const entry of entries) {
    if (entry.startsWith('.')) continue
    const fullPath = path.join(dir, entry)

    let stat: fs.Stats
    try { stat = fs.statSync(fullPath) } catch { continue }

    if (stat.isDirectory()) {
      if (!isNonInputDir(entry)) {
        walkForInputs(fullPath, root, inputs, seen, depth + 1)
      }
      continue
    }

    if (!stat.isFile()) continue

    const relPath = path.relative(root, fullPath).replace(/\\/g, '/')
    if (seen.has(relPath)) continue
    seen.add(relPath)

    const category = categorizeFile(fullPath, root)
    if (!category) continue

    const input = buildInputFromFile(fullPath, relPath, category)
    if (input) inputs.push(input)
  }
}

export function buildInputFromFile(fullPath: string, relPath: string, category: BuildInputCategory): BuildInput | null {
  try {
    const stat = fs.statSync(fullPath)
    if (!stat.isFile()) return null

    const content = fs.readFileSync(fullPath)
    const sha256 = crypto.createHash('sha256').update(content).digest('hex')
    const permissions = (stat.mode & 0o777).toString(8).padStart(3, '0')
    let symlinkTarget: string | null = null
    try {
      if (stat.isSymbolicLink()) {
        symlinkTarget = fs.readlinkSync(fullPath)
      }
    } catch {}

    return {
      filePath: relPath,
      category,
      sha256,
      size: stat.size,
      mtime: stat.mtimeMs,
      permissions,
      owner: getOwner(fullPath),
      symlinkTarget,
      realPath: fs.realpathSync(fullPath),
      encoding: detectEncoding(content),
    }
  } catch { return null }
}

function getOwner(filePath: string): string {
  try {
    if (process.platform === 'win32') {
      return ''
    }
    const stat = fs.statSync(filePath)
    return `${stat.uid}:${stat.gid}`
  } catch { return '' }
}

function detectEncoding(buf: Buffer): string {
  if (buf.length === 0) return 'empty'
  if (buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) return 'utf-8-bom'
  if (buf.includes(0)) return 'binary'
  try {
    const str = buf.toString('utf-8')
    return str.includes('\u0000') ? 'binary' : 'utf-8'
  } catch { return 'binary' }
}

export function computeInputFingerprint(inputs: BuildInput[]): string {
  const sorted = [...inputs].sort((a, b) => a.filePath.localeCompare(b.filePath))
  const hash = crypto.createHash('sha256')
  for (const inp of sorted) {
    hash.update(`${inp.filePath}:${inp.sha256}:${inp.size}:${inp.permissions}\n`)
  }
  return hash.digest('hex')
}

export function computeInputStability(current: number, previous: number): number {
  if (previous === 0) return current === 0 ? 100 : 0
  return Math.round((current / previous) * 10000) / 100
}

export function diffInputs(previous: BuildInput[], current: BuildInput[]): InputChange[] {
  const changes: InputChange[] = []
  const prevMap = new Map(previous.map(i => [i.filePath, i]))
  const currMap = new Map(current.map(i => [i.filePath, i]))

  for (const [path, curr] of currMap) {
    const prev = prevMap.get(path)
    if (!prev) {
      changes.push({ input: curr, changeType: 'new' })
      continue
    }

    if (prev.sha256 !== curr.sha256) {
      changes.push({ input: curr, changeType: 'modified', previousSha256: prev.sha256 })
    } else {
      if (prev.permissions !== curr.permissions) {
        changes.push({ input: curr, changeType: 'permission_changed' })
      }
      if (prev.owner !== curr.owner) {
        changes.push({ input: curr, changeType: 'owner_changed' })
      }
      if (prev.symlinkTarget !== curr.symlinkTarget) {
        changes.push({ input: curr, changeType: 'symlink_changed' })
      }
    }
  }

  for (const [path, prev] of prevMap) {
    if (!currMap.has(path)) {
      changes.push({ input: prev, changeType: 'removed' })
    }
  }

  return changes
}

export function buildInputIdentity(cwd: string, prevInputs?: BuildInput[]): BuildInputIdentity {
  const inputs = scanBuildInputs(cwd)
  const changedInputs: InputChange[] = prevInputs ? diffInputs(prevInputs, inputs) : []
  const inputStability = prevInputs
    ? computeInputStability(inputs.length, prevInputs.length)
    : null

  return {
    inputs,
    totalInputs: inputs.length,
    inputFingerprint: computeInputFingerprint(inputs),
    inputStability,
    changedInputs,
  }
}

export function captureScriptIdentity(pid: number, cmdline: string): ScriptIdentity | null {
  try {
    const interpreter = cmdline.split(/\s+/)[0] || ''
    const interpRealPath = fs.realpathSync(interpreter)
    const interpContent = fs.readFileSync(interpreter)
    const interpSha256 = crypto.createHash('sha256').update(interpContent).digest('hex')

    let scriptPath = ''
    const parts = cmdline.split(/\s+/)
    for (let i = 1; i < parts.length; i++) {
      const p = parts[i]
      if (!p.startsWith('-') && (p.endsWith('.py') || p.endsWith('.sh') || p.endsWith('.js') || p.endsWith('.ts') || p.endsWith('.rb') || p.endsWith('.ps1') || p.endsWith('.bat') || p.endsWith('.cmd'))) {
        scriptPath = p
        break
      }
    }

    if (!scriptPath || !fs.existsSync(scriptPath)) return null

    const content = fs.readFileSync(scriptPath)
    const sha256 = crypto.createHash('sha256').update(content).digest('hex')
    const realPath = fs.realpathSync(scriptPath)
    const stat = fs.statSync(scriptPath)

    const imports = extractImports(content, scriptPath)

    return {
      filePath: path.resolve(scriptPath),
      sha256,
      argv: cmdline,
      interpreter,
      interpreterSha256: interpSha256,
      realPath,
      size: stat.size,
      mtime: stat.mtimeMs,
      imports,
    }
  } catch { return null }
}

function extractImports(content: Buffer, filePath: string): string[] {
  const imports: string[] = []
  const text = content.toString('utf-8')
  const ext = path.extname(filePath).toLowerCase()

  if (ext === '.py') {
    const re = /^(?:import\s+(\S+)|from\s+(\S+)\s+import)/gm
    let match
    while ((match = re.exec(text)) !== null) {
      imports.push(match[1] || match[2])
    }
  } else if (ext === '.js' || ext === '.ts') {
    const re = /(?:require\s*\(\s*['"](\S+?)['"]|from\s+['"](\S+?)['"])/g
    let match
    while ((match = re.exec(text)) !== null) {
      imports.push(match[1] || match[2])
    }
  } else if (ext === '.sh' || ext === '.bash') {
    const re = /^\s*source\s+(\S+)|\.\s+(\S+)/gm
    let match
    while ((match = re.exec(text)) !== null) {
      imports.push(match[1] || match[2])
    }
  }

  return [...new Set(imports)].slice(0, 50)
}

export function computeToolchainPurity(expected: string[], observed: string[]): number {
  if (expected.length === 0 && observed.length === 0) return 100
  if (expected.length === 0) return 0
  const expectedSet = new Set(expected)
  const expectedOnly = observed.filter(t => expectedSet.has(t)).length
  return Math.round((expectedOnly / Math.max(expected.length, 1)) * 100)
}

export function renderInputChanges(changes: InputChange[], limit = 15): string[] {
  if (changes.length === 0) return ['No input changes detected']

  const lines: string[] = [`Input Changes (${changes.length})`, '===================']
  for (const c of changes.slice(0, limit)) {
    const icon = c.changeType === 'new' ? '+' : c.changeType === 'removed' ? '-' : '~'
    lines.push(`  ${icon} [${c.changeType}] ${c.input.filePath} (${c.input.category})`)
    if (c.previousSha256) {
      lines.push(`      sha: ${c.previousSha256.substring(0, 12)} → ${c.input.sha256.substring(0, 12)}`)
    }
  }
  if (changes.length > limit) {
    lines.push(`  ... and ${changes.length - limit} more`)
  }
  return lines
}
