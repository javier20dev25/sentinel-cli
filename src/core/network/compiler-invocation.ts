import * as fs from 'fs'
import * as crypto from 'crypto'
import { BuildProcessEvent, BuildFileEvent, ResponseFileChange, CompilerInvocation, CompilerInvocationIdentity } from './build-types'

const COMPILER_NAMES = new Set([
  'gcc', 'g++', 'clang', 'clang++', 'cc', 'c++',
  'rustc', 'javac', 'zig', 'dmd', 'ldc', 'gdc',
  'emcc', 'em++', 'emar',
])

const LINKER_NAMES = new Set([
  'ld', 'ld.lld', 'lld-link', 'link', 'link.exe',
])

const SUSPICIOUS_FLAGS = [
  '-fplugin', '-fmodules', '-fno-stack-protector',
  '-fno-pie', '-no-pie', '-z execstack',
  '-Wl,--enable-new-dtags', '-Wl,-rpath,',
]

export function isCompilerOrLinker(name: string): boolean {
  return COMPILER_NAMES.has(name) || LINKER_NAMES.has(name)
}

export function extractCompilerInvocation(
  proc: BuildProcessEvent,
  cwd: string,
): CompilerInvocation | null {
  if (!isCompilerOrLinker(proc.name)) return null

  const argv = parseArgv(proc.cmdline)
  const responseFiles: string[] = []
  const responseFileContent: string[] = []
  const inputFiles: string[] = []
  const outputFiles: string[] = []
  const flags: string[] = []
  const defines: string[] = []
  const includeDirs: string[] = []

  for (const arg of argv) {
    if (arg.startsWith('@')) {
      const rfPath = arg.substring(1)
      responseFiles.push(rfPath)
      try {
        const absRfPath = rfPath.startsWith('/') || rfPath.match(/^[a-zA-Z]:\\/)
          ? rfPath
          : require('path').resolve(cwd, rfPath)
        if (fs.existsSync(absRfPath)) {
          const content = fs.readFileSync(absRfPath, 'utf-8')
          responseFileContent.push(content)
        }
      } catch {}
    } else if (arg === '-o' || arg.startsWith('/Fo')) {
      if (arg.startsWith('/Fo')) {
        outputFiles.push(arg.substring(3))
      }
    } else if (arg.startsWith('-D')) {
      defines.push(arg)
    } else if (arg.startsWith('-I') || arg.startsWith('/I')) {
      includeDirs.push(arg)
    } else if (arg.startsWith('-')) {
      if (!arg.startsWith('-D') && !arg.startsWith('-I')) {
        flags.push(arg)
      }
    } else if (!arg.startsWith('-')) {
      const ext = arg.split('.').pop()?.toLowerCase()
      if (ext && ['c', 'cc', 'cpp', 'cxx', 'c++', 'm', 'mm', 'rs', 'java', 'go', 's', 'S', 'asm', 'o', 'obj', 'a', 'lib', 'rlib'].includes(ext)) {
        inputFiles.push(arg)
      }
    }
  }

  const nextIsOutput = argv.indexOf('-o')
  if (nextIsOutput >= 0 && nextIsOutput + 1 < argv.length) {
    outputFiles.push(argv[nextIsOutput + 1])
  }

  const hasResponseFile = responseFiles.length > 0
  const hasStdinInput = argv.includes('-') || proc.cmdline.includes(' -c ') || proc.cmdline.includes(' -x c')

  const hasDash = argv.includes('-')
  const hasDashC = argv.some(a => a === '-c' || a === '-x')
  const effectiveStdin = hasStdinInput || (hasDash && inputFiles.length === 0)

  const fromMemfd = inputFiles.length === 0 && !effectiveStdin && argv.length > 1

  const envSnapshot: Record<string, string> = {}
  const globalEnv = process.env
  for (const key of ['CC', 'CXX', 'CFLAGS', 'CXXFLAGS', 'LDFLAGS', 'LD_LIBRARY_PATH', 'CPATH', 'LIBRARY_PATH', 'INCLUDE']) {
    const val = globalEnv[key]
    if (val !== undefined) envSnapshot[key] = val
  }

  return {
    tool: proc.name,
    argv,
    cwd,
    responseFiles,
    responseFileContent,
    envSnapshot,
    pid: proc.pid,
    timestamp: proc.timestamp,
    inputFiles,
    outputFiles,
    flags,
    defines,
    includeDirs,
    hasResponseFile,
    hasStdinInput,
    fromStdin: effectiveStdin || undefined,
    fromMemfd: fromMemfd || undefined,
  }
}

function parseArgv(cmdline: string): string[] {
  const args: string[] = []
  let current = ''
  let inQuote = false
  let quoteChar = ''

  for (let i = 0; i < cmdline.length; i++) {
    const c = cmdline[i]
    if (inQuote) {
      if (c === quoteChar) {
        inQuote = false
      } else {
        current += c
      }
    } else if (c === '"' || c === "'") {
      inQuote = true
      quoteChar = c
    } else if (c === ' ') {
      if (current) {
        args.push(current)
        current = ''
      }
    } else {
      current += c
    }
  }
  if (current) args.push(current)

  return args
}

export function analyzeCompilerInvocations(
  processes: BuildProcessEvent[],
  cwd: string,
): CompilerInvocationIdentity {
  const invocations: CompilerInvocation[] = []
  const allFlags = new Set<string>()
  const suspicious: string[] = []

  for (const p of processes) {
    const inv = extractCompilerInvocation(p, cwd)
    if (!inv) continue
    invocations.push(inv)

    for (const f of inv.flags) allFlags.add(f)

    for (const sf of SUSPICIOUS_FLAGS) {
      if (inv.flags.some(f => f.includes(sf))) {
        suspicious.push(`${inv.tool} (PID ${inv.pid}): flag "${sf}" in ${inv.argv.join(' ').substring(0, 100)}`)
      }
    }

    if (inv.hasResponseFile) {
      for (const rf of inv.responseFileContent) {
        for (const sf of SUSPICIOUS_FLAGS) {
          if (rf.includes(sf)) {
            suspicious.push(`${inv.tool} (PID ${inv.pid}): flag "${sf}" in response file ${inv.responseFiles[0]}`)
          }
        }
      }
    }
  }

  return {
    invocations,
    totalInvocations: invocations.length,
    uniqueFlags: [...allFlags].sort(),
    suspiciousInvocations: suspicious,
    stdinInvocations: invocations.filter(i => i.fromStdin).length,
    memfdInvocations: invocations.filter(i => i.fromMemfd).length,
  }
}

export function detectResponseFileChanges(
  invocations: CompilerInvocation[],
): ResponseFileChange[] {
  const changes: ResponseFileChange[] = []
  for (const inv of invocations) {
    if (!inv.hasResponseFile) continue
    for (let i = 0; i < inv.responseFiles.length; i++) {
      const rf = inv.responseFiles[i]
      const originalContent = inv.responseFileContent[i] || ''
      const originalSha256 = crypto.createHash('sha256').update(originalContent).digest('hex')
      let currentSha256 = originalSha256
      let changed = false
      try {
        const absRfPath = rf.startsWith('/') || rf.match(/^[a-zA-Z]:\\/)
          ? rf
          : require('path').resolve(inv.cwd, rf)
        if (fs.existsSync(absRfPath)) {
          const currentContent = fs.readFileSync(absRfPath, 'utf-8')
          currentSha256 = crypto.createHash('sha256').update(currentContent).digest('hex')
          changed = currentSha256 !== originalSha256
        }
      } catch {}
      changes.push({
        tool: inv.tool,
        pid: inv.pid,
        responseFile: rf,
        originalSha256,
        currentSha256,
        changed,
        timestamp: Date.now(),
      })
    }
  }
  return changes
}

export function renderCompilerInvocations(identity: CompilerInvocationIdentity): string[] {
  if (identity.totalInvocations === 0) return ['No compiler invocations detected']

  const lines: string[] = [
    'Compiler Invocation Identity',
    '===========================',
    `Total invocations: ${identity.totalInvocations}`,
    `Unique flags: ${identity.uniqueFlags.length}`,
    '',
  ]

  for (const inv of identity.invocations.slice(0, 20)) {
    lines.push(`  ${inv.tool} (PID ${inv.pid})`)
    if (inv.hasResponseFile) {
      lines.push(`    Response file: ${inv.responseFiles[0]} (${inv.responseFileContent[0]?.length || 0}B)`)
    }
    if (inv.inputFiles.length > 0) {
      lines.push(`    Inputs: ${inv.inputFiles.slice(0, 5).join(', ')}${inv.inputFiles.length > 5 ? ` +${inv.inputFiles.length - 5}` : ''}`)
    }
    if (inv.outputFiles.length > 0) {
      lines.push(`    Outputs: ${inv.outputFiles.join(', ')}`)
    }
    if (inv.flags.length > 0) {
      const shortFlags = inv.flags.slice(0, 8).join(' ')
      lines.push(`    Flags: ${shortFlags}${inv.flags.length > 8 ? '...' : ''}`)
    }
    if (inv.defines.length > 0) {
      lines.push(`    Defines: ${inv.defines.join(' ')}`)
    }
  }

  if (identity.suspiciousInvocations.length > 0) {
    lines.push('', '⚠ Suspicious Invocations:')
    for (const s of identity.suspiciousInvocations) {
      lines.push(`  ${s}`)
    }
  }

  return lines
}
