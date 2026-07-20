export interface BuildProcessEvent {
  pid: number
  name: string
  cmdline: string
  ppid: number
  pname: string
  timestamp: number
}

export interface BuildFileEvent {
  filePath: string
  size: number
  operation: 'created' | 'modified'
  timestamp: number
}

export interface BuildNetEvent {
  type: 'tcp' | 'dns'
  host: string
  port?: number
  timestamp: number
}

export interface BuildStep {
  name: string
  tool: string
  durationMs: number
  exitCode: number | null
  children: BuildStep[]
}

export interface BuildChainLink {
  index: number
  timestamp: number
  eventType: string
  eventFingerprint: string
  previousHash: string
  linkHash: string
}

export interface BuildRecord {
  command: string
  args: string[]
  cwd: string
  startTime: string
  durationMs: number
  exitCode: number | null
  platform: string
  nodeVersion: string
  processes: BuildProcessEvent[]
  files: BuildFileEvent[]
  network: BuildNetEvent[]
  summary: BuildSummary
  hashChain: BuildChainLink[]
}

export interface ProcessNode {
  name: string
  pid: number
  ppid: number
  cmdline: string
  children: ProcessNode[]
}

export interface BuildSummary {
  totalProcesses: number
  uniqueProcesses: string[]
  buildToolsDetected: string[]
  filesCreated: number
  filesModified: number
  networkConnections: number
  dnsQueries: string[]
  anomalies: string[]
  processTree: ProcessNode[]
  totalHashLinks: number
}

export const BUILD_TOOLS = new Set([
  'gcc', 'g++', 'clang', 'clang++', 'cl.exe', 'cl', 'link.exe', 'link',
  'ld', 'ld.lld', 'lld-link', 'ar', 'lib.exe',
  'make', 'cmake', 'ninja', 'nmake', 'msbuild',
  'cargo', 'rustc', 'go', 'javac', 'kotlinc',
  'node', 'tsc', 'esbuild', 'webpack', 'rollup', 'vite',
  'python', 'python3', 'pip', 'pip3',
  'cc', 'c++', 'gcc-*', 'g++-*',
])

export const DANGEROUS_BUILD_TOOLS = new Set([
  'curl', 'wget', 'fetch', 'axel', 'aria2c',
  'bash', 'sh', 'zsh', 'powershell', 'pwsh', 'cmd.exe',
  'perl', 'ruby', 'lua',
  'openssl', 'base64',
  'telnet', 'nc', 'ncat', 'socat',
  'gdb', 'lldb', 'objdump', 'readelf', 'strings',
])
