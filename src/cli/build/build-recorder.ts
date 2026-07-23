import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import * as crypto from 'crypto'
import { spawn, ChildProcess, execFileSync } from 'child_process'
import {
  BuildRecord, BuildProcessEvent, BuildFileEvent, BuildNetEvent,
  BuildChainLink, BuildSummary, ProcessNode, ArtifactHash, FileReadEvent,
  BuildInputIdentity, ScriptIdentity, PathState, TrustResult,
  BUILD_TOOLS, DANGEROUS_BUILD_TOOLS, BUILD_ENV_KEYS, BuildIdentity,
  SecretFlow, SecretFlowChain, CompilerInvocationIdentity,
  RecordOptions, ObservationConfidence, OrphanProcessInfo, NamedPipeEvent,
  ProcessMaps, ResponseFileChange, EvidenceSource,
} from '../../core/network/build-types'
import { captureBuildIdentity } from '../../core/network/build-identity'
import { capturePreBuildInventory, pollProcessOpenFiles, detectReadFilesPostBuild, deduplicateReadEvents } from '../../core/network/file-read-provenance'
import { buildInputIdentity, captureScriptIdentity } from '../../core/network/build-input-identity'
import { capturePathState } from '../../core/network/path-resolution'
import { computeTrust } from '../../core/network/build-trust-engine'
import { trackProcessExits, findEphemeralProcesses, classifyEphemeralProcesses } from '../../core/network/process-lifetime'
import { buildIntentFlow } from '../../core/network/build-intent'
import { loadContract, updateContract, saveContract } from '../../core/network/build-contract'
import { classifyIntent } from '../../core/network/build-intent'
import {
  scanProcessReadsForSecrets, scanEnvForSecrets, buildSecretFlowChains,
  computeHermeticScore, computeReproducibilityScore,
} from '../../core/network/secret-flow'
import {
  analyzeCompilerInvocations, detectResponseFileChanges,
} from '../../core/network/compiler-invocation'
import { computeObservationConfidence, propagateGraphConfidence, findConfidencePaths } from '../../core/network/evidence-reliability'
import { buildEvidenceGraph } from '../../core/network/evidence-graph'
import { buildProcessTimelines } from '../../core/network/process-timeline'
import { extractFeatureVector, autoLabel, getDefaultStore } from '../../core/network/trust-calibration'
import {
  detectOrphanProcesses, detectNamedPipes, captureProcessMaps,
  detectDnsOverHttps, detectEphemeralProcesses, detectFilelessExecution,
  inferEvidenceSource,
} from '../../core/network/evasion-detection'

const POLL_PROCESS_MS = 200
const POLL_FILE_MS = 1000
const POLL_NET_MS = 2000
const POLL_READ_MS = 1500

interface ProcessEntry {
  pid: number
  name: string
  cmdline: string
  ppid: number
}

let _pwarned = false

function getProcessList(): ProcessEntry[] {
  try {
    if (process.platform === 'win32') {
      if (!_pwarned) { _pwarned = true }
      const out = execFileSync('powershell', [
        '-NoProfile', '-Command',
        'Get-CimInstance Win32_Process | Select-Object ProcessId,Name,CommandLine,ParentProcessId | ConvertTo-Json -Compress',
      ], { timeout: 5000, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] })
      const data = JSON.parse(out.trim())
      const arr: any[] = Array.isArray(data) ? data : [data]
      return arr.filter((p: any) => p && p.ProcessId).map((p: any) => ({
        pid: p.ProcessId,
        name: (p.Name || '').toLowerCase().replace(/\.exe$/, ''),
        cmdline: (p.CommandLine || p.Name || ''),
        ppid: p.ParentProcessId ?? 0,
      }))
    } else {
      const out = execFileSync('ps', ['-eo', 'pid,comm,args,ppid', '--no-headers'], { timeout: 3000, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] })
      return out.trim().split('\n').filter(Boolean).map((line: string) => {
        const firstSpace = line.indexOf(' ')
        if (firstSpace === -1) return { pid: parseInt(line.trim()), name: '', cmdline: '', ppid: 0 }
        const pid = parseInt(line.substring(0, firstSpace))
        const rest = line.substring(firstSpace + 1).trim()
        const lastSpace = rest.lastIndexOf(' ')
        if (lastSpace === -1) return { pid, name: rest, cmdline: rest, ppid: 0 }
        const name = rest.substring(0, lastSpace).trim().split(/\s+/)[0] || ''
        const ppid = parseInt(rest.substring(lastSpace + 1)) || 0
        const cmdline = rest
        return { pid, name: name.toLowerCase(), cmdline, ppid }
      })
    }
  } catch { return [] }
}

function getNetConnections(): BuildNetEvent[] {
  try {
    const events: BuildNetEvent[] = []
    if (process.platform === 'win32') {
      const out = execFileSync('powershell', [
        '-NoProfile', '-Command',
        'Get-NetTCPConnection -State Established | Select-Object RemoteAddress,RemotePort | ConvertTo-Json -Compress',
      ], { timeout: 3000, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] })
      const data = JSON.parse(out.trim())
      const arr: any[] = Array.isArray(data) ? data : [data]
      for (const c of arr) {
        if (c && c.RemoteAddress && c.RemoteAddress !== '::1' && c.RemoteAddress !== '127.0.0.1') {
          events.push({ type: 'tcp', host: c.RemoteAddress, port: c.RemotePort, timestamp: Date.now() })
        }
      }
      const dnsOut = execFileSync('powershell', [
        '-NoProfile', '-Command',
        'Get-DnsClientCache | Where-Object Entry -notmatch "^::1$|^127\\.|^$" | Select-Object Entry | ConvertTo-Json -Compress',
      ], { timeout: 3000, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] })
      const dnsData = JSON.parse(dnsOut.trim())
      const dnsArr: any[] = Array.isArray(dnsData) ? dnsData : [dnsData]
      for (const d of dnsArr) {
        if (d && d.Entry && !d.Entry.endsWith('.local')) {
          events.push({ type: 'dns', host: d.Entry, timestamp: Date.now() })
        }
      }
    } else {
      const out = execFileSync('ss', ['-tunp', '--no-header'], { timeout: 3000, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] })
      for (const line of out.trim().split('\n')) {
        const parts = line.trim().split(/\s+/)
        const dest = parts[4]
        if (dest && dest !== '::1:0' && !dest.startsWith('127.')) {
          const [host, port] = dest.split(':')
          events.push({ type: 'tcp', host: host || dest, port: port ? parseInt(port) : undefined, timestamp: Date.now() })
        }
      }
    }
    return events
  } catch { return [] }
}

function isDescendantOf(pid: number, targetPpid: number, procs: Map<number, { ppid: number }>, depth = 0): boolean {
  if (depth > 20) return false
  const proc = procs.get(pid)
  if (!proc) return false
  if (proc.ppid === targetPpid) return true
  if (proc.ppid === 0 || proc.ppid === pid) return false
  return isDescendantOf(proc.ppid, targetPpid, procs, depth + 1)
}

function buildToolName(name: string): string {
  for (const tool of BUILD_TOOLS) {
    if (tool.endsWith('*')) {
      if (name.startsWith(tool.slice(0, -1))) return tool.slice(0, -1)
    }
    if (name === tool) return tool
  }
  return ''
}

function fileSha256(fp: string): string | null {
  try {
    return crypto.createHash('sha256').update(fs.readFileSync(fp)).digest('hex')
  } catch { return null }
}

const SYSTEM_PROCESSES = new Set([
  'system', 'secure system', 'registry', 'smss.exe', 'csrss.exe',
  'wininit.exe', 'winlogon.exe', 'services.exe', 'lsaiso.exe', 'lsass.exe',
  'svchost.exe', 'fontdrvhost.exe', 'dwm.exe', 'spoolsv.exe',
  'memory compression', 'msmpeng.exe', 'taskhostw.exe', 'explorer.exe',
  'runtimebroker.exe', 'ctfmon.exe', 'lockapp.exe', 'textinputhost.exe',
  'dllhost.exe', 'sihost.exe', 'searchhost.exe', 'systemsettings.exe',
  'securityhealthsystray.exe', 'securityhealthservice.exe',
  'startmenuexperiencehost.exe', 'shellexperiencehost.exe',
  'widgets.exe', 'widgetservice.exe',
])

const KNOWN_BUILD_PROCESSES = new Set([
  'node', 'node.exe', 'cmd.exe', 'cmd', 'powershell', 'powershell.exe',
  'conhost', 'conhost.exe', 'sh', 'bash', 'zsh', 'make', 'nmake',
  'gcc', 'g++', 'clang', 'clang++', 'rustc', 'cargo', 'go',
  'python', 'python3', 'java', 'javac', 'mvn', 'gradle',
  'npm', 'npx', 'yarn', 'pnpm', 'tsc', 'esbuild', 'webpack',
  'rollup', 'vite', 'babel',
])

const ARTIFACT_EXTENSIONS = new Set([
  '.o', '.obj', '.a', '.lib', '.so', '.dll', '.dylib', '.exe', '.out',
  '.bin', '.elf', '.wasm', '.jar', '.war', '.apk', '.aab',
  '.rlib', '.rmeta', '.pyc', '.pyo',
])

function isArtifact(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase()
  return ARTIFACT_EXTENSIONS.has(ext)
}

function safePoll<T>(fn: () => T, fallback: T): T {
  try { return fn() } catch { return fallback }
}

export function recordBuild(command: string, args: string[], cwd: string, options?: RecordOptions): Promise<BuildRecord> {
  return new Promise((resolve, reject) => {
    const startTime = Date.now()
    const startTimeIso = new Date().toISOString()
    const timeoutMs = options?.timeoutMs ?? 300_000
    const observeOnly = options?.observeOnly ?? false
    const failOnError = options?.failOnError ?? false
    const pollProcessMs = options?.pollProcessMs ?? 200
    const pollFileMs = options?.pollFileMs ?? 1000
    const pollNetMs = options?.pollNetMs ?? 2000
    const pollReadMs = options?.pollReadMs ?? 1500
    const evidenceSource = inferEvidenceSource(process.platform, options)

    const buildProcesses: BuildProcessEvent[] = []
    const files: BuildFileEvent[] = []
    const network: BuildNetEvent[] = []
    const seenDns = new Set<string>()
    const seenTcp = new Set<string>()
    const buildPidSet = new Set<number>()
    const hashChain: BuildChainLink[] = []
    const artifactHashes: ArtifactHash[] = []
    const readFiles: FileReadEvent[] = []
    let inputIdentity: BuildInputIdentity | undefined
    let pathPreState: PathState = capturePathState(cwd)
    const scriptIdentities: ScriptIdentity[] = []
    let prevRecord: BuildRecord | undefined
    let preInventory = capturePreBuildInventory(cwd)
    let processInterval: NodeJS.Timeout | null = null
    let fileInterval: NodeJS.Timeout | null = null
    let netInterval: NodeJS.Timeout | null = null
    let readInterval: NodeJS.Timeout | null = null
    let child: ChildProcess | null = null

    const envSnapshot: Record<string, string> = {}
    for (const key of BUILD_ENV_KEYS) {
      const val = process.env[key]
      if (val !== undefined) envSnapshot[key] = val
    }

    function addHashLink(eventType: string, fingerprint: string) {
      const previousHash = hashChain.length > 0 ? hashChain[hashChain.length - 1].linkHash : crypto.createHash('sha256').update('genesis').digest('hex')
      const linkData = `${eventType}|${fingerprint}|${previousHash}`
      const linkHash = crypto.createHash('sha256').update(linkData).digest('hex')
      hashChain.push({ index: hashChain.length, timestamp: Date.now(), eventType, eventFingerprint: fingerprint, previousHash, linkHash })
    }

    let baselinePids = new Set<number>()
    let previousPollPids = new Set<number>()
    const processMap = new Map<number, BuildProcessEvent>()

    function pollProcesses() {
      safePoll(() => {
        const list = getProcessList()
        const currentPids = new Set(list.map(p => p.pid))
        const procMap = new Map(list.map(p => [p.pid, p]))

        const exits = trackProcessExits(currentPids, previousPollPids, processMap)
        for (const p of exits) {
          addHashLink('process_exit', `${p.pid}:${p.name}:${(p.exitTime || 0) - (p.startTime || p.timestamp)}ms`)
        }

        for (const entry of list) {
          if (baselinePids.has(entry.pid)) continue
          if (buildPidSet.has(entry.pid)) continue
          buildPidSet.add(entry.pid)
          const processEvent: BuildProcessEvent = {
            pid: entry.pid, name: entry.name, cmdline: entry.cmdline || entry.name,
            ppid: entry.ppid, pname: procMap.get(entry.ppid)?.name || '',
            timestamp: Date.now(),
            startTime: Date.now(),
            source: evidenceSource,
            confidence: evidenceSource === 'etw' ? 98 : evidenceSource === 'ebpf' ? 97 : evidenceSource === 'cim_query' ? 82 : 72,
          }
          buildProcesses.push(processEvent)
          processMap.set(entry.pid, processEvent)
          addHashLink('process_start', `${entry.pid}:${entry.name}`)

          const cmdline = entry.cmdline || ''
          if (/python|node|bash|sh|zsh|ruby|perl|pwsh|powershell/.test(entry.name) && cmdline.includes('.')) {
            const si = captureScriptIdentity(entry.pid, cmdline)
            if (si) scriptIdentities.push(si)
          }
        }

        previousPollPids = currentPids
      }, undefined)
    }

    interface FileEntry {
      size: number
      mtimeMs: number
    }

    function buildFileMap(root: string): Map<string, FileEntry> {
      const map = new Map<string, FileEntry>()
      const walk = (dir: string, depth = 0) => {
        if (depth > 4) return
        try {
          for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const fp = path.join(dir, entry.name)
            try {
              if (entry.isDirectory()) {
                if (!entry.name.startsWith('.') && entry.name !== 'node_modules' && entry.name !== '.git') {
                  walk(fp, depth + 1)
                }
              } else {
                const stat = fs.statSync(fp)
                map.set(fp, { size: stat.size, mtimeMs: stat.mtimeMs })
              }
            } catch { }
          }
        } catch { }
      }
      try { walk(root) } catch { }
      return map
    }

    let fileBaseline = new Map<string, FileEntry>()

    function pollFiles() {
      if (fileBaseline.size === 0) {
        fileBaseline = buildFileMap(cwd)
        return
      }
      const current = buildFileMap(cwd)
      for (const [fp, cur] of current) {
        const base = fileBaseline.get(fp)
        if (!base) {
          fileBaseline.set(fp, cur)
          files.push({ filePath: fp, size: cur.size, operation: 'created', timestamp: Date.now() })
          addHashLink('file_create', `${path.basename(fp)}:${cur.size}`)
        } else if (base.size !== cur.size || Math.abs(base.mtimeMs - cur.mtimeMs) > 100) {
          fileBaseline.set(fp, cur)
          files.push({ filePath: fp, size: cur.size, operation: 'modified', timestamp: Date.now() })
          addHashLink('file_modify', `${path.basename(fp)}:${cur.size}`)
        }
      }
      for (const [fp, base] of fileBaseline) {
        if (!current.has(fp)) {
          fileBaseline.delete(fp)
          files.push({ filePath: fp, size: base.size, operation: 'deleted', timestamp: Date.now() })
          addHashLink('file_delete', path.basename(fp))
        }
      }
    }

    function pollNetwork() {
      const conns = getNetConnections()
      for (const c of conns) {
        if (c.type === 'tcp') {
          const key = `${c.host}:${c.port}`
          if (seenTcp.has(key)) continue
          seenTcp.add(key)
          network.push(c)
          addHashLink('tcp_conn', key)
        } else {
          if (seenDns.has(c.host)) continue
          seenDns.add(c.host)
          network.push(c)
          addHashLink('dns_query', c.host)
        }
      }
    }

    function filteredPidsForReads(): number[] {
      const cp = child?.pid || 0
      const pm = new Map<number, { pid: number; ppid: number }>()
      for (const p of buildProcesses) pm.set(p.pid, { pid: p.pid, ppid: p.ppid })
      return buildProcesses
        .filter(p => p.pid === cp || (pm.has(p.ppid) && isDescendantOf(p.pid, cp, pm)))
        .map(p => p.pid)
    }

    function pollReads() {
      const pidSet = new Set(filteredPidsForReads())
      const processNames = new Map(buildProcesses.map(p => [p.pid, p.name]))
      const events = pollProcessOpenFiles(pidSet, cwd, processNames)
      for (const e of events) readFiles.push(e)
    }

    baselinePids = new Set(getProcessList().map(p => p.pid))
    fileBaseline = new Map()
    pollFiles()

    inputIdentity = buildInputIdentity(cwd)

    processInterval = setInterval(pollProcesses, pollProcessMs)
    fileInterval = setInterval(pollFiles, pollFileMs)
    netInterval = setInterval(pollNetwork, pollNetMs)
    readInterval = setInterval(pollReads, pollReadMs)

    if (observeOnly) {
      const durationMs = Date.now() - startTime
      pollFiles()
      pollNetwork()
      const emptyRecord: BuildRecord = {
        command, args, cwd: path.resolve(cwd),
        startTime: startTimeIso, durationMs, exitCode: null,
        platform: os.platform(), nodeVersion: process.version,
        env: envSnapshot,
        processes: buildProcesses,
        files, network, artifactHashes: [],
        summary: {
          totalProcesses: buildProcesses.length,
          uniqueProcesses: [...new Set(buildProcesses.map(p => p.name))],
          buildToolsDetected: [],
          filesCreated: files.filter(f => f.operation === 'created').length,
          filesModified: files.filter(f => f.operation === 'modified').length,
          filesDeleted: files.filter(f => f.operation === 'deleted').length,
          filesRead: readFiles.length,
          networkConnections: network.length,
          dnsQueries: [...new Set(network.filter(n => n.type === 'dns').map(n => n.host))],
          artifactsHashed: 0,
          anomalies: [],
          processTree: [],
          totalHashLinks: hashChain.length,
        },
        hashChain,
        recordOptions: options,
      }
      if (processInterval) clearInterval(processInterval)
      if (fileInterval) clearInterval(fileInterval)
      if (netInterval) clearInterval(netInterval)
      if (readInterval) clearInterval(readInterval)
      resolve(emptyRecord)
      return
    }

    const useShell = process.platform === 'win32'
    child = spawn(useShell ? `${command} ${args.join(' ')}` : command, useShell ? [] : args, {
      cwd,
      stdio: ['pipe', 'pipe', 'pipe'],
      shell: useShell,
      env: { ...process.env, NODE_OPTIONS: '--no-deprecation' },
    })

    const timer = setTimeout(() => {
      child?.kill('SIGTERM')
    }, timeoutMs)

    child.on('close', (exitCode) => {
      clearTimeout(timer)
      if (processInterval) clearInterval(processInterval)
      if (fileInterval) clearInterval(fileInterval)
      if (netInterval) clearInterval(netInterval)
      if (readInterval) clearInterval(readInterval)

      pollFiles()
      pollNetwork()

      const durationMs = Date.now() - startTime

      const procMap = new Map<number, { pid: number; ppid: number; name: string; cmdline: string }>()
      for (const p of buildProcesses) {
        procMap.set(p.pid, { pid: p.pid, ppid: p.ppid, name: p.name, cmdline: p.cmdline })
      }

      const childPid = child?.pid || 0
      const childPids = new Set<number>()
      for (const [pid, proc] of procMap) {
        if (pid === childPid || isDescendantOf(pid, childPid, procMap)) {
          childPids.add(pid)
        }
      }

      const filteredProcesses = buildProcesses.filter(p => childPids.has(p.pid))
      const uniqueNames = [...new Set(filteredProcesses.map(p => p.name))]
      const buildToolsDetected = uniqueNames.filter(n => buildToolName(n))

      for (const f of files) {
        if (f.operation === 'deleted') continue
        try {
          const sha = fileSha256(f.filePath)
          if (sha) {
            f.sha256 = sha
            if (isArtifact(f.filePath)) {
              artifactHashes.push({ filePath: f.filePath, sha256: sha, size: f.size })
            }
          }
        } catch { }
      }

      const anomalies: string[] = []

      const dangerousSeen = filteredProcesses.filter(p =>
        [...DANGEROUS_BUILD_TOOLS].some(t => p.name.includes(t) || p.cmdline.includes(t))
      )
      if (dangerousSeen.length > 0) {
        anomalies.push(`Suspicious process${dangerousSeen.length > 1 ? 'es' : ''}: ${[...new Set(dangerousSeen.map(p => p.name))].join(', ')}`)
      }

      const unknown = uniqueNames.filter(n =>
        !buildToolName(n) &&
        !DANGEROUS_BUILD_TOOLS.has(n) &&
        !SYSTEM_PROCESSES.has(n) &&
        !KNOWN_BUILD_PROCESSES.has(n)
      )
      if (unknown.length > 0) {
        anomalies.push(`Unrecognized build process${unknown.length > 1 ? 'es' : ''}: ${unknown.join(', ')}`)
      }

      const suspiciousNet = network.filter(n =>
        n.type === 'dns' && (
          n.host.includes('pastebin') || n.host.includes('transfer.sh') ||
          n.host.includes('ngrok') || n.host.includes('webhook') ||
          (n.host.match(/\.(ru|cn|tk|ml|ga)$/) && !n.host.endsWith('.com'))
        )
      )
      if (suspiciousNet.length > 0) {
        anomalies.push(`Suspicious network destinations: ${[...new Set(suspiciousNet.map(n => n.host))].join(', ')}`)
      }

      function buildTree(pid: number, depth = 0): ProcessNode {
        if (depth > 10) return { name: '...', pid, ppid: 0, cmdline: '', children: [] }
        const p = procMap.get(pid)
        if (!p) return { name: '?', pid, ppid: 0, cmdline: '', children: [] }
        return {
          name: p.name, pid: p.pid, ppid: p.ppid, cmdline: p.cmdline,
          children: filteredProcesses
            .filter(c => c.ppid === pid && c.pid !== pid)
            .map(c => buildTree(c.pid, depth + 1)),
        }
      }

      const processTree: ProcessNode[] = []
      if (childPid && procMap.has(childPid)) {
        processTree.push(buildTree(childPid))
      }

      const postBuildReads = detectReadFilesPostBuild(preInventory, files, filteredProcesses, cwd)
      const allReadFiles = deduplicateReadEvents([...readFiles, ...postBuildReads])

      const identity = captureBuildIdentity()

      const summary: BuildSummary = {
        totalProcesses: filteredProcesses.length,
        uniqueProcesses: uniqueNames,
        buildToolsDetected,
        filesCreated: files.filter(f => f.operation === 'created').length,
        filesModified: files.filter(f => f.operation === 'modified').length,
        filesDeleted: files.filter(f => f.operation === 'deleted').length,
        filesRead: allReadFiles.length,
        networkConnections: network.length,
        dnsQueries: [...new Set(network.filter(n => n.type === 'dns').map(n => n.host))],
        artifactsHashed: artifactHashes.length,
        anomalies,
        processTree,
        totalHashLinks: hashChain.length,
      }

      const pathResolutions = [pathPreState, capturePathState(cwd)]
      const stubRecord: BuildRecord = {
        command, args, cwd: path.resolve(cwd),
        startTime: startTimeIso, durationMs, exitCode,
        platform: os.platform(), nodeVersion: process.version,
        env: envSnapshot,
        processes: filteredProcesses,
        files, network, artifactHashes, summary, hashChain,
        identity,
        readFiles: allReadFiles,
        inputIdentity,
        pathResolutions,
      }
      const trustResult = computeTrust(stubRecord)
      const intentFlow = buildIntentFlow(stubRecord)
      const existingContract = loadContract(command, cwd)
      const { contract, violations } = updateContract(stubRecord, existingContract)
      saveContract(command, cwd, contract)

      if (intentFlow.deviations.length > 0) {
        anomalies.push(...intentFlow.deviations.map(d => `Intent deviation: ${d}`))
      }
      for (const v of violations) {
        anomalies.push(`[${v.severity.toUpperCase()}] Contract: ${v.reason}`)
      }

      const ephemeral = findEphemeralProcesses(filteredProcesses, 100)
      if (ephemeral.length > 0) {
        anomalies.push(`${ephemeral.length} ephemeral process${ephemeral.length > 1 ? 'es' : ''} (<100ms): ${[...new Set(ephemeral.map(e => e.name))].join(', ')}`)
      }

      const ephemeralClusters = classifyEphemeralProcesses(filteredProcesses)
      const sub25msCluster = ephemeralClusters.find(c => c.thresholdMs === 25)
      if (sub25msCluster && sub25msCluster.count > 0) {
        anomalies.push(`[HIGH] ${sub25msCluster.count} process(es) with lifetime <25ms (possible ptrace injection evasion): ${[...new Set(sub25msCluster.processes.map(e => e.name))].join(', ')}`)
      }

      const secretAccesses = [
        ...scanProcessReadsForSecrets(allReadFiles),
        ...scanEnvForSecrets(envSnapshot),
      ]
      const secretChains = buildSecretFlowChains(secretAccesses, filteredProcesses, network)
      const secretFlow: SecretFlow = {
        secretAccesses,
        chains: secretChains,
        totalSecrets: secretAccesses.length,
        criticalCount: secretAccesses.filter(s => s.severity === 'critical').length,
        exfilRiskCount: secretChains.filter(c => c.hasExfilRisk).length,
      }
      if (secretFlow.exfilRiskCount > 0) {
        anomalies.push(`${secretFlow.exfilRiskCount} secret exfiltration risk(s) detected`)
      }
      if (secretFlow.criticalCount > 0) {
        anomalies.push(`${secretFlow.criticalCount} critical secret(s) found in build workspace`)
      }

      const compilerIdentity = analyzeCompilerInvocations(filteredProcesses, cwd)
      for (const s of compilerIdentity.suspiciousInvocations) {
        anomalies.push(`Suspicious compiler invocation: ${s}`)
      }
      if ((compilerIdentity.stdinInvocations || 0) > 0) {
        anomalies.push(`[MEDIUM] ${compilerIdentity.stdinInvocations} compiler invocation(s) from stdin (no file provenance)`)
      }
      if ((compilerIdentity.memfdInvocations || 0) > 0) {
        anomalies.push(`[HIGH] ${compilerIdentity.memfdInvocations} compiler invocation(s) with no input files (possible memfd_create evasion)`)
      }

      const responseFileChanges = detectResponseFileChanges(compilerIdentity.invocations)
      const changedRsp = responseFileChanges.filter(r => r.changed)
      if (changedRsp.length > 0) {
        anomalies.push(`[HIGH] ${changedRsp.length} response file(s) changed between read and post-build: ${changedRsp.map(r => `${r.tool}@${r.responseFile}`).join(', ')}`)
      }

      const fileless = detectFilelessExecution(filteredProcesses)
      if (fileless.length > 0) {
        anomalies.push(`[HIGH] ${fileless.length} fileless execution(s) detected: ${[...new Set(fileless.map(p => `${p.name} (${p.cmdline.substring(0, 60)})`))].join(', ')}`)
      }

      const orphans = detectOrphanProcesses(filteredProcesses)
      if (orphans.length > 0) {
        anomalies.push(`[CRITICAL] ${orphans.length} orphan process(es) (possible ptrace injection): ${[...new Set(orphans.map(o => o.name))].join(', ')}`)
      }

      const dohEvents = detectDnsOverHttps(network)
      if (dohEvents.length > 0) {
        anomalies.push(`[MEDIUM] ${dohEvents.length} DNS-over-HTTPS connection(s) detected (DNS audit bypass): ${[...new Set(dohEvents.map(d => d.host))].join(', ')}`)
      }

      const namedPipes = detectNamedPipes(filteredProcesses, cwd)
      if (namedPipes.length > 0) {
        anomalies.push(`[MEDIUM] ${namedPipes.length} named pipe(s) detected (inter-process communication not tracked)`)
      }

      const processMaps = captureProcessMaps(filteredProcesses)
      const ldPreloadProcesses = processMaps.filter(m => m.ldPreload)
      if (ldPreloadProcesses.length > 0) {
        anomalies.push(`[HIGH] LD_PRELOAD detected in ${ldPreloadProcesses.length} process(es): ${[...new Set(ldPreloadProcesses.map(m => `${m.processName} [${m.ldPreload}]`))].join(', ')}`)
      }
      const suspiciousMaps = processMaps.filter(m => m.suspiciousRegions.length > 0)
      if (suspiciousMaps.length > 0) {
        anomalies.push(`[CRITICAL] ${suspiciousMaps.length} process(es) with suspicious memory regions (rwx/memfd): ${[...new Set(suspiciousMaps.map(m => m.processName))].join(', ')}`)
      }

      const prevInputFingerprint = prevRecord?.inputIdentity?.inputFingerprint || null
      const prevArtifacts = prevRecord?.artifactHashes || null
      const hermetricScore = computeHermeticScore(
        filteredProcesses.length,
        network.length,
        compilerIdentity.suspiciousInvocations.length,
        uniqueNames.length,
        pathResolutions.length >= 2 ? 1 : 0,
        violations.length,
        ephemeral.length,
        secretAccesses.length,
      )
      if (hermetricScore < 50) {
        anomalies.push(`Low hermetic build score: ${hermetricScore}/100`)
      }

      const reproducibility = computeReproducibilityScore(
        inputIdentity?.inputFingerprint || '',
        prevInputFingerprint,
        artifactHashes,
        prevArtifacts,
      )

      const observationConfidence = computeObservationConfidence(
        filteredProcesses, files, network, allReadFiles,
      )

      // Build full record first, then derive graph/timelines
      const record: BuildRecord = {
        ...stubRecord,
        scriptIdentities: scriptIdentities.length > 0 ? scriptIdentities : undefined,
        trustResult,
        buildIntent: intentFlow.observed.map((intent) => {
          const matching = filteredProcesses.find(p => classifyIntent(p.name, p.cmdline) === intent)
          return {
            tool: matching?.name || intent,
            intent,
            timestamp: matching?.timestamp || Date.now(),
            durationMs: matching?.exitTime ? matching.exitTime - (matching.startTime || matching.timestamp) : 0,
          }
        }),
        buildContractViolations: violations,
        secretFlow,
        compilerInvocations: compilerIdentity,
        hermetricScore,
        reproducibilityScore: reproducibility.score,
        observationConfidence,
        orphanProcesses: orphans.length > 0 ? orphans : undefined,
        namedPipes: namedPipes.length > 0 ? namedPipes : undefined,
        processMaps: processMaps.length > 0 ? processMaps : undefined,
        responseFileChanges: changedRsp.length > 0 ? responseFileChanges : undefined,
        recordOptions: options,
      }

      const evidenceGraph = buildEvidenceGraph(record)
      const propagatedGraph = propagateGraphConfidence(evidenceGraph)
      const processTimelines = buildProcessTimelines(record, propagatedGraph)
      const confidencePaths = findConfidencePaths(
        propagatedGraph,
        propagatedGraph.nodes[0]?.id || '',
        propagatedGraph.nodes[propagatedGraph.nodes.length - 1]?.id || '',
      )

      record.evidenceGraph = propagatedGraph
      record.processTimelines = processTimelines
      record.confidencePaths = confidencePaths

      // Corpus harvesting: record feature vector for trust calibration
      try {
        const vector = extractFeatureVector(record, propagatedGraph)
        const label = autoLabel(record)
        if (label) {
          vector.label = label
          vector.labelSource = 'auto'
        }
        getDefaultStore().record(vector)
      } catch {
        // corpus harvesting is best-effort
      }

      resolve(record)
    })

    child.on('error', (err) => {
      clearTimeout(timer)
      if (processInterval) clearInterval(processInterval)
      if (fileInterval) clearInterval(fileInterval)
      if (netInterval) clearInterval(netInterval)
      reject(err)
    })
  })
}
