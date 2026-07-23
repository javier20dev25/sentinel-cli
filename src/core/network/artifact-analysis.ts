import * as crypto from 'crypto'
import * as fs from 'fs'
import * as path from 'path'
import { spawnSync } from 'child_process'
import { ArtifactAnalysis, SectionInfo, ArtifactDiff, ArtifactHash } from './build-types'

let _toolsChecked = false
let _hasElfTools = false
let _hasPeTools = false
let _hasMachoTools = false
let _hasStrings = false

function checkTools(): void {
  if (_toolsChecked) return
  _toolsChecked = true
  _hasElfTools = checkCommand('readelf') || checkCommand('objdump')
  _hasPeTools = checkCommand('dumpbin') || checkCommand('llvm-objdump')
  _hasMachoTools = checkCommand('otool')
  _hasStrings = checkCommand('strings')
}

function checkCommand(cmd: string): boolean {
  const r = spawnSync(process.platform === 'win32' ? 'where' : 'which', [cmd], { stdio: 'pipe', timeout: 3000 })
  return r.status === 0 && r.stdout.toString().trim().length > 0
}

function sha256File(filePath: string): string {
  try {
    const buf = fs.readFileSync(filePath)
    return crypto.createHash('sha256').update(buf).digest('hex')
  } catch { return '' }
}

export function computeEntropy(data: Buffer): number {
  if (data.length === 0) return 0
  let freq: number[] = new Array(256).fill(0)
  for (let i = 0; i < data.length; i++) freq[data[i]]++
  let entropy = 0
  for (let i = 0; i < 256; i++) {
    if (freq[i] > 0) {
      const p = freq[i] / data.length
      entropy -= p * Math.log2(p)
    }
  }
  return Math.round(entropy * 100) / 100
}

function parseElf(path: string): { sections: SectionInfo[], architecture: string, imports: string[], symbols: string[] } {
  const sections: SectionInfo[] = []
  const symbols: string[] = []
  const imports: string[] = []
  let architecture = 'unknown'

  const r1 = spawnSync('readelf', ['-h', path], { stdio: 'pipe', timeout: 10000, maxBuffer: 1024 * 1024 })
  if (r1.status === 0) {
    const out = r1.stdout.toString()
    const m = out.match(/Machine:\s+(.+)/)
    if (m) architecture = m[1].trim()
  }

  const r2 = spawnSync('readelf', ['-S', path], { stdio: 'pipe', timeout: 10000, maxBuffer: 1024 * 1024 })
  if (r2.status === 0) {
    const out = r2.stdout.toString()
    for (const line of out.split('\n')) {
      const m = line.match(/\[\s*\d+\]\s+(\.[\w_]+)\s+[\w_]+\s+[0-9a-f]+\s+[0-9a-f]+\s+([0-9a-f]+)/)
      if (m) {
        const name = m[1]
        const size = parseInt(m[2], 16)
        const flags = line.includes('AX') ? 'AX' : line.includes('WA') ? 'WA' : line.includes('A') ? 'A' : ''
        sections.push({ name, size, flags, entropy: 0 })
      }
    }
  }

  const r3 = spawnSync('readelf', ['-s', path], { stdio: 'pipe', timeout: 10000, maxBuffer: 1024 * 1024 })
  if (r3.status === 0) {
    const out = r3.stdout.toString()
    for (const line of out.split('\n')) {
      const m = line.match(/\d+:\s+[0-9a-f]+\s+\d+\s+\w+\s+\w+\s+\w+\s+\d+\s+(\S+)/)
      if (m) symbols.push(m[1])
    }
  }

  const r4 = spawnSync('readelf', ['-d', path], { stdio: 'pipe', timeout: 10000, maxBuffer: 1024 * 1024 })
  if (r4.status === 0) {
    const out = r4.stdout.toString()
    for (const line of out.split('\n')) {
      const m = line.match(/NEEDED\s+\[(.+?)\]/)
      if (m) imports.push(m[1])
    }
  }

  return { sections, architecture, imports, symbols }
}

function parsePe(filePath: string): { sections: SectionInfo[], architecture: string, imports: string[], symbols: string[] } {
  const out: { sections: SectionInfo[], architecture: string, imports: string[], symbols: string[] } = { sections: [], architecture: 'unknown', imports: [], symbols: [] }

  const dumpbin = spawnSync('dumpbin', ['/HEADERS', filePath], { stdio: 'pipe', timeout: 10000, maxBuffer: 1024 * 1024 })
  if (dumpbin.status === 0) {
    const txt = dumpbin.stdout.toString()
    const archM = txt.match(/machine\s+\((\w+)\)/i) || txt.match(/Machine:\s+(\w+)/i)
    if (archM) out.architecture = archM[1]

    const inHeader = txt.indexOf('SECTION HEADER')
    if (inHeader >= 0) {
      const sectionLines = txt.substring(inHeader).split('\n')
      for (let i = 0; i < sectionLines.length; i++) {
        const m = sectionLines[i].match(/^SECTION HEADER #(\d+)/)
        if (m) {
          const nameLine = sectionLines[i + 1] || ''
          const virtLine = sectionLines[i + 3] || ''
          const rawLine = sectionLines[i + 4] || ''
          const name = nameLine.match(/([.\w]+)\s+name/)?.[1] || `.section_${m[1]}`
          const sizeM = rawLine.match(/size\s+([0-9a-f]+)/i)
          const size = sizeM ? parseInt(sizeM[1], 16) : 0
          out.sections.push({ name, size, flags: '', entropy: 0 })
        }
      }
    }
  }

  const importsR = spawnSync('dumpbin', ['/IMPORTS', filePath], { stdio: 'pipe', timeout: 10000, maxBuffer: 1024 * 1024 })
  if (importsR.status === 0) {
    for (const line of importsR.stdout.toString().split('\n')) {
      const m = line.match(/^\s+([a-zA-Z0-9_.]+)\.(dll|DLL)/)
      if (m) out.imports.push(m[0].trim())
      const m2 = line.match(/^\s+[0-9a-fA-F]+\s+(\S+)/)
      if (m2 && !line.includes('ordinal')) out.symbols.push(m2[1])
    }
  }

  return out
}

function parseMacho(filePath: string): { sections: SectionInfo[], architecture: string, imports: string[], symbols: string[] } {
  const sections: SectionInfo[] = []
  const symbols: string[] = []
  const imports: string[] = []
  let architecture = 'unknown'

  const r1 = spawnSync('otool', ['-h', filePath], { stdio: 'pipe', timeout: 10000, maxBuffer: 1024 * 1024 })
  if (r1.status === 0) {
    const m = r1.stdout.toString().match(/(arm64|x86_64|i386)/)
    if (m) architecture = m[1]
  }

  const r2 = spawnSync('otool', ['-l', filePath], { stdio: 'pipe', timeout: 10000, maxBuffer: 1024 * 1024 })
  if (r2.status === 0) {
    const lines = r2.stdout.toString().split('\n')
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(/sectname\s+(\S+)/)
      if (m) {
        const segM = lines[i - 1]?.match(/segname\s+(\S+)/)
        const sizeM = lines[i + 2]?.match(/size\s+([0-9a-fA-F]+)/)
        const name = `${segM?.[1] || ''}.${m[1]}`
        const size = sizeM ? parseInt(sizeM[1], 16) : 0
        sections.push({ name, size, flags: '', entropy: 0 })
      }
    }
  }

  const r3 = spawnSync('nm', ['-u', filePath], { stdio: 'pipe', timeout: 10000, maxBuffer: 1024 * 1024 })
  if (r3.status === 0) {
    for (const line of r3.stdout.toString().split('\n')) {
      const m = line.match(/_\s*(.+)/)
      if (m) imports.push(m[1].trim())
    }
  }

  return { sections, architecture, imports, symbols }
}

function extractSuspiciousStrings(filePath: string): string[] {
  if (!_hasStrings) return []
  const suspicious: string[] = []
  const r = spawnSync('strings', [filePath], { stdio: 'pipe', timeout: 30000, maxBuffer: 10 * 1024 * 1024 })
  if (r.status !== 0) return []

  const patterns = [
    /https?:\/\/[^\s]{3,}/gi,
    /[a-z0-9._-]+\.(ru|cn|tk|ml|ga)/gi,
    /(sh|csh|bash|powershell|cmd)\s+/gi,
    /(token|secret|key|password|api_key|apikey)/gi,
    /base64[A-Za-z0-9+/=]{10,}/gi,
    /(dlopen|dlsym|LoadLibrary|GetProcAddress)/g,
    /(socket|connect|send|recv|bind|listen|accept)\s*\(/g,
  ]

  for (const line of r.stdout.toString().split('\n')) {
    const trimmed = line.trim()
    if (trimmed.length < 4) continue
    for (const pat of patterns) {
      if (pat.test(trimmed)) {
        suspicious.push(trimmed.substring(0, 120))
        break
      }
    }
  }

  return [...new Set(suspicious)]
}

export function detectFormat(filePath: string): { format: ArtifactAnalysis['format']; architecture: string } {
  try {
    const fd = fs.openSync(filePath, 'r')
    const buf = Buffer.alloc(64)
    fs.readSync(fd, buf, 0, 64, 0)
    fs.closeSync(fd)

    if (buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) return { format: 'elf', architecture: '' }
    if (buf[0] === 0x4d && buf[1] === 0x5a) return { format: 'pe', architecture: '' }
    if (buf[0] === 0xcf && buf[1] === 0xfa && buf[2] === 0xed && buf[3] === 0xfe) return { format: 'macho', architecture: '' }
    if (buf[0] === 0x00 && buf[1] === 0x61 && buf[2] === 0x73 && buf[3] === 0x6d) return { format: 'wasm', architecture: 'wasm' }
    return { format: 'unknown', architecture: '' }
  } catch { return { format: 'unknown', architecture: '' } }
}

export function analyzeArtifact(filePath: string): ArtifactAnalysis {
  checkTools()
  const detected = detectFormat(filePath)
  const fileSize = fs.existsSync(filePath) ? fs.statSync(filePath).size : 0
  const hash = sha256File(filePath)

  const base: ArtifactAnalysis = {
    filePath,
    format: detected.format,
    architecture: detected.architecture,
    size: fileSize,
    sha256: hash,
    sections: [],
    symbolsAdded: [],
    symbolsRemoved: [],
    importsAdded: [],
    importsRemoved: [],
    suspiciousStrings: [],
    entropy: 0,
    suspiciousFindings: [],
  }

  let parsed: { sections: SectionInfo[]; architecture: string; imports: string[]; symbols: string[] } = { sections: [], architecture: 'unknown', imports: [], symbols: [] }

  try {
    if (base.format === 'elf' && _hasElfTools) {
      parsed = parseElf(filePath)
    } else if (base.format === 'pe' && _hasPeTools) {
      parsed = parsePe(filePath)
    } else if (base.format === 'macho' && _hasMachoTools) {
      parsed = parseMacho(filePath)
    }
  } catch {}

  base.architecture = parsed.architecture || base.architecture
  base.sections = parsed.sections

  const suspiciousStrings = extractSuspiciousStrings(filePath)
  base.suspiciousStrings = suspiciousStrings

  try {
    const data = fs.readFileSync(filePath)
    base.entropy = computeEntropy(data)

    for (const s of base.sections) {
      if (s.size > 0 && s.size <= data.length) {
        const secData = data.subarray(0, Math.min(s.size, data.length))
        s.entropy = computeEntropy(secData)
      }
    }

    if (base.entropy > 7.5) {
      base.suspiciousFindings.push(`High global entropy: ${base.entropy} (possible packed/encrypted)`)
    }
  } catch {}

  const execSections = base.sections.filter(s => s.flags.includes('X') || s.name === '.text')
  for (const es of execSections) {
    if (es.entropy > 7.8) {
      base.suspiciousFindings.push(`High entropy in executable section ${es.name}: ${es.entropy} > 7.8`)
    }
  }

  for (const s of suspiciousStrings) {
    if (/\.(ru|cn|tk|ml|ga)/i.test(s)) {
      base.suspiciousFindings.push(`Suspicious domain TLD in binary: ${s.substring(0, 60)}`)
      break
    }
  }

  if (parsed.imports.some(i => /dlopen|dlsym|LoadLibrary|GetProcAddress/i.test(i))) {
    base.importsAdded = parsed.imports.filter(i => /dlopen|dlsym|LoadLibrary|GetProcAddress/i.test(i))
    base.suspiciousFindings.push('Dynamic library loading functions detected in imports')
  }

  return base
}

export function diffArtifacts(prev: ArtifactAnalysis, curr: ArtifactAnalysis): ArtifactDiff {
  const prevSections = new Map(prev.sections.map(s => [s.name, s]))
  const currSections = new Map(curr.sections.map(s => [s.name, s]))

  const addedSections = curr.sections.filter(s => !prevSections.has(s.name)).map(s => s.name)
  const removedSections = prev.sections.filter(s => !currSections.has(s.name)).map(s => s.name)
  const changedSections = curr.sections
    .filter(s => prevSections.has(s.name) && prevSections.get(s.name)!.size !== s.size)
    .map(s => `${s.name} (${prevSections.get(s.name)!.size}B -> ${s.size}B)`)

  const addedSymbols = curr.symbolsAdded.filter(s => !prev.symbolsAdded.includes(s))
  const removedSymbols = prev.symbolsAdded.filter(s => !curr.symbolsAdded.includes(s))

  const addedImports = curr.importsAdded.filter(i => !prev.importsAdded.includes(i))
  const removedImports = prev.importsAdded.filter(i => !curr.importsAdded.includes(i))

  const newSuspiciousStrings = curr.suspiciousStrings.filter(s => !prev.suspiciousStrings.includes(s))

  const entropyDelta = Math.round((curr.entropy - prev.entropy) * 100) / 100

  const findings: string[] = []
  if (addedSections.length > 0) findings.push(`New section(s): ${addedSections.join(', ')}`)
  if (changedSections.length > 0) findings.push(`Section size changed: ${changedSections.join(', ')}`)
  if (addedImports.some(i => /dlopen|dlsym|LoadLibrary/i.test(i))) findings.push('Dynamic loading imports introduced')
  if (entropyDelta > 0.5) findings.push(`Entropy increased by ${entropyDelta}`)
  if (newSuspiciousStrings.length > 0) findings.push(`${newSuspiciousStrings.length} new suspicious string(s)`)

  return {
    addedSections,
    removedSections,
    changedSections,
    addedSymbols,
    removedSymbols,
    addedImports,
    removedImports,
    newSuspiciousStrings,
    entropyDelta,
    findings,
  }
}

export function analyzeArtifactsForRecord(
  artifactHashes: ArtifactHash[],
): ArtifactAnalysis[] {
  return artifactHashes
    .filter(a => {
      const ext = path.extname(a.filePath).toLowerCase()
      return ['.exe', '.dll', '.so', '.o', '.a', '.lib', '.dylib', '.wasm',
        '.out', '.bin', '.elf', '.node', '.wasm'].includes(ext) || !ext
    })
    .slice(0, 10)
    .map(a => {
      try {
        return analyzeArtifact(a.filePath)
      } catch {
        return null as unknown as ArtifactAnalysis
      }
    })
    .filter(Boolean)
}
