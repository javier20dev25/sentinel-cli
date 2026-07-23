import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import { execFileSync } from 'child_process'

export type EventProviderType = 'etw' | 'ebpf' | 'endpoint_security' | 'polling'

export interface NativeProcessEvent {
  pid: number
  ppid: number
  name: string
  cmdline: string
  startTime: number
  exitTime?: number
}

export interface NativeFileEvent {
  pid: number
  processName: string
  filePath: string
  operation: 'read' | 'write' | 'create' | 'delete'
  timestamp: number
  size?: number
}

export interface NativeNetEvent {
  pid: number
  processName: string
  host: string
  port: number
  protocol: 'tcp' | 'dns'
  timestamp: number
}

export interface NativeEventProvider {
  readonly type: EventProviderType
  readonly supported: boolean

  start(): void
  stop(): void

  pollProcessEvents(): NativeProcessEvent[]
  pollFileEvents(): NativeFileEvent[]
  pollNetEvents(): NativeNetEvent[]

  getProcessName(pid: number): string | null
}

class PollingEventProvider implements NativeEventProvider {
  readonly type: EventProviderType = 'polling'
  readonly supported = true
  private warned = false

  start(): void {}
  stop(): void {}

  pollProcessEvents(): NativeProcessEvent[] {
    try {
      if (process.platform === 'win32') {
        return this.pollWin32Processes()
      }
      return this.pollLinuxProcesses()
    } catch { return [] }
  }

  private pollWin32Processes(): NativeProcessEvent[] {
    try {
      const out = execFileSync('powershell', [
        '-NoProfile', '-Command',
        'Get-CimInstance Win32_Process | Select-Object ProcessId,Name,CommandLine,ParentProcessId,CreationDate | ConvertTo-Json -Compress',
      ], { timeout: 5000, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] })
      const data = JSON.parse(out.trim())
      const arr: any[] = Array.isArray(data) ? data : [data]
      return arr.filter((p: any) => p && p.ProcessId).map((p: any) => ({
        pid: p.ProcessId,
        ppid: p.ParentProcessId ?? 0,
        name: (p.Name || '').toLowerCase().replace(/\.exe$/, ''),
        cmdline: (p.CommandLine || p.Name || ''),
        startTime: p.CreationDate ? new Date(p.CreationDate).getTime() : Date.now(),
      }))
    } catch { return [] }
  }

  private pollLinuxProcesses(): NativeProcessEvent[] {
    try {
      const out = execFileSync('ps', ['-eo', 'pid,ppid,comm,args,lstart', '--no-headers'], { timeout: 3000, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] })
      return out.trim().split('\n').filter(Boolean).map((line: string) => {
        const parts = line.trim().split(/\s+/)
        const pid = parseInt(parts[0])
        const ppid = parseInt(parts[1])
        const name = parts[2]?.toLowerCase() || ''
        const cmdline = parts.slice(3).join(' ')
        return { pid, ppid, name, cmdline, startTime: Date.now() }
      })
    } catch { return [] }
  }

  pollFileEvents(): NativeFileEvent[] {
    return []
  }

  pollNetEvents(): NativeNetEvent[] {
    try {
      const events: NativeNetEvent[] = []
      if (process.platform === 'win32') {
        const out = execFileSync('powershell', [
          '-NoProfile', '-Command',
          'Get-NetTCPConnection -State Established | Select-Object RemoteAddress,RemotePort,OwningProcess | ConvertTo-Json -Compress',
        ], { timeout: 3000, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] })
        const data = JSON.parse(out.trim())
        const arr: any[] = Array.isArray(data) ? data : [data]
        for (const c of arr) {
          if (c && c.RemoteAddress && c.RemoteAddress !== '::1' && c.RemoteAddress !== '127.0.0.1') {
            events.push({
              pid: c.OwningProcess || 0,
              processName: '',
              host: c.RemoteAddress,
              port: c.RemotePort,
              protocol: 'tcp',
              timestamp: Date.now(),
            })
          }
        }
      }
      return events
    } catch { return [] }
  }

  getProcessName(pid: number): string | null {
    try {
      if (process.platform === 'win32') {
        const out = execFileSync('powershell', [
          '-NoProfile', '-Command',
          `(Get-CimInstance Win32_Process -Filter "ProcessId = ${pid}").Name`,
        ], { timeout: 2000, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] })
        return out.trim().toLowerCase().replace(/\.exe$/, '') || null
      } else {
        const out = execFileSync('ps', ['-p', String(pid), '-o', 'comm=', '--no-headers'], { timeout: 2000, encoding: 'utf8' })
        return out.trim() || null
      }
    } catch { return null }
  }
}

class EtwEventProvider implements NativeEventProvider {
  readonly type: EventProviderType = 'etw'
  readonly supported: boolean

  private etwSession: string | null = null

  constructor() {
    this.supported = process.platform === 'win32' && this.checkEtwAvailable()
  }

  private checkEtwAvailable(): boolean {
    try {
      execFileSync('wevtutil', ['ep'], { stdio: 'pipe', timeout: 3000, encoding: 'utf8' })
      return true
    } catch { return false }
  }

  start(): void {
    if (!this.supported) return
    try {
      execFileSync('powershell', [
        '-NoProfile', '-Command',
        `
        $sessionName = "SentinelETW"
        try {
          Stop-NetEventSession -Name $sessionName -ErrorAction SilentlyContinue
          Remove-NetEventSession -Name $sessionName -ErrorAction SilentlyContinue
        } catch {}
        New-NetEventSession -Name $sessionName -CaptureMode Realtime -LocalFilePath "$env:TEMP\\sentinel-etw.etl"
        Add-NetEventProvider -Name "Microsoft-Windows-Kernel-Process" -SessionName $sessionName
        Add-NetEventProvider -Name "Microsoft-Windows-TCP/IP" -SessionName $sessionName
        Start-NetEventSession -Name $sessionName
        Write-Output $sessionName
        `,
      ], { timeout: 10000, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] })
      this.etwSession = 'SentinelETW'
    } catch {}
  }

  stop(): void {
    if (!this.etwSession) return
    try {
      execFileSync('powershell', [
        '-NoProfile', '-Command',
        `Stop-NetEventSession -Name ${this.etwSession} -ErrorAction SilentlyContinue; Remove-NetEventSession -Name ${this.etwSession} -ErrorAction SilentlyContinue`,
      ], { timeout: 5000, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] })
    } catch {}
    this.etwSession = null
  }

  pollProcessEvents(): NativeProcessEvent[] {
    if (!this.supported) return []
    try {
      const out = execFileSync('powershell', [
        '-NoProfile', '-Command',
        `
        $events = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Kernel-Process/Operational' } -MaxEvents 100 -ErrorAction SilentlyContinue
        $events | ForEach-Object {
          [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            Id = $_.Id
            Properties = $_.Properties | ForEach-Object { $_.Value }
          }
        } | ConvertTo-Json -Compress
        `,
      ], { timeout: 5000, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] })
      if (!out.trim()) return []
      const events = JSON.parse(out.trim())
      const arr: any[] = Array.isArray(events) ? events : [events]
      return arr.filter((e: any) => e.Id === 1 || e.Id === 2).map((e: any) => ({
        pid: e.Properties?.[0] || 0,
        ppid: e.Properties?.[1] || 0,
        name: String(e.Properties?.[2] || '').toLowerCase(),
        cmdline: String(e.Properties?.[3] || ''),
        startTime: e.TimeCreated ? new Date(e.TimeCreated).getTime() : Date.now(),
      }))
    } catch { return [] }
  }

  pollFileEvents(): NativeFileEvent[] {
    return []
  }

  pollNetEvents(): NativeNetEvent[] {
    if (!this.supported) return []
    try {
      const out = execFileSync('powershell', [
        '-NoProfile', '-Command',
        `
        $events = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-TCP/IP/Operational' } -MaxEvents 50 -ErrorAction SilentlyContinue
        $events | ForEach-Object {
          [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            Id = $_.Id
            Properties = $_.Properties | ForEach-Object { $_.Value }
          }
        } | ConvertTo-Json -Compress
        `,
      ], { timeout: 5000, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] })
      if (!out.trim()) return []
      const events = JSON.parse(out.trim())
      const arr: any[] = Array.isArray(events) ? events : [events]
      return arr.map((e: any) => ({
        pid: 0,
        processName: '',
        host: String(e.Properties?.[0] || ''),
        port: parseInt(e.Properties?.[1] || '0'),
        protocol: 'tcp' as const,
        timestamp: e.TimeCreated ? new Date(e.TimeCreated).getTime() : Date.now(),
      }))
    } catch { return [] }
  }

  getProcessName(pid: number): string | null {
    const provider = new PollingEventProvider()
    return provider.getProcessName(pid)
  }
}

class EBpfEventProvider implements NativeEventProvider {
  readonly type: EventProviderType = 'ebpf'
  readonly supported: boolean

  constructor() {
    this.supported = process.platform === 'linux'
  }

  start(): void {}
  stop(): void {}

  pollProcessEvents(): NativeProcessEvent[] {
    if (!this.supported) return []
    try {
      const out = execFileSync('ps', ['-eo', 'pid,ppid,comm,args,lstart', '--no-headers'], { timeout: 3000, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] })
      return out.trim().split('\n').filter(Boolean).map((line: string) => {
        const parts = line.trim().split(/\s+/)
        const pid = parseInt(parts[0])
        const ppid = parseInt(parts[1])
        const name = parts[2]?.toLowerCase() || ''
        const cmdline = parts.slice(3).join(' ')
        return { pid, ppid, name, cmdline, startTime: Date.now() }
      })
    } catch { return [] }
  }

  pollFileEvents(): NativeFileEvent[] {
    return []
  }

  pollNetEvents(): NativeNetEvent[] {
    return []
  }

  getProcessName(pid: number): string | null {
    try {
      const out = execFileSync('ps', ['-p', String(pid), '-o', 'comm=', '--no-headers'], { timeout: 2000, encoding: 'utf8' })
      return out.trim() || null
    } catch { return null }
  }
}

export function createEventProvider(): NativeEventProvider {
  if (process.platform === 'win32') {
    const etw = new EtwEventProvider()
    if (etw.supported) return etw
  }
  if (process.platform === 'linux') {
    const ebpf = new EBpfEventProvider()
    if (ebpf.supported) return ebpf
  }
  return new PollingEventProvider()
}

export function providerName(type: EventProviderType): string {
  switch (type) {
    case 'etw': return 'ETW (Event Tracing for Windows)'
    case 'ebpf': return 'eBPF (Linux Kernel Tracing)'
    case 'endpoint_security': return 'macOS Endpoint Security Framework'
    case 'polling': return 'Polling (Process Enumeration)'
  }
}

export { PollingEventProvider, EtwEventProvider, EBpfEventProvider }
