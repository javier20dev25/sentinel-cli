export type EvidenceSource = 'etw' | 'ebpf' | 'endpoint_security' | 'polling' | 'procfs' | 'handle' | 'mtime_heuristic' | 'ps' | 'cim_query' | 'auditd' | 'ftrace' | 'named_pipe' | 'process_maps'

export interface BuildProcessEvent {
  pid: number
  name: string
  cmdline: string
  ppid: number
  pname: string
  timestamp: number
  startTime?: number
  exitTime?: number
  confidence?: number
  source?: EvidenceSource
}

export type FileOperation = 'created' | 'modified' | 'deleted'

export interface BuildFileEvent {
  filePath: string
  size: number
  operation: FileOperation
  timestamp: number
  sha256?: string
  confidence?: number
  source?: EvidenceSource
}

export interface FileReadEvent {
  filePath: string
  pid: number
  processName: string
  timestamp: number
  size: number
  confidence?: number
  source?: EvidenceSource
}

export interface BuildNetEvent {
  type: 'tcp' | 'dns'
  host: string
  port?: number
  timestamp: number
  confidence?: number
  source?: EvidenceSource
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

export interface ArtifactHash {
  filePath: string
  sha256: string
  size: number
}

export interface BuildDiffEntry {
  field: string
  before: string
  after: string
}

export interface ObservationConfidence {
  overall: number
  signals: Record<string, number>
  coverage: number
  sources: EvidenceSource[]
  weakestSignal: number
  strongestSignal: number
}

export interface OrphanProcessInfo {
  pid: number
  name: string
  cmdline: string
  ppid: number
  pname: string
  reason: string
  timestamp: number
}

export interface NamedPipeEvent {
  pipePath: string
  pid: number
  processName: string
  operation: 'read' | 'write' | 'create'
  timestamp: number
}

export interface MemoryRegion {
  start: string
  end: string
  permissions: string
  path: string
  inode: number
}

export interface ProcessMaps {
  pid: number
  processName: string
  regions: MemoryRegion[]
  ldPreload: string | null
  suspiciousRegions: string[]
  timestamp: number
}

export interface ResponseFileChange {
  tool: string
  pid: number
  responseFile: string
  originalSha256: string
  currentSha256: string
  changed: boolean
  timestamp: number
}

export interface RecordOptions {
  observeOnly?: boolean
  timeoutMs?: number
  pollProcessMs?: number
  pollFileMs?: number
  pollNetMs?: number
  pollReadMs?: number
  failOnError?: boolean
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
  env: Record<string, string>
  processes: BuildProcessEvent[]
  files: BuildFileEvent[]
  network: BuildNetEvent[]
  artifactHashes: ArtifactHash[]
  summary: BuildSummary
  hashChain: BuildChainLink[]
  identity?: BuildIdentity
  readFiles?: FileReadEvent[]
  inputIdentity?: BuildInputIdentity
  scriptIdentities?: ScriptIdentity[]
  pathResolutions?: PathState[]
  trustResult?: TrustResult
  buildIntent?: BuildIntentStep[]
  buildContractViolations?: BuildContractViolation[]
  secretFlow?: SecretFlow
  compilerInvocations?: CompilerInvocationIdentity
  hermetricScore?: number
  reproducibilityScore?: number
  observationConfidence?: ObservationConfidence
  orphanProcesses?: OrphanProcessInfo[]
  namedPipes?: NamedPipeEvent[]
  processMaps?: ProcessMaps[]
  responseFileChanges?: ResponseFileChange[]
  recordOptions?: RecordOptions
  confidencePaths?: ConfidencePath[]
  evidenceGraph?: EvidenceGraph
  processTimelines?: ProcessTimeline[]
}

export interface ProcessNode {
  name: string
  pid: number
  ppid: number
  cmdline: string
  children: ProcessNode[]
}

export interface BuildGraphEdge {
  from: string
  to: string
  type: 'produced' | 'consumed' | 'spawned' | 'configured'
  fromPid?: number
  toPid?: number
  timestamp?: number
}

export interface BuildDna {
  toolchain: string[]
  envVector: string[]
  artifactHashes: string[]
  processGraphSignature: string
  networkProfile: string
  totalFileOps: number
  durationMs: number
  anomalyCount: number
}

export interface MultiDna {
  toolchain: string
  environment: string
  artifact: string
  network: string
  graph: string
  behavior: string
}

export interface MultiDnaSimilarity {
  overall: number
  toolchain: number
  environment: number
  artifact: number
  network: number
  graph: number
  behavior: number
}

export interface BuildExplanation {
  summary: string
  confidence: number
  confidenceLabel: 'HIGH' | 'MODERATE' | 'LOW'
  confidenceBreakdown: ConfidenceBreakdown
  reasons: string[]
  changes: string[]
  rootCause: string
  causalDag: CausalNode[]
}

export interface ConfidenceBreakdown {
  overall: number
  toolchain: number
  environment: number
  artifact: number
  network: number
  graph: number
  behavior: number
  nSignals: number
  diversity: number
  severityBonus: number
}

export interface CausalNode {
  id: string
  label: string
  type: 'process' | 'file' | 'network' | 'artifact' | 'behavior'
  detail: string
  depth: number
  children: CausalNode[]
  timestamp?: number
}

export interface BuildBaselineStats {
  count: number
  meanDurationMs: number
  stdDurationMs: number
  meanArtifactCount: number
  stdArtifactCount: number
  meanFileOps: number
  stdFileOps: number
  typicalToolchain: string[]
  typicalGraphSignature: string | null
}

export interface BuildNormalityResult {
  zScoreDuration: number
  zScoreArtifacts: number
  zScoreFileOps: number
  overallNormality: number
  isOutlier: boolean
}

export interface BuildDnaSimilarity {
  overall: number
  toolchain: number
  artifacts: number
  processGraph: number
  network: number
}

export interface BuildSummary {
  totalProcesses: number
  uniqueProcesses: string[]
  buildToolsDetected: string[]
  filesCreated: number
  filesModified: number
  filesDeleted: number
  filesRead: number
  networkConnections: number
  dnsQueries: string[]
  artifactsHashed: number
  anomalies: string[]
  processTree: ProcessNode[]
  totalHashLinks: number
  avgProcessConfidence?: number
  avgFileConfidence?: number
  avgNetConfidence?: number
  primaryEvidenceSource?: EvidenceSource
}

export const BUILD_TOOLS = new Set([
  'gcc', 'g++', 'clang', 'clang++', 'cl.exe', 'cl', 'link.exe', 'link',
  'ld', 'ld.lld', 'lld-link', 'ar', 'lib.exe', 'ranlib', 'strip',
  'objcopy', 'objdump', 'nm', 'readelf', 'size',
  'make', 'cmake', 'ninja', 'nmake', 'msbuild', 'meson', 'scons',
  'cargo', 'rustc', 'go', 'javac', 'kotlinc', 'scalac',
  'node', 'tsc', 'esbuild', 'webpack', 'rollup', 'vite', 'babel',
  'python', 'python3', 'pip', 'pip3',
  'cc', 'c++', 'gcc-*', 'g++-*',
  'configure', 'autoconf', 'automake', 'libtool', 'pkg-config',
  'awk', 'gawk', 'sed', 'm4', 'bison', 'flex', 'yacc', 'lex',
  'docker', 'podman',
])

export const DANGEROUS_BUILD_TOOLS = new Set([
  'curl', 'wget', 'fetch', 'axel', 'aria2c',
  'perl', 'ruby', 'lua',
  'openssl', 'base64',
  'telnet', 'nc', 'ncat', 'socat',
  'gdb', 'lldb', 'objdump', 'readelf', 'strings',
])

export const BUILD_ENV_KEYS = [
  'CC', 'CXX', 'CFLAGS', 'CXXFLAGS', 'LDFLAGS', 'LD_LIBRARY_PATH',
  'LD_PRELOAD', 'PKG_CONFIG_PATH', 'PATH', 'HOME', 'USER',
  'CMAKE_PREFIX_PATH', 'CPATH', 'LIBRARY_PATH', 'INCLUDE',
  'npm_config_registry', 'NODE_ENV', 'PYTHONPATH',
  'CARGO_HOME', 'GOPATH', 'GOROOT', 'RUSTUP_HOME',
]

// ── Toolchain Identity ─────────────────────────────────────
export interface ToolIdentity {
  name: string
  realPath: string
  sha256: string
  size: number
  version: string | null
  mtime: string | null
}

export interface BuildIdentity {
  hostname: string
  platform: string
  arch: string
  kernel: string
  kernelVersion: string
  container: string | null
  ciProvider: string | null
  ciRunId: string | null
  ciRunNumber: string | null
  ciRepository: string | null
  ciRef: string | null
  ciSha: string | null
  runnerName: string | null
  runnerArch: string | null
  dockerImage: string | null
  toolVersions: Record<string, string>
  toolIdentities: ToolIdentity[]
  builderProcess: string
  osVersion: string
  cpus: number
  memoryGb: number
  uptimeHours: number
}

// ── Trend Engine / Slow Drift ──────────────────────────────
export interface TrendMetric {
  metric: string
  values: number[]
  timestamps: number[]
  slope: number
  cusum: number
  ewma: number
  mean: number
  std: number
  drift: 'none' | 'low' | 'medium' | 'high'
  alert: boolean
}

export interface TrendResult {
  buildsAnalyzed: number
  timeRangeMs: number
  metrics: TrendMetric[]
  overallDrift: 'none' | 'low' | 'medium' | 'high'
  findings: string[]
}

// ── Provenance Graph ───────────────────────────────────────
export type ProvenanceNodeType = 'source' | 'intermediate' | 'artifact' | 'tool' | 'script'

export interface ProvenanceNode {
  id: string
  label: string
  type: ProvenanceNodeType
  detail: string
  sha256?: string
  size?: number
  timestamp?: number
}

export interface ProvenanceEdge {
  from: string
  to: string
  type: 'compiled' | 'linked' | 'archived' | 'generated' | 'downloaded' | 'copied' | 'configured' | 'read'
  tool: string
  timestamp?: number
}

export interface ProvenanceGraph {
  nodes: ProvenanceNode[]
  edges: ProvenanceEdge[]
  stages: string[]
  buildId: string
}
export interface SectionInfo {
  name: string
  size: number
  flags: string
  entropy: number
}

export interface ArtifactAnalysis {
  filePath: string
  format: 'elf' | 'pe' | 'macho' | 'wasm' | 'unknown'
  architecture: string
  size: number
  sha256: string
  sections: SectionInfo[]
  symbolsAdded: string[]
  symbolsRemoved: string[]
  importsAdded: string[]
  importsRemoved: string[]
  suspiciousStrings: string[]
  entropy: number
  suspiciousFindings: string[]
}

export interface ArtifactDiff {
  addedSections: string[]
  removedSections: string[]
  changedSections: string[]
  addedSymbols: string[]
  removedSymbols: string[]
  addedImports: string[]
  removedImports: string[]
  newSuspiciousStrings: string[]
  entropyDelta: number
  findings: string[]
}

// ── Phase 2: Release Baseline ───────────────────────────────
export interface ReleaseEntry {
  buildId: string
  tag: string
  timestamp: number
}

export interface ReleaseStore {
  currentRelease: string | null
  releases: ReleaseEntry[]
}

// ── Compiler Invocation Identity ────────────────────────────
export interface CompilerInvocation {
  tool: string
  argv: string[]
  cwd: string
  responseFiles: string[]
  responseFileContent: string[]
  envSnapshot: Record<string, string>
  pid: number
  timestamp: number
  inputFiles: string[]
  outputFiles: string[]
  flags: string[]
  defines: string[]
  includeDirs: string[]
  hasResponseFile: boolean
  hasStdinInput: boolean
  fromStdin?: boolean
  fromMemfd?: boolean
}

export interface CompilerInvocationIdentity {
  invocations: CompilerInvocation[]
  totalInvocations: number
  uniqueFlags: string[]
  suspiciousInvocations: string[]
  stdinInvocations?: number
  memfdInvocations?: number
}

// ── Build Input Identity ────────────────────────────────────
export type BuildInputCategory = 'build_system' | 'language_config' | 'ci_config' | 'shell_script' | 'source'

export interface BuildInput {
  filePath: string
  category: BuildInputCategory
  sha256: string
  size: number
  mtime: number
  permissions: string
  owner: string
  symlinkTarget: string | null
  realPath: string
  encoding: string
}

export interface BuildInputIdentity {
  inputs: BuildInput[]
  totalInputs: number
  inputFingerprint: string
  inputStability: number | null
  changedInputs: InputChange[]
}

export interface InputChange {
  input: BuildInput
  changeType: 'new' | 'removed' | 'modified' | 'renamed' | 'permission_changed' | 'owner_changed' | 'symlink_changed'
  previousSha256?: string
}

export interface ScriptIdentity {
  filePath: string
  sha256: string
  argv: string
  interpreter: string
  interpreterSha256: string
  realPath: string
  size: number
  mtime: number
  imports: string[]
}

// ── Build Intent ────────────────────────────────────────────
export type ProcessIntent =
  | 'configure'
  | 'compile'
  | 'link'
  | 'archive'
  | 'download'
  | 'script'
  | 'package'
  | 'test'
  | 'install'
  | 'unknown'

export interface BuildIntentStep {
  tool: string
  intent: ProcessIntent
  timestamp: number
  durationMs: number
}

export interface BuildIntentFlow {
  expected: string[]
  observed: ProcessIntent[]
  deviations: string[]
}

// ── Build Contract ──────────────────────────────────────────
export interface BuildContractEntry {
  tool: string
  firstSeen: number
  lastSeen: number
  count: number
  intent: ProcessIntent
}

export interface BuildContractViolation {
  tool: string
  intent: ProcessIntent
  reason: string
  severity: 'info' | 'warning' | 'critical'
}

// ── PATH Resolution ─────────────────────────────────────────
export interface ToolResolution {
  toolName: string
  resolvedPath: string
  realPath: string
  sha256: string
  version: string
  fromPathEntry: string
  pathIndex: number
}

export interface PathState {
  pathValue: string
  entries: string[]
  resolutions: ToolResolution[]
  timestamp: number
}

// ── Trust Engine ────────────────────────────────────────────
export interface TrustDimension {
  name: string
  score: number
  weight: number
  evidence: string[]
  maxScore: number
}

export interface TrustResult {
  overallTrust: number
  dimensions: TrustDimension[]
  breakdown: string[]
  inputStability: number
  toolchainPurity: number
  buildDeterminism: boolean
}

// ── Phase 1: Explain types ──────────────────────────────────
export interface ExplainResult {
  buildId: string
  comparedAgainst: string
  summary: string
  reasons: string[]
  changes: string[]
  rootCause: string
  confidence: number
}

export interface ExplainEvent {
  type: 'process_spawn' | 'file_create' | 'file_modify' | 'file_delete' | 'network_conn' | 'dns_query' | 'artifact_hash'
  processName?: string
  parentProcess?: string
  fileName?: string
  host?: string
  port?: number
  artifact?: string
  oldHash?: string
  newHash?: string
  oldSize?: number
  newSize?: number
  stage?: string
  known?: boolean
  severity?: 'info' | 'warning' | 'high'
}

// ── Secret Flow ──────────────────────────────────────────────
export interface SecretAccess {
  type: string
  severity: 'critical' | 'high' | 'medium'
  filePath: string
  match: string
  line: number
  context: string
  snippet: string
  sha256: string
  pid?: number
  processName?: string
  timestamp?: number
}

export interface SecretFlowChain {
  processName: string
  pid: number
  processCmdline: string
  secrets: SecretAccess[]
  networkEvents: BuildNetEvent[]
  hasExfilRisk: boolean
  severity: 'critical' | 'high' | 'medium' | 'low'
}

export interface SecretFlow {
  secretAccesses: SecretAccess[]
  chains: SecretFlowChain[]
  totalSecrets: number
  criticalCount: number
  exfilRiskCount: number
}

// ── Evidence Normalization ────────────────────────────────────
export const EVIDENCE_SCHEMA_VERSION = 1

export interface EvidenceSchema {
  version: number
  createdAt: number
}
export type EvidenceType =
  | 'PROCESS_CREATED'
  | 'PROCESS_EXITED'
  | 'PROCESS_SPAWNED'
  | 'FILE_CREATED'
  | 'FILE_MODIFIED'
  | 'FILE_DELETED'
  | 'FILE_READ'
  | 'FILE_WRITTEN'
  | 'NETWORK_CONNECT'
  | 'NETWORK_DISCONNECT'
  | 'NETWORK_DNS_QUERY'
  | 'NETWORK_UPLOAD'
  | 'NETWORK_DOWNLOAD'
  | 'SECRET_ACCESSED'
  | 'SECRET_EXFILTRATED'
  | 'COMPILER_STARTED'
  | 'COMPILER_FINISHED'
  | 'LINKER_STARTED'
  | 'LINKER_FINISHED'
  | 'ARTIFACT_CREATED'
  | 'ARTIFACT_HASH_CHANGED'
  | 'ARTIFACT_MODIFIED'
  | 'SCRIPT_EXECUTED'
  | 'TOOL_INVOKED'
  | 'PATH_CHANGED'
  | 'ENV_CHANGED'
  | 'CONTRACT_VIOLATED'
  | 'CONFIGURED'
  | 'DOWNLOADED'
  | 'CANARY_TRIGGERED'

export type EvidenceRelation =
  | 'spawned'
  | 'read'
  | 'wrote'
  | 'created'
  | 'modified'
  | 'deleted'
  | 'compiled'
  | 'linked'
  | 'archived'
  | 'generated'
  | 'downloaded'
  | 'configured'
  | 'uploaded'
  | 'exfiltrated'
  | 'loaded'
  | 'accessed'
  | 'connected'
  | 'triggered'
  | 'heuristic_association'

export interface EvidenceNode {
  id: string
  type: EvidenceType
  label: string
  timestamp: number
  confidence: number
  observationConfidence: number
  inferenceConfidence: number
  source: EvidenceSource
  pid?: number
  processName?: string
  filePath?: string
  host?: string
  port?: number
  sha256?: string
  size?: number
  severity?: string
  attributes: Record<string, unknown>
}

export interface EvidenceEdge {
  from: string
  to: string
  relation: EvidenceRelation
  confidence: number
  timestamp: number
  degradation: number
  // Temporal attributes
  latencyMs?: number
  causalDelayMs?: number
  timeWindowStart?: number
  timeWindowEnd?: number
}

export interface TemporalPath {
  nodes: string[]
  edges: EvidenceEdge[]
  totalLatencyMs: number
  causalDelayMs: number
  timeSpanMs: number
  bottleneckEdge?: EvidenceEdge
}

export interface TemporalEvidenceGraph {
  graph: EvidenceGraph
  paths: TemporalPath[]
  longestCausalChain: TemporalPath
  avgEdgeLatencyMs: number
  maxEdgeLatencyMs: number
  criticalPath: TemporalPath
}

export interface BayesianRelation {
  relation: EvidenceRelation
  priorP: number
  likelihoodPositive: number
  likelihoodNegative: number
  posteriorGivenEvidence: number
  posteriorGivenNoEvidence: number
  sampleCount: number
}

export interface BayesianNetwork {
  relations: BayesianRelation[]
  globalPrior: number
  overallPosterior: number
  calibrationVersion: number
}

export interface DominatorAnalysis {
  currentDominators: Record<string, string | null>
  previousDominators: Record<string, string | null> | null
  dominantProcess: string | null
  dominantProcessChanged: boolean
  toolchainShiftDetected: boolean
  hijackRiskScore: number
  dominantPath: string[]
  anomalySignals: string[]
}

export interface EvidenceGraphMetrics {
  // Already computed
  nodeCount: number
  edgeCount: number
  graphDensity: number
  graphEntropy: number
  maxDepth: number
  componentCount: number
  sccCount: number
  isDag: boolean
  // New metrics
  avgBetweenness: number
  maxBetweenness: number
  avgCloseness: number
  maxCloseness: number
  idomCount: number
  longestCausalChainMs: number
  criticalPathMs: number
  avgEdgeLatencyMs: number
  maxEdgeLatencyMs: number
  edgeLatencyVariance: number
  temporalSpanMs: number
  secretPathLength: number
  networkPathLength: number
  compilerDiversity: number
  toolchainEntropy: number
  processTreeDepth: number
  avgBranchFactor: number
  rootEccentricity: number
  avgInferenceDegradation: number
  avgObservationDegradation: number
  confidenceVariance: number
  contractViolationRatio: number
  fileReadRatio: number
  secretToProcessRatio: number
  networkToProcessRatio: number
}

export interface EvidenceGraph {
  nodes: EvidenceNode[]
  edges: EvidenceEdge[]
  buildId: string
  rootPid: number
  rootProcess: string
  createdAt: number
  schemaVersion: number
}

export interface ProcessTimelineEvent {
  pid: number
  processName: string
  sequenceIndex: number
  type: EvidenceType
  label: string
  timestamp: number
  confidence: number
  observationConfidence: number
  inferenceConfidence: number
  source: EvidenceSource
  detail: string
  relatedPids: number[]
  relatedFiles: string[]
  relatedHosts: string[]
  durationMs?: number
}

export interface ProcessTimeline {
  pid: number
  processName: string
  cmdline: string
  ppid: number
  startTime: number
  exitTime?: number
  events: ProcessTimelineEvent[]
  totalEvents: number
  secretsRead: number
  filesCreated: number
  networkConnections: number
  dataUploadedBytes: number
  childPids: number[]
}

export interface ConfidencePath {
  path: string[]
  edges: EvidenceRelation[]
  initialConfidence: number
  propagatedConfidence: number
  degradationFactor: number
}
