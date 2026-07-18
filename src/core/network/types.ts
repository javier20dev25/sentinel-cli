'use strict';

export interface NetworkFlow {
  id: string;
  sessionId: string;
  timestamp: Date;
  protocol: 'TCP' | 'TLS' | 'HTTP' | 'WS' | 'DNS';
  sourceAddr: string;
  sourcePort: number;
  destAddr: string;
  destPort: number;
  hostname?: string;
  sni?: string;
  tlsVersion?: string;
  bytesSent: number;
  bytesReceived: number;
  durationMs: number;
  method?: string;
  path?: string;
  contentType?: string;
  statusCode?: number;
  headers?: Record<string, string>;
  bodyPreview?: string;
  wsFrames?: WebSocketFrame[];
  dnsQuery?: string;
  dnsResponse?: string[];
}

export interface WebSocketFrame {
  opcode: number;
  payload: Buffer | string;
  length: number;
  timestamp: Date;
}

export interface ProcessEvent {
  sessionId?: string;
  pid: number;
  name: string;
  commandLine: string;
  parentPid?: number;
  parentName?: string;
  timestamp: Date;
  username?: string;
  riskIndicators: string[];
}

export interface FileAccessEvent {
  filePath: string;
  processName: string;
  pid: number;
  operation: 'read' | 'write' | 'open' | 'create';
  timestamp: Date;
  bytesRead?: number;
}

export interface GitCommandEvent {
  pid: number;
  processName: string;
  commandLine: string;
  action: 'clone' | 'bundle' | 'archive' | 'push' | 'fetch' | 'pack' | 'rev-list' | 'log' | 'grep' | 'other' |
    'pull' | 'diff' | 'status' | 'add' | 'commit' | 'checkout' | 'branch' | 'merge' | 'rebase' | 'init' | 'config' |
    'remote' | 'rev-parse' | 'cat-file' | 'ls-tree' | 'show-ref' | 'for-each-ref' | 'stash' | 'tag' | 'reset' |
    'revert' | 'cherry-pick' | 'clean' | 'submodule' | 'worktree' | 'gc' | 'fsck';
  timestamp: Date;
  repository?: string;
}

export interface Artifact {
  type: 'file' | 'prompt' | 'embedding' | 'git-object' | 'git-bundle' | 'secret' | 'canary' | 'archive';
  name: string;
  sizeBytes: number;
  detectedAt: Date;
  confidence: number;
  sourceFlowId?: string;
  detail?: string;
}

export interface Behavior {
  id: string;
  sessionId: string;
  type: BehaviorType;
  confidence: number;
  evidence: string[];
  artifacts: Artifact[];
  timestamp: Date;
  source: 'process' | 'file' | 'git' | 'dns' | 'connection' | 'http' | 'websocket' | 'tls';
}

export type BehaviorType =
  | 'repo_indexed'
  | 'git_history_read'
  | 'git_objects_read'
  | 'git_bundle_created'
  | 'git_bundle_uploaded'
  | 'git_archive_created'
  | 'secrets_scanned'
  | 'secrets_exfiltrated'
  | 'embeddings_generated'
  | 'full_repo_snapshot'
  | 'canary_exfiltrated'
  | 'mass_file_read'
  | 'suspicious_connection'
  | 'ai_prompt_sent'
  | 'code_upload'
  | 'prompt_injection_attempt'
  | 'process_suspicious'
  | 'dns_suspicious'
  | 'tls_suspicious'
  | 'anti_evasion_detected'
  | 'preparation_detected'
  | 'process_chain_detected'
  | 'monitor_awareness_detected'
  | 'canary_read'
  | 'canary_modified'
  | 'fake_secret_read'
  | 'fake_secret_exfiltrated'
  | 'contaminated_git_read'
  | 'evidence_chain_detected'
  | 'pre_operational_snapshot_detected';

export interface RiskAssessment {
  score: number;
  level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  factors: RiskFactor[];
  behaviors: Behavior[];
  timestamp: Date;
}

export interface RiskFactor {
  name: string;
  contribution: number;
  detail: string;
}

export interface Evidence {
  id: string;
  sessionId: string;
  flowId?: string;
  behaviorId?: string;
  type: EvidenceType;
  title: string;
  description: string;
  data: Record<string, unknown>;
  timestamp: Date;
  severity: 'info' | 'warning' | 'critical';
}

export type EvidenceType =
  | 'connection_log'
  | 'process_log'
  | 'file_access_log'
  | 'git_command_log'
  | 'dns_query_log'
  | 'http_request_log'
  | 'websocket_log'
  | 'tls_handshake_log'
  | 'artifact_capture'
  | 'behavior_classification'
  | 'risk_calculation'
  | 'session_summary';

export type AntiEvasionSignalType =
  | 'artificial_rhythm'
  | 'fragmented_traffic'
  | 'protocol_hopping'
  | 'custom_compression'
  | 'monitor_awareness'
  | 'memory_only_ops'
  | 'distributed_chain'
  | 'no_temp_files'
  | 'preparation_phase'
  | 'process_chain';

export interface AntiEvasionSignal {
  id: string;
  sessionId: string;
  type: AntiEvasionSignalType;
  score: number;
  confidence: number;
  timestamp: Date;
  evidence: string[];
  details: Record<string, unknown>;
}

export interface EvidenceChainStep {
  order: number;
  type: string;
  description: string;
  timestamp: Date;
  eventIds: string[];
}

export interface EvidenceChain {
  id: string;
  sessionId: string;
  name: string;
  confidence: number;
  steps: EvidenceChainStep[];
  timestamp: Date;
  summary: string;
}

export interface CanaryConfig {
  enabled: boolean;
  decoyFiles: string[];
  fakeSecrets: boolean;
  contaminatedGitHistory: boolean;
  autoDeploy: boolean;
}

export interface CanaryEvent {
  id: string;
  sessionId: string;
  type: 'decoy_file_read' | 'decoy_file_modified' | 'fake_secret_read' | 'contaminated_git_read' | 'decoy_exfiltrated';
  canaryName: string;
  confidence: number;
  timestamp: Date;
  processName?: string;
  pid?: number;
  detail: string;
}

export interface NetworkAuditSession {
  id: string;
  startTime: Date;
  endTime?: Date;
  status: 'running' | 'stopped';
  config: NetworkAuditConfig;
  flows: NetworkFlow[];
  behaviors: Behavior[];
  evidence: Evidence[];
  verdict?: Verdict;
}

export interface NetworkAuditReport {
  session: NetworkAuditSession;
  summary: SessionDna;
  alerts: Evidence[];
  recommendations: string[];
  generatedAt: Date;
}

export interface SensorCapability {
  detects: string[];
  cannotDetect: string[];
  confidence: number;
  latencyMs: number;
}

export interface SensorProvider {
  readonly name: string;
  readonly category: 'filesystem' | 'process' | 'dns' | 'network' | 'git' | 'http' | 'tls' | 'websocket';
  readonly capability: SensorCapability;
  start(sessionId: string, callback: (event: unknown) => void): void;
  stop(): void;
  isRunning(): boolean;
  healthCheck(): { ok: boolean; latencyMs: number; error?: string };
}

export interface NetworkProvider extends SensorProvider {
  readonly category: 'network' | 'http' | 'tls' | 'websocket';
  start(sessionId: string, callback: (flow: NetworkFlow) => void): void;
}

export interface DnsProvider extends SensorProvider {
  readonly category: 'dns';
  start(sessionId: string, callback: (flow: NetworkFlow) => void): void;
}

export interface CoverageInfo {
  score: number;
  sensors: Array<{
    name: string;
    active: boolean;
    coverage: number;
    capability: SensorCapability;
  }>;
  totalActive: number;
  totalConfigured: number;
  blindSpots: string[];
}

export interface TrustScore {
  provider: string;
  score: number;
  samples: number;
  lastVerified: Date;
}

export interface HealthReport {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: Date;
  sensors: Array<{
    name: string;
    ok: boolean;
    latencyMs: number;
    error?: string;
    lastEvent?: Date;
  }>;
  coverage: CoverageInfo;
  metrics: RuntimeMetrics;
}

export interface RuntimeMetrics {
  flowsReceived: number;
  flowsDiscarded: number;
  avgProcessTimeMs: number;
  eventsPerSecond: number;
  backpressure: boolean;
  bufferUsage: number;
  peakMemoryMb: number;
  queueDepth: number;
  uptimeMs: number;
}

export type BlindSpotSeverity = 'low' | 'medium' | 'high' | 'critical';

export type BlindSpotStatus = 'open' | 'investigating' | 'resolved' | 'wontfix';

export interface BlindSpotEntry {
  id: string;
  title: string;
  description: string;
  howItHappened: string;
  sensorFailed: string;
  expectedBehavior: string;
  actualObservation: string;
  impact: string;
  severity: BlindSpotSeverity;
  status: BlindSpotStatus;
  sessionId?: string;
  createdAt: Date;
  updatedAt: Date;
  resolvedAt?: Date;
  resolution?: string;
}

export interface NetworkAuditConfig {
  enableProcessMonitor: boolean;
  enableFileWatcher: boolean;
  enableGitDetector: boolean;
  enableDnsObserver: boolean;
  enableConnectionInspector: boolean;
  enableHttpInterceptor: boolean;
  enableWebSocketObserver: boolean;
  enableTlsInterceptor: boolean;
  dbPath: string;
  notificationEnabled: boolean;
  autoStartOnBoot: boolean;
  trustedHosts: string[];
  trustedProcesses: string[];
  alertThreshold: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  antiEvasionEnabled: boolean;
  processChainDetection: boolean;
  preparationDetection: boolean;
  canaryConfig: CanaryConfig;
  performanceBudget: {
    maxCpuPercent: number;
    maxMemoryMb: number;
    maxEventsPerSecond: number;
    providerTimeoutMs: number;
  };
}

export interface Verdict {
  sessionId: string;
  overallRisk: RiskAssessment;
  behaviors: Behavior[];
  evidence: Evidence[];
  sessionDna: SessionDna;
  timestamp: Date;
  confidenceScore: number;
  coverageInfo: CoverageInfo;
  healthAtEnd: HealthReport;
}

export interface SessionDna {
  sessionId: string;
  startTime: Date;
  endTime?: Date;
  durationMs: number;
  totalFlows: number;
  totalBytesSent: number;
  totalBytesReceived: number;
  uniqueHosts: string[];
  repositoriesAccessed: string[];
  behaviors: BehaviorType[];
  topRiskFactor: string;
  riskScore: number;
  riskLevel: string;
  verdictSummary: string;
  confidence: number;
  antiEvasionScore: number;
  antiEvasionSignals: AntiEvasionSignalType[];
  evidenceChains: string[];
  preparationSignals: string[];
  processChains: string[];
  hasCanaryTrigger: boolean;
  coverageScore: number;
  healthStatus: string;
  metrics: RuntimeMetrics;
}

export type ScenarioEvent =
  | { type: 'flow'; data: NetworkFlow }
  | { type: 'process'; data: ProcessEvent }
  | { type: 'file_access'; data: FileAccessEvent }
  | { type: 'git_command'; data: GitCommandEvent };

export interface ValidationScenario {
  id: string;
  name: string;
  description: string;
  tags: string[];
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  events: ScenarioEvent[];
  expected: {
    riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    riskScoreMin: number;
    riskScoreMax: number;
    confidenceMin: number;
    coverageMin: number;
    mustHaveBehaviors: BehaviorType[];
    mustNotHaveBehaviors: BehaviorType[];
  };
}

export interface CampaignResult {
  scenarioId: string;
  scenarioName: string;
  passed: boolean;
  riskLevel: string;
  riskScore: number;
  confidenceScore: number;
  coverageScore: number;
  behaviorsDetected: string[];
  expectedBehaviors: string[];
  missingBehaviors: string[];
  unexpectedBehaviors: string[];
  errors: string[];
  durationMs: number;
  timestamp: Date;
  details: {
    riskLevelMatch: boolean;
    riskScoreInRange: boolean;
    confidenceMet: boolean;
    coverageMet: boolean;
    allRequiredBehaviors: boolean;
    noForbiddenBehaviors: boolean;
  };
}

export interface CampaignReport {
  campaignId: string;
  name: string;
  totalScenarios: number;
  passed: number;
  failed: number;
  passRate: number;
  avgRiskScore: number;
  avgConfidence: number;
  avgCoverage: number;
  results: CampaignResult[];
  topFailures: Array<{ scenarioId: string; scenarioName: string; missingBehaviors: string[]; unexpectedBehaviors: string[] }>;
  timestamp: Date;
  durationMs: number;
}

export interface CampaignConfig {
  id: string;
  name: string;
  description: string;
  scenarioIds: string[];
  createdAt: Date;
}

export type EnvironmentDependency = 'docker' | 'go' | 'terraform';

export interface SessionProfile {
  id: string;
  category: 'benign' | 'ia' | 'suspicious' | 'malicious';
  tool: string;
  action: string;
  expectedRisk: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  tags: string[];
  requires?: EnvironmentDependency[];  // tools required beyond baseline (not available on all machines)
}

export interface SessionEnvironment {
  os: string;
  osVersion: string;
  cpu: string;
  memoryGb: number;
  nodeVersion: string;
  gitVersion: string;
  editor: string;
  sentinelVersion: string;
  policyVersion: string;
  corpusVersion: string;
  recordedAt: string;
}

export interface SessionPrivateMetadata {
  hostname: string;
  username: string;
  workingDirectory: string;
  absolutePaths?: string[];
}

export interface SessionGroundTruth {
  profileId: string;
  expectedRisk: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  expectedBehaviors: string[];
  forbiddenBehaviors: string[];
  reviewedBy: string;
  reviewStatus: 'unreviewed' | 'verified' | 'flagged';
  notes?: string;
}

export interface RecordedSession {
  format: 'sentinel-session-v1';
  metadata: {
    id: string;
    recordedAt: string;
    durationMs: number;
    platform: string;
    sentinelVersion: string;
    tags: string[];
    profile?: SessionProfile;
    environment?: SessionEnvironment;
  };
  private?: SessionPrivateMetadata;
  events: ScenarioEvent[];
}

export interface ReplayResult {
  sessionId: string;
  sessionName: string;
  verdict: Verdict | null;
  riskScore: number;
  riskLevel: string;
  confidence: number;
  behaviorsDetected: string[];
  errors: string[];
  durationMs: number;
  replayedAt: string;
}

export interface ReplayCampaign {
  id: string;
  name: string;
  sessions: RecordedSession[];
  results: ReplayResult[];
  createdAt: string;
  totalPassed: number;
  totalFailed: number;
}

export function generateId(): string {
  const ts = Date.now().toString(36);
  const r = Math.random().toString(36).substring(2, 8);
  return `na-${ts}-${r}`;
}

export function generateScenarioId(): string {
  const r1 = Math.random().toString(36).substring(2, 6);
  const r2 = Math.random().toString(36).substring(2, 6);
  return `SC-${r1}-${r2}`;
}
