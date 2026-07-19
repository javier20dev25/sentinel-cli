'use strict';

import {
  SensorProvider, SensorCapability, CoverageInfo,
  HealthReport, RuntimeMetrics, NetworkFlow
} from './types';

export const SENSOR_TRUST_SCORES: Record<string, number> = {
  FileWatcher: 0.98,
  GitDetector: 0.95,
  ProcessMonitor: 0.92,
  DnsObserver: 0.71,
  HttpInterceptor: 0.88,
  TlsInterceptor: 0.55,
  ConnectionInspector: 0.85,
  WebSocketObserver: 0.78,
};

export const DEFAULT_CAPABILITIES: Record<string, SensorCapability> = {
  FileWatcher: {
    detects: ['file_read', 'file_write', 'decoy_file_access', 'temp_file_creation'],
    cannotDetect: ['memory_only_ops', 'network_traffic', 'dns_queries', 'git_operations'],
    confidence: 0.98,
    latencyMs: 50,
  },
  GitDetector: {
    detects: ['git_clone', 'git_push', 'git_bundle', 'git_log', 'git_filter_branch', 'contaminated_git_read'],
    cannotDetect: ['file_access', 'network_traffic', 'process_injection'],
    confidence: 0.95,
    latencyMs: 30,
  },
  ProcessMonitor: {
    detects: ['process_spawn', 'process_chain', 'child_process', 'command_line_args', 'preparation_phase'],
    cannotDetect: ['dns_traffic', 'encrypted_payloads', 'git_operations'],
    confidence: 0.92,
    latencyMs: 100,
  },
  DnsObserver: {
    detects: ['dns_query', 'dns_tunnel', 'domain_generation_algorithm', 'high_query_volume', 'suspicious_tld'],
    cannotDetect: ['encrypted_dns', 'dot_queries', 'file_system_ops'],
    confidence: 0.71,
    latencyMs: 200,
  },
  HttpInterceptor: {
    detects: ['http_request', 'http_post', 'data_exfiltration_http', 'large_payload', 'suspicious_header'],
    cannotDetect: ['https_content', 'raw_tcp', 'dns_traffic'],
    confidence: 0.88,
    latencyMs: 150,
  },
  TlsInterceptor: {
    detects: ['tls_handshake', 'sni_sniff', 'certificate_pinning', 'tls_fingerprint'],
    cannotDetect: ['encrypted_payload', 'http_content', 'dns_traffic'],
    confidence: 0.55,
    latencyMs: 180,
  },
  ConnectionInspector: {
    detects: ['tcp_connection', 'udp_flow', 'port_scan', 'connection_frequency', 'protocol_hopping', 'slow_read'],
    cannotDetect: ['encrypted_payload', 'application_layer', 'dns_queries'],
    confidence: 0.85,
    latencyMs: 80,
  },
  WebSocketObserver: {
    detects: ['websocket_open', 'websocket_message', 'websocket_close', 'persistent_channel', 'binary_frame'],
    cannotDetect: ['raw_tcp', 'http_rest', 'file_system_ops'],
    confidence: 0.78,
    latencyMs: 120,
  },
};

export class RuntimeMetricsCollector {
  private metrics: RuntimeMetrics;
  private startTime: number;
  private flowTimestamps: number[] = [];
  private totalProcessTimeMs = 0;
  private maxLatencyMs = 0;
  private processingCount = 0;
  private memorySamples: number[] = [];

  constructor() {
    this.startTime = Date.now();
    this.metrics = this.zeroMetrics();
  }

  recordFlowReceived(): void {
    this.metrics.flowsReceived++;
    this.flowTimestamps.push(Date.now());
    this.trimFlowTimestamps();
  }

  recordFlowDiscarded(): void {
    this.metrics.flowsDiscarded++;
  }

  recordProcessingTime(ms: number): void {
    this.totalProcessTimeMs += ms;
    this.processingCount++;
    this.maxLatencyMs = Math.max(this.maxLatencyMs, ms);
  }

  recordBackpressure(): void {
    this.metrics.backpressure = true;
  }

  recordBufferUsage(usage: number): void {
    this.metrics.bufferUsage = usage;
  }

  recordMemorySample(mb: number): void {
    this.memorySamples.push(mb);
    if (this.memorySamples.length > 100) this.memorySamples.shift();
  }

  getMetrics(): RuntimeMetrics {
    const uptime = Date.now() - this.startTime;
    const avgTime = this.processingCount > 0
      ? Math.round(this.totalProcessTimeMs / this.processingCount)
      : 0;
    const eps = uptime > 0
      ? Math.round((this.metrics.flowsReceived / uptime) * 1000)
      : 0;
    const peakMem = this.memorySamples.length > 0
      ? Math.round(Math.max(...this.memorySamples))
      : 0;

    return {
      flowsReceived: this.metrics.flowsReceived,
      flowsDiscarded: this.metrics.flowsDiscarded,
      avgProcessTimeMs: avgTime,
      eventsPerSecond: eps,
      backpressure: this.metrics.backpressure,
      bufferUsage: this.metrics.bufferUsage,
      peakMemoryMb: peakMem,
      queueDepth: this.flowTimestamps.length,
      uptimeMs: uptime,
    };
  }

  reset(): void {
    this.startTime = Date.now();
    this.flowTimestamps = [];
    this.totalProcessTimeMs = 0;
    this.maxLatencyMs = 0;
    this.processingCount = 0;
    this.memorySamples = [];
    this.metrics = this.zeroMetrics();
  }

  private zeroMetrics(): RuntimeMetrics {
    return {
      flowsReceived: 0, flowsDiscarded: 0, avgProcessTimeMs: 0,
      eventsPerSecond: 0, backpressure: false, bufferUsage: 0,
      peakMemoryMb: 0, queueDepth: 0, uptimeMs: 0,
    };
  }

  private trimFlowTimestamps(): void {
    const cutoff = Date.now() - 1000;
    while (this.flowTimestamps.length > 0 && this.flowTimestamps[0] < cutoff) {
      this.flowTimestamps.shift();
    }
  }
}

export class HealthMonitor {
  private metrics: RuntimeMetricsCollector;
  private sensorStatuses: Map<string, { ok: boolean; latencyMs: number; error?: string; lastEvent?: Date }> = new Map();
  private capabilities: Map<string, SensorCapability> = new Map();

  constructor() {
    this.metrics = new RuntimeMetricsCollector();
  }

  registerSensor(name: string, capability: SensorCapability): void {
    this.capabilities.set(name, capability);
    this.sensorStatuses.set(name, { ok: true, latencyMs: 0 });
  }

  recordSensorOk(name: string, latencyMs: number): void {
    this.sensorStatuses.set(name, {
      ok: true, latencyMs, lastEvent: new Date(),
    });
  }

  recordSensorError(name: string, error: string, latencyMs: number): void {
    this.sensorStatuses.set(name, {
      ok: false, latencyMs, error, lastEvent: new Date(),
    });
  }

  getHealthReport(): HealthReport {
    const sensors: Array<{ name: string; ok: boolean; latencyMs: number; error?: string; lastEvent?: Date }> = [];
    let totalOk = 0;
    let totalLatency = 0;

    for (const [name, status] of this.sensorStatuses) {
      sensors.push({ name, ...status });
      if (status.ok) totalOk++;
      totalLatency += status.latencyMs;
    }

    const totalSensors = sensors.length || 1;
    const healthRatio = totalOk / totalSensors;
    const status: HealthReport['status'] =
      healthRatio >= 0.8 ? 'healthy' :
      healthRatio >= 0.5 ? 'degraded' : 'unhealthy';

    const coverage = this.computeCoverage();

    return {
      status,
      timestamp: new Date(),
      sensors,
      coverage,
      metrics: this.metrics.getMetrics(),
    };
  }

  computeCoverage(): CoverageInfo {
    const sensors: CoverageInfo['sensors'] = [];
    let totalScore = 0;
    const blindSpots = new Set<string>();

    for (const [name, status] of this.sensorStatuses) {
      const capability = this.capabilities.get(name) ?? {
        detects: [], cannotDetect: [], confidence: 0.5, latencyMs: 0,
      };
      const trust = SENSOR_TRUST_SCORES[name] ?? 0.8;
      const coverage = status.ok ? trust * capability.confidence * 100 : 0;
      sensors.push({
        name, active: status.ok,
        coverage: Math.round(coverage * 100) / 100,
        capability,
      });
      totalScore += coverage;
      for (const blind of capability.cannotDetect) {
        blindSpots.add(blind);
      }
    }

    const totalConfigured = sensors.length || 1;
    const score = Math.min(100, Math.round(totalScore / totalConfigured * 100) / 100);

    return {
      score,
      sensors,
      totalActive: sensors.filter(s => s.active).length,
      totalConfigured,
      blindSpots: [...blindSpots].sort(),
    };
  }

  getMetricsCollector(): RuntimeMetricsCollector {
    return this.metrics;
  }
}

export function withResilience<T>(
  providerName: string,
  healthMonitor: HealthMonitor,
  fn: () => T,
  timeoutMs = 5000
): T | undefined {
  const start = Date.now();
  try {
    const result = fn();
    const elapsed = Date.now() - start;
    healthMonitor.recordSensorOk(providerName, elapsed);
    return result;
  } catch (err: unknown) {
    const elapsed = Date.now() - start;
    const msg = err instanceof Error ? err.message : String(err);
    healthMonitor.recordSensorError(providerName, msg, elapsed);
    return undefined;
  }
}

export async function withResilienceAsync<T>(
  providerName: string,
  healthMonitor: HealthMonitor,
  fn: () => Promise<T>,
  timeoutMs = 5000
): Promise<T | undefined> {
  const start = Date.now();
  try {
    const result = await Promise.race([
      fn(),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error(`Provider ${providerName} timed out after ${timeoutMs}ms`)), timeoutMs)
      ),
    ]);
    const elapsed = Date.now() - start;
    healthMonitor.recordSensorOk(providerName, elapsed);
    return result;
  } catch (err: unknown) {
    const elapsed = Date.now() - start;
    const msg = err instanceof Error ? err.message : String(err);
    healthMonitor.recordSensorError(providerName, msg, elapsed);
    return undefined;
  }
}
