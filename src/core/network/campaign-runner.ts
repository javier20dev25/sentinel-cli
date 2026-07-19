'use strict';

import {
  ValidationScenario, CampaignResult, CampaignReport, CampaignConfig,
  ScenarioEvent, NetworkFlow, ProcessEvent, FileAccessEvent,
  GitCommandEvent, Behavior, generateId, BehaviorType,
} from './types';
import { NetworkAuditPipeline } from './pipeline';
import { buildBehaviorEvidence } from './evidence-builder';

export class CampaignRunner {
  private pipeline: NetworkAuditPipeline;

  constructor() {
    this.pipeline = new NetworkAuditPipeline({
      enableProcessMonitor: true,
      enableFileWatcher: true,
      enableGitDetector: true,
      enableDnsObserver: true,
      enableConnectionInspector: true,
      enableHttpInterceptor: false,
      enableWebSocketObserver: false,
      enableTlsInterceptor: false,
      dbPath: '',
      notificationEnabled: false,
      autoStartOnBoot: false,
      trustedHosts: [],
      trustedProcesses: [],
      alertThreshold: 'MEDIUM',
      antiEvasionEnabled: true,
      processChainDetection: true,
      preparationDetection: true,
      canaryConfig: {
        enabled: true, decoyFiles: [],
        fakeSecrets: true, contaminatedGitHistory: true,
        autoDeploy: false,
      },
      performanceBudget: {
        maxCpuPercent: 100, maxMemoryMb: 1024,
        maxEventsPerSecond: 100000, providerTimeoutMs: 10000,
      },
    });
  }

  runScenario(scenario: ValidationScenario): CampaignResult {
    const startTime = Date.now();
    const sessionId = generateId();
    const errors: string[] = [];

    const canarySystem = this.pipeline.getCanarySystem();
    canarySystem.registerMockCanary('passwords.txt', 'C:\\project\\passwords.txt', 'SENTINEL_CANARY_TOKEN_passwords');
    canarySystem.registerMockCanary('.env.prod', 'C:\\project\\.env.prod', 'SENTINEL_CANARY_TOKEN_env_prod');
    canarySystem.registerMockCanary('ssh-private.key', 'C:\\project\\ssh-private.key', 'SENTINEL_CANARY_TOKEN_ssh_key');
    canarySystem.registerMockCanary('aws-keys.json', 'C:\\project\\src\\aws-keys.json', 'SENTINEL_CANARY_TOKEN_aws');
    canarySystem.registerMockCanary('database.sql', 'C:\\project\\src\\config\\database.sql', 'SENTINEL_CANARY_TOKEN_db');
    canarySystem.registerMockCanary('.secrets.env', 'C:\\project\\.secrets.env', 'SENTINEL_CANARY_TOKEN_secrets');
    canarySystem.registerMockCanary('.git_canary_commit', 'C:\\project\\.git_canary_commit', 'SENTINEL_CANARY_TOKEN_git');

    const flows: NetworkFlow[] = [];
    const processes: ProcessEvent[] = [];
    const fileAccesses: FileAccessEvent[] = [];
    const gitCommands: GitCommandEvent[] = [];

    const allBehaviors: Behavior[] = [];
    const allEvidence: import('./types').Evidence[] = [];

    for (const event of scenario.events) {
      try {
        switch (event.type) {
          case 'flow':
            event.data.sessionId = sessionId;
            flows.push(event.data);
            const flowResult = this.pipeline.processFlow(event.data, sessionId);
            allBehaviors.push(...flowResult.behaviors);
            allEvidence.push(...flowResult.evidence);
            break;
          case 'process':
            event.data.sessionId = sessionId;
            processes.push(event.data);
            const procResult = this.pipeline.processProcessEvent(event.data, sessionId);
            allBehaviors.push(...procResult.behaviors);
            allEvidence.push(...procResult.evidence);
            break;
          case 'file_access':
            fileAccesses.push(event.data);
            const fileResult = this.pipeline.processFileAccess(event.data, sessionId);
            allBehaviors.push(...fileResult.behaviors);
            allEvidence.push(...fileResult.evidence);
            break;
          case 'git_command':
            gitCommands.push(event.data);
            const gitResult = this.pipeline.processGitCommand(event.data, sessionId);
            allBehaviors.push(...gitResult.behaviors);
            allEvidence.push(...gitResult.evidence);
            break;
        }
      } catch (err: unknown) {
        errors.push(`Event ${event.type}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    if (fileAccesses.length > 1) {
      try {
        const massBehavior = this.pipeline.processBatchFileAccess(fileAccesses, sessionId);
        if (massBehavior) {
          allBehaviors.push(massBehavior);
          allEvidence.push(buildBehaviorEvidence(massBehavior, sessionId));
        }
      } catch (err: unknown) {
        errors.push(`batch_file_access: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    let verdict;
    try {
      verdict = this.pipeline.generateVerdict(
        sessionId, new Date(startTime),
        flows, allBehaviors,
        allEvidence,
        processes, fileAccesses, gitCommands
      );
    } catch (err: unknown) {
      errors.push(`verdict: ${err instanceof Error ? err.message : String(err)}`);
      const durationMs = Date.now() - startTime;
      return {
        scenarioId: scenario.id,
        scenarioName: scenario.name,
        passed: false,
        riskLevel: 'LOW',
        riskScore: 0,
        confidenceScore: 0,
        coverageScore: 0,
        behaviorsDetected: [],
        expectedBehaviors: scenario.expected.mustHaveBehaviors,
        missingBehaviors: scenario.expected.mustHaveBehaviors,
        unexpectedBehaviors: [],
        errors,
        durationMs,
        timestamp: new Date(),
        details: {
          riskLevelMatch: false, riskScoreInRange: false,
          confidenceMet: false, coverageMet: false,
          allRequiredBehaviors: false, noForbiddenBehaviors: true,
        },
      };
    }

    const durationMs = Date.now() - startTime;
    const dna = verdict.sessionDna;
    const behaviorsDetected = dna.behaviors || [];

    const missingBehaviors = scenario.expected.mustHaveBehaviors.filter(
      (b: string) => !behaviorsDetected.includes(b as BehaviorType)
    );
    const unexpectedBehaviors = behaviorsDetected.filter(
      (b: BehaviorType) => scenario.expected.mustNotHaveBehaviors.includes(b)
    );

    const riskLevelMatch = verdict.overallRisk.level === scenario.expected.riskLevel;
    const riskScoreInRange = verdict.overallRisk.score >= scenario.expected.riskScoreMin
      && verdict.overallRisk.score <= scenario.expected.riskScoreMax;
    const confidenceMet = dna.confidence >= scenario.expected.confidenceMin;
    const coverageMet = dna.coverageScore >= scenario.expected.coverageMin;
    const allRequiredBehaviors = missingBehaviors.length === 0;
    const noForbiddenBehaviors = unexpectedBehaviors.length === 0;

    const passed = riskLevelMatch && riskScoreInRange
      && allRequiredBehaviors && noForbiddenBehaviors;

    canarySystem.cleanup();
    this.pipeline.reset();

    return {
      scenarioId: scenario.id,
      scenarioName: scenario.name,
      passed,
      riskLevel: verdict.overallRisk.level,
      riskScore: verdict.overallRisk.score,
      confidenceScore: dna.confidence,
      coverageScore: dna.coverageScore,
      behaviorsDetected,
      expectedBehaviors: scenario.expected.mustHaveBehaviors,
      missingBehaviors: missingBehaviors.map(b => b as string),
      unexpectedBehaviors: unexpectedBehaviors.map(b => b as string),
      errors,
      durationMs,
      timestamp: new Date(),
      details: {
        riskLevelMatch, riskScoreInRange, confidenceMet, coverageMet,
        allRequiredBehaviors, noForbiddenBehaviors,
      },
    };
  }

  runCampaign(
    scenarios: ValidationScenario[],
    config?: CampaignConfig
  ): CampaignReport {
    const startTime = Date.now();
    const results: CampaignResult[] = [];
    let passed = 0;
    let failed = 0;
    let totalRiskScore = 0;
    let totalConfidence = 0;
    let totalCoverage = 0;

    for (const scenario of scenarios) {
      const result = this.runScenario(scenario);
      results.push(result);
      if (result.passed) passed++;
      else failed++;
      totalRiskScore += result.riskScore;
      totalConfidence += result.confidenceScore;
      totalCoverage += result.coverageScore;
    }

    const n = results.length || 1;
    const topFailures = results
      .filter(r => !r.passed)
      .slice(0, 10)
      .map(r => ({
        scenarioId: r.scenarioId,
        scenarioName: r.scenarioName,
        missingBehaviors: r.missingBehaviors,
        unexpectedBehaviors: r.unexpectedBehaviors,
      }));

    return {
      campaignId: config?.id || generateId(),
      name: config?.name || 'ad-hoc',
      totalScenarios: scenarios.length,
      passed,
      failed,
      passRate: Math.round((passed / n) * 1000) / 10,
      avgRiskScore: Math.round(totalRiskScore / n),
      avgConfidence: Math.round((totalConfidence / n) * 100) / 100,
      avgCoverage: Math.round((totalCoverage / n) * 100) / 100,
      results,
      topFailures,
      timestamp: new Date(),
      durationMs: Date.now() - startTime,
    };
  }
}
