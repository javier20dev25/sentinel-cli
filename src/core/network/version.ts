'use strict';

// Detection Engine v1.0 — frozen.
// Any future change must demonstrate improvement against
// corpus + blind corpus + replay, without regression.
export const ENGINE_VERSION = '1.0.0';
export const POLICY_VERSION = '1.0.0';
export const CORPUS_VERSION = '1.0.0';

export const VERSION_MANIFEST = {
  engine: {
    version: ENGINE_VERSION,
    description: 'Network audit detection pipeline: behavior-engine, risk-engine, anti-evasion-engine, campaign-runner',
    frozen: true,
    frozenAt: '2026-07-16',
    files: [
      'src/core/network/pipeline.ts',
      'src/core/network/behavior-engine.ts',
      'src/core/network/risk-engine.ts',
      'src/core/network/anti-evasion-engine.ts',
      'src/core/network/campaign-runner.ts',
      'src/core/network/evidence-builder.ts',
      'src/core/network/evidence-chain.ts',
      'src/core/network/session-dna.ts',
      'src/core/network/canary-system.ts',
      'src/core/network/providers.ts',
    ],
  },
  policy: {
    version: POLICY_VERSION,
    description: 'Classification Policy — behavior weights, risk thresholds, inference rules, gold rules',
    frozen: true,
    frozenAt: '2026-07-16',
    files: [
      'CLASSIFICATION_POLICY.md',
    ],
  },
  corpus: {
    version: CORPUS_VERSION,
    description: '39 calibrated scenarios + 43 blind validation scenarios (3 campaigns)',
    frozen: true,
    frozenAt: '2026-07-16',
    files: [
      'src/core/network/scenarios.ts',
      'src/core/network/blind-validation.ts',
      'src/core/network/blind-validation-2.ts',
      'src/core/network/blind-validation-3.ts',
    ],
  },
  replay: {
    version: '1.0.0',
    description: 'Replay framework for real session capture and pipeline replay',
    frozen: false,
    files: [
      'src/core/network/replay-engine.ts',
      'src/core/network/recorder.ts',
      'src/core/network/replay-campaign.ts',
    ],
  },
};
