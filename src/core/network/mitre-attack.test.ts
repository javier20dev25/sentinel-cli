import { describe, it, expect } from 'vitest';
import {
  getMitreMapping,
  getBehaviorStage,
  buildMitreMappings,
  buildBehaviorTimeline,
} from './mitre-attack';

describe('mitre-attack', () => {
  it('maps git_bundle_uploaded to Exfiltration/T1041', () => {
    const mapping = getMitreMapping('git_bundle_uploaded');
    expect(mapping.techniqueId).toBe('T1041');
    expect(mapping.tactic).toBe('Exfiltration');
  });

  it('maps preparation_detected to Reconnaissance/T1590', () => {
    const mapping = getMitreMapping('preparation_detected');
    expect(mapping.techniqueId).toBe('T1590');
    expect(mapping.tactic).toBe('Reconnaissance');
  });

  it('maps monitor_disabled to Defense Evasion/T1562', () => {
    const mapping = getMitreMapping('monitor_disabled');
    expect(mapping.techniqueId).toBe('T1562');
    expect(mapping.tactic).toBe('Defense Evasion');
  });

  it('maps unknown behavior to default', () => {
    const mapping = getMitreMapping('repo_indexed' as any);
    expect(mapping).toBeTruthy();
  });

  it('buildMitreMappings deduplicates same technique', () => {
    const mappings = buildMitreMappings(['git_history_read', 'git_objects_read']);
    // Both map to T1213/Collection — should deduplicate
    const t1213 = mappings.filter(m => m.techniqueId === 'T1213');
    expect(t1213).toHaveLength(1);
  });

  describe('getBehaviorStage', () => {
    it('classifies preparation_detected as Preparation', () => {
      expect(getBehaviorStage('preparation_detected')).toBe('Preparation');
    });

    it('classifies git_bundle_created as Packaging', () => {
      expect(getBehaviorStage('git_bundle_created')).toBe('Packaging');
    });

    it('classifies code_upload as Exfiltration', () => {
      expect(getBehaviorStage('code_upload')).toBe('Exfiltration');
    });

    it('classifies mass_file_read as Collection', () => {
      expect(getBehaviorStage('mass_file_read')).toBe('Collection');
    });
  });

  describe('buildBehaviorTimeline', () => {
    it('returns stages in correct order', () => {
      const timeline = buildBehaviorTimeline([
        { type: 'code_upload', timestamp: new Date('2024-01-01T00:00:03Z'), evidence: ['upload'] },
        { type: 'git_bundle_created', timestamp: new Date('2024-01-01T00:00:02Z'), evidence: ['bundle'] },
        { type: 'preparation_detected', timestamp: new Date('2024-01-01T00:00:01Z'), evidence: ['whoami'] },
      ]);
      expect(timeline.map(t => t.stage)).toEqual(['Preparation', 'Packaging', 'Exfiltration']);
    });

    it('deduplicates behaviors within same stage', () => {
      const timeline = buildBehaviorTimeline([
        { type: 'code_upload', timestamp: new Date('2024-01-01T00:00:02Z'), evidence: ['upload'] },
        { type: 'git_bundle_uploaded', timestamp: new Date('2024-01-01T00:00:03Z'), evidence: ['bundle upload'] },
      ]);
      const exfilStage = timeline.find(t => t.stage === 'Exfiltration');
      expect(exfilStage).toBeDefined();
      expect(exfilStage!.behaviors).toContain('code_upload');
      expect(exfilStage!.behaviors).toContain('git_bundle_uploaded');
    });
  });
});
