import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { CanarySystem, resolveCanaryRoot } from './canary-system';
import type { CanaryConfig } from './types';

const TEST_WORKSPACE = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-canary-test-'));

const config: CanaryConfig = {
  enabled: true,
  decoyFiles: [],
  fakeSecrets: true,
  contaminatedGitHistory: true,
  autoDeploy: false,
};

function cleanWorkspace(): void {
  if (fs.existsSync(TEST_WORKSPACE)) fs.rmSync(TEST_WORKSPACE, { recursive: true, force: true });
  fs.mkdirSync(TEST_WORKSPACE, { recursive: true });
}

describe('canary-system root resolution', () => {
  beforeEach(cleanWorkspace);
  afterEach(() => {
    cleanWorkspace();
  });

  it('uses the workspace .sentinel/canaries for writable normal directories', () => {
    const resolved = resolveCanaryRoot(TEST_WORKSPACE);
    expect(resolved.fallback).toBe(false);
    expect(resolved.root).toBe(path.join(TEST_WORKSPACE, '.sentinel', 'canaries'));
  });

  it('falls back to ~/.sentinel/canaries when the workspace is a system directory', () => {
    const resolved = resolveCanaryRoot('C:\\Windows\\system32');
    expect(resolved.fallback).toBe(true);
    expect(resolved.root).toBe(path.join(os.homedir(), '.sentinel', 'canaries'));
  });

  it('falls back when the workspace is a drive root', () => {
    const resolved = resolveCanaryRoot('C:\\');
    expect(resolved.fallback).toBe(true);
  });

  it('deployCanaries never throws on a system directory and reports the fallback', () => {
    const system = new CanarySystem(config);
    expect(() => system.deployCanaries('C:\\Windows\\system32')).not.toThrow();
    const info = system.getDeployedRootInfo();
    expect(info).not.toBeNull();
    expect(info!.fallback).toBe(true);
  });

  it('deploys into the workspace for a normal (writable) directory', () => {
    const canary = new CanarySystem(config);
    canary.deployCanaries(TEST_WORKSPACE);
    const info = canary.getDeployedRootInfo();
    expect(info).not.toBeNull();
    expect(info!.fallback).toBe(false);
    expect(fs.existsSync(path.join(TEST_WORKSPACE, '.sentinel', 'canaries'))).toBe(true);
    expect(canary.getDeployedCount()).toBeGreaterThan(0);
  });
});