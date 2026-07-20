import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as path from 'path';
import * as os from 'os';

const mockExistsSync = vi.hoisted(() => vi.fn());
const mockMkdirSync = vi.hoisted(() => vi.fn());
const mockReadFileSync = vi.hoisted(() => vi.fn());
const mockWriteFileSync = vi.hoisted(() => vi.fn());
const mockHomedir = vi.hoisted(() => vi.fn(() => '/home/testuser'));

vi.mock('fs', () => ({
  existsSync: mockExistsSync,
  mkdirSync: mockMkdirSync,
  readFileSync: mockReadFileSync,
  writeFileSync: mockWriteFileSync,
}));

vi.mock('os', () => ({
  homedir: mockHomedir,
}));

describe('network-config', () => {
  let config: typeof import('./network-config');

  beforeEach(async () => {
    vi.clearAllMocks();
    mockExistsSync.mockReturnValue(false);
    config = await import('./network-config');
  });

  afterEach(() => {
    vi.resetModules();
  });

  it('returns default config when no file exists', () => {
    const cfg = config.loadConfig();
    expect(cfg.autoStart).toBe(false);
    expect(cfg.alertThreshold).toBe('MEDIUM');
    expect(cfg.trustedHosts).toEqual([]);
    expect(cfg.trustedProcesses).toEqual([]);
    expect(cfg.performanceBudget.maxCpuPercent).toBe(5);
    expect(cfg.performanceBudget.maxMemoryMb).toBe(128);
  });

  it('loads config from file when it exists', () => {
    const saved = JSON.stringify({ autoStart: true, alertThreshold: 'HIGH' });
    mockExistsSync.mockReturnValue(true);
    mockReadFileSync.mockReturnValue(saved);
    const cfg = config.loadConfig();
    expect(cfg.autoStart).toBe(true);
    expect(cfg.alertThreshold).toBe('HIGH');
    expect(cfg.performanceBudget.maxCpuPercent).toBe(5);
  });

  it('saves config to correct path', () => {
    const cfg = config.getDefaultConfig();
    config.saveConfig(cfg);
    const expectedDir = path.join('/home/testuser', '.sentinel');
    const expectedFile = path.join(expectedDir, 'network-config.json');
    expect(mockMkdirSync).toHaveBeenCalledWith(expectedDir, { recursive: true });
    expect(mockWriteFileSync).toHaveBeenCalledWith(
      expectedFile,
      expect.stringContaining('"autoStart": false'),
      'utf-8',
    );
  });

  it('returns correct config path', () => {
    const p = config.getConfigPath();
    expect(p).toBe(path.join('/home/testuser', '.sentinel', 'network-config.json'));
  });
});
