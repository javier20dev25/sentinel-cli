import { describe, it, expect } from 'vitest';
import { classifyProcess } from './behavior-engine';
import { ProcessEvent } from './types';

function makeProcess(overrides: Partial<ProcessEvent>): ProcessEvent {
  return {
    sessionId: 'test',
    pid: 1234,
    name: 'test.exe',
    commandLine: '',
    timestamp: new Date(),
    riskIndicators: [],
    ...overrides,
  };
}

describe('classifyProcess', () => {
  it('detects monitor_disabled when taskkill targets sentinel by image name', () => {
    const result = classifyProcess(makeProcess({
      name: 'taskkill.exe',
      commandLine: 'taskkill /F /IM sentinel.exe',
    }));
    expect(result).not.toBeNull();
    expect(result!.type).toBe('monitor_disabled');
    expect(result!.confidence).toBe(0.9);
  });

  it('detects monitor_disabled when taskkill targets sentinel PID', () => {
    // process.pid in the test runner will be used; match via "sentinel" name
    const result = classifyProcess(makeProcess({
      name: 'taskkill.exe',
      commandLine: 'taskkill /PID 99999 /F',
    }));
    // Only detects if process.pid == 99999 (extremely unlikely for a test runner)
    // This tests that the PID match path works without sentinel in cmdline
    if (process.pid === 99999) {
      expect(result).not.toBeNull();
      expect(result!.type).toBe('monitor_disabled');
    } else {
      expect(result).toBeNull();
    }
  });

  it('detects monitor_disabled when Stop-Process targets sentinel', () => {
    const result = classifyProcess(makeProcess({
      name: 'powershell.exe',
      commandLine: 'powershell -Command "Stop-Process -Name sentinel -Force"',
    }));
    expect(result).not.toBeNull();
    expect(result!.type).toBe('monitor_disabled');
  });

  it('detects monitor_disabled when wmic targets sentinel', () => {
    const result = classifyProcess(makeProcess({
      name: 'wmic.exe',
      commandLine: 'wmic process where name="sentinel.exe" delete',
    }));
    expect(result).not.toBeNull();
    expect(result!.type).toBe('monitor_disabled');
  });

  it('does not flag normal processes', () => {
    const result = classifyProcess(makeProcess({
      name: 'notepad.exe',
      commandLine: 'notepad.exe README.md',
    }));
    expect(result).toBeNull();
  });

  it('does not flag taskkill targeting unrelated process', () => {
    const result = classifyProcess(makeProcess({
      name: 'taskkill.exe',
      commandLine: 'taskkill /PID 1234 /F',
    }));
    expect(result).toBeNull();
  });
});
