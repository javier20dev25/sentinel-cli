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
    const result = classifyProcess(makeProcess({
      name: 'taskkill.exe',
      commandLine: `taskkill /PID ${process.pid} /F`,
    }));
    expect(result).not.toBeNull();
    expect(result!.type).toBe('monitor_disabled');
  });

  it('detects monitor_disabled when Stop-Process targets sentinel by name', () => {
    const result = classifyProcess(makeProcess({
      name: 'powershell.exe',
      commandLine: 'powershell -Command "Stop-Process -Name sentinel -Force"',
    }));
    expect(result).not.toBeNull();
    expect(result!.type).toBe('monitor_disabled');
  });

  it('detects monitor_disabled when Stop-Process targets sentinel PID', () => {
    const result = classifyProcess(makeProcess({
      name: 'powershell.exe',
      commandLine: `powershell -Command "Stop-Process -Id ${process.pid} -Force"`,
    }));
    expect(result).not.toBeNull();
    expect(result!.type).toBe('monitor_disabled');
  });

  it('detects monitor_disabled when wmic targets sentinel by name', () => {
    const result = classifyProcess(makeProcess({
      name: 'wmic.exe',
      commandLine: 'wmic process where name="sentinel.exe" delete',
    }));
    expect(result).not.toBeNull();
    expect(result!.type).toBe('monitor_disabled');
  });

  it('detects monitor_disabled when wmic targets sentinel PID', () => {
    const result = classifyProcess(makeProcess({
      name: 'wmic.exe',
      commandLine: `wmic process where ProcessId=${process.pid} delete`,
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

  it('does not flag taskkill targeting unrelated PID', () => {
    const result = classifyProcess(makeProcess({
      name: 'taskkill.exe',
      commandLine: 'taskkill /PID 99999 /F',
    }));
    expect(result).toBeNull();
  });

  it('does not flag Stop-Process targeting unrelated PID', () => {
    const result = classifyProcess(makeProcess({
      name: 'powershell.exe',
      commandLine: 'powershell -Command "Stop-Process -Id 99999 -Force"',
    }));
    expect(result).toBeNull();
  });

  it('does not flag wmic targeting unrelated PID', () => {
    const result = classifyProcess(makeProcess({
      name: 'wmic.exe',
      commandLine: 'wmic process where ProcessId=99999 delete',
    }));
    expect(result).toBeNull();
  });
});
