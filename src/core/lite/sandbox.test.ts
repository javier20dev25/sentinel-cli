import { describe, it, expect } from 'vitest';
import { runSandbox } from './sandbox';

describe('runSandbox', () => {
  it('returns SAFE for benign code', () => {
    const result = runSandbox('const x = 1 + 2; const y = x * 3;');
    expect(result.risk).toBe('SAFE');
    expect(result.safe).toBe(true);
    expect(result.findings).toHaveLength(0);
    expect(result.error).toBeUndefined();
  });

  it('detects eval() usage as MALICIOUS', () => {
    const result = runSandbox('eval("1+1")');
    expect(result.risk).toBe('MALICIOUS');
    expect(result.safe).toBe(false);
    expect(result.findings.some(f => f.type === 'EVAL_USAGE')).toBe(true);
  });

  it('returns SUSPICIOUS when eval is lower risk', () => {
    const result = runSandbox('eval("1+1")');
    expect(result.findings.some(f => f.riskScore >= 70)).toBe(true);
  });

  it('tracks require("fs") module access', () => {
    const result = runSandbox('const fs = require("fs");');
    expect(result.findings.some(f =>
      f.type === 'MODULE_ACCESS' && f.detail.includes("'fs'")
    )).toBe(true);
    expect(result.risk).toBe('SUSPICIOUS');
  });

  it('tracks require("child_process") module access', () => {
    const result = runSandbox('const cp = require("child_process");');
    expect(result.findings.some(f =>
      f.type === 'MODULE_ACCESS' && f.detail.includes("'child_process'")
    )).toBe(true);
  });

  it('intercepts fs.writeFileSync calls', () => {
    const result = runSandbox('const fs = require("fs"); fs.writeFileSync("/tmp/test", "data");');
    expect(result.findings.some(f => f.type === 'FILE_WRITE')).toBe(true);
    expect(result.risk).toBe('SUSPICIOUS');
  });

  it('intercepts child_process.exec calls', () => {
    const result = runSandbox('const cp = require("child_process"); cp.exec("ls");');
    expect(result.findings.some(f => f.type === 'COMMAND_EXEC')).toBe(true);
    expect(result.risk).toBe('MALICIOUS');
  });

  it('intercepts process.env access', () => {
    const result = runSandbox('const x = process.env;');
    expect(result.findings.some(f => f.type === 'ENV_ACCESS')).toBe(true);
  });

  it('intercepts fetch calls', () => {
    const result = runSandbox('fetch("https://example.com");');
    expect(result.findings.some(f => f.type === 'NETWORK_CALL')).toBe(true);
  });

  it('returns MALICIOUS for infinite loop (timeout)', () => {
    const result = runSandbox('while(true) {}', 1000);
    expect(result.risk).toBe('MALICIOUS');
    expect(result.findings.some(f => f.type === 'TIMEOUT')).toBe(true);
    expect(result.error).toBe('Execution timed out');
  });

  it('captures executionTimeMs for safe code', () => {
    const result = runSandbox('const x = 1;');
    expect(result.executionTimeMs).toBeGreaterThanOrEqual(0);
    expect(result.risk).toBe('SAFE');
  });
});
