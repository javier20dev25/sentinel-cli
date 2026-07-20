import vm from 'node:vm';
import { createRequire } from 'node:module';
import path from 'node:path';

const _require = createRequire(typeof __filename !== 'undefined' ? __filename : path.resolve('.'));
const _process = typeof process !== 'undefined' ? process : { env: {}, argv: [], exit() {} } as any;

export interface SandboxResult {
  safe: boolean;
  risk: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS';
  findings: { type: string; detail: string; riskScore: number }[];
  executionTimeMs: number;
  error?: string;
}

type Finding = { type: string; detail: string; riskScore: number };

function createFSProxy(findings: Finding[]): any {
  const fs = _require('fs');
  return new Proxy(fs, {
    get(target, prop) {
      if (prop === 'writeFileSync' || prop === 'writeFile' || prop === 'appendFile') {
        findings.push({ type: 'FILE_WRITE', detail: `fs.${String(prop)} called`, riskScore: 60 });
        return (...args: any[]) => {};
      }
      return (target as any)[prop];
    },
  });
}

function createChildProcessProxy(findings: Finding[]): any {
  const cp = _require('child_process');
  return new Proxy(cp, {
    get(target, prop) {
      if (prop === 'exec' || prop === 'execSync' || prop === 'spawn') {
        findings.push({ type: 'COMMAND_EXEC', detail: `child_process.${String(prop)} called`, riskScore: 70 });
        return (...args: any[]) => {};
      }
      return (target as any)[prop];
    },
  });
}

function createHttpProxy(moduleName: string, findings: Finding[]): any {
  const mod = _require(moduleName);
  return new Proxy(mod, {
    get(target, prop) {
      if (prop === 'get' || prop === 'request') {
        findings.push({ type: 'NETWORK_CALL', detail: `${moduleName}.${String(prop)} called`, riskScore: 30 });
        return (...args: any[]) => {};
      }
      return (target as any)[prop];
    },
  });
}

export function runSandbox(code: string, timeoutMs: number = 3000): SandboxResult {
  const startTime = Date.now();
  const findings: Finding[] = [];

  const sandbox: Record<string, any> = {
    console: { log() {}, error() {}, warn() {} },
    Buffer,
    process: new Proxy({} as Record<string, any>, {
      get(target, prop) {
        if (prop === 'env') {
          findings.push({ type: 'ENV_ACCESS', detail: 'process.env accessed', riskScore: 40 });
          return new Proxy({} as Record<string, any>, {
            get(_t, key) {
              if (typeof key === 'string') {
                findings.push({ type: 'ENV_ACCESS', detail: `process.env.${key} accessed`, riskScore: 50 });
              }
              return undefined;
            },
          });
        }
        return (target as any)[prop];
      },
    }),
    eval: (code: string) => {
      findings.push({ type: 'EVAL_USAGE', detail: 'eval() called', riskScore: 70 });
      return undefined;
    },
    fetch: (url: string) => {
      findings.push({ type: 'NETWORK_CALL', detail: `fetch(${url})`, riskScore: 30 });
      return Promise.resolve({ ok: true, status: 200 });
    },
    require: (mod: string) => {
      findings.push({ type: 'MODULE_ACCESS', detail: `require('${mod}')`, riskScore: 10 });
      switch (mod) {
        case 'fs': return createFSProxy(findings);
        case 'child_process': return createChildProcessProxy(findings);
        case 'http': return createHttpProxy('http', findings);
        case 'https': return createHttpProxy('https', findings);
        default: return _require(mod);
      }
    },
  };

  const context = vm.createContext(sandbox);
  const script = new vm.Script(code);

  try {
    script.runInContext(context, { timeout: timeoutMs });
  } catch (err: any) {
    const elapsed = Date.now() - startTime;
    if (err.code === 'ERR_SCRIPT_EXECUTION_TIMEOUT') {
      return {
        safe: false,
        risk: 'MALICIOUS',
        findings: [...findings, { type: 'TIMEOUT', detail: 'Execution timed out', riskScore: 90 }],
        executionTimeMs: elapsed,
        error: 'Execution timed out',
      };
    }
    return {
      safe: false,
      risk: 'MALICIOUS',
      findings,
      executionTimeMs: elapsed,
      error: err.message || String(err),
    };
  }

  const elapsed = Date.now() - startTime;

  if (findings.length === 0) {
    return { safe: true, risk: 'SAFE', findings: [], executionTimeMs: elapsed };
  }

  const maxRisk = Math.max(...findings.map(f => f.riskScore));
  const risk: 'SUSPICIOUS' | 'MALICIOUS' = maxRisk >= 70 ? 'MALICIOUS' : 'SUSPICIOUS';

  return {
    safe: false,
    risk,
    findings,
    executionTimeMs: elapsed,
  };
}
