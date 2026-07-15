"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.runSandbox = runSandbox;
const node_vm_1 = __importDefault(require("node:vm"));
const node_module_1 = require("node:module");
const node_path_1 = __importDefault(require("node:path"));
const _require = (0, node_module_1.createRequire)(typeof __filename !== 'undefined' ? __filename : node_path_1.default.resolve('.'));
const _process = typeof process !== 'undefined' ? process : { env: {}, argv: [], exit() { } };
function createFSProxy(findings) {
    const fs = _require('fs');
    return new Proxy(fs, {
        get(target, prop) {
            if (prop === 'writeFileSync' || prop === 'writeFile' || prop === 'appendFile') {
                findings.push({ type: 'FILE_WRITE', detail: `fs.${String(prop)} called`, riskScore: 60 });
                return (...args) => { };
            }
            return target[prop];
        },
    });
}
function createChildProcessProxy(findings) {
    const cp = _require('child_process');
    return new Proxy(cp, {
        get(target, prop) {
            if (prop === 'exec' || prop === 'execSync' || prop === 'spawn') {
                findings.push({ type: 'COMMAND_EXEC', detail: `child_process.${String(prop)} called`, riskScore: 70 });
                return (...args) => { };
            }
            return target[prop];
        },
    });
}
function createHttpProxy(moduleName, findings) {
    const mod = _require(moduleName);
    return new Proxy(mod, {
        get(target, prop) {
            if (prop === 'get' || prop === 'request') {
                findings.push({ type: 'NETWORK_CALL', detail: `${moduleName}.${String(prop)} called`, riskScore: 30 });
                return (...args) => { };
            }
            return target[prop];
        },
    });
}
function runSandbox(code, timeoutMs = 3000) {
    const startTime = Date.now();
    const findings = [];
    const sandbox = {
        console: { log() { }, error() { }, warn() { } },
        Buffer,
        process: new Proxy({}, {
            get(target, prop) {
                if (prop === 'env') {
                    findings.push({ type: 'ENV_ACCESS', detail: 'process.env accessed', riskScore: 40 });
                    return new Proxy({}, {
                        get(_t, key) {
                            if (typeof key === 'string') {
                                findings.push({ type: 'ENV_ACCESS', detail: `process.env.${key} accessed`, riskScore: 50 });
                            }
                            return undefined;
                        },
                    });
                }
                return target[prop];
            },
        }),
        eval: (code) => {
            findings.push({ type: 'EVAL_USAGE', detail: 'eval() called', riskScore: 70 });
            return undefined;
        },
        fetch: (url) => {
            findings.push({ type: 'NETWORK_CALL', detail: `fetch(${url})`, riskScore: 30 });
            return Promise.resolve({ ok: true, status: 200 });
        },
        require: (mod) => {
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
    const context = node_vm_1.default.createContext(sandbox);
    const script = new node_vm_1.default.Script(code);
    try {
        script.runInContext(context, { timeout: timeoutMs });
    }
    catch (err) {
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
    const risk = maxRisk >= 70 ? 'MALICIOUS' : 'SUSPICIOUS';
    return {
        safe: false,
        risk,
        findings,
        executionTimeMs: elapsed,
    };
}
