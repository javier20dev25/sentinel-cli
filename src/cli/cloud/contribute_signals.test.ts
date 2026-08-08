import { describe, it, expect } from 'vitest';
import { CONTRIBUTE_SIGNALS, findingsToSignals } from './contribute_signals';
import { extractIdentity } from './contribute';
import type { LiteFinding } from '../../core/lite/lite_scanner';

function finding(
    type: string,
    overrides: Partial<LiteFinding> = {}
): LiteFinding {
    return {
        type,
        intent: 'SUSPICIOUS',
        file: 'package.json',
        line: 1,
        severity: 'HIGH',
        description: 'fixture finding',
        snippet: 'fixture',
        ...overrides,
    };
}

describe('findingsToSignals', () => {
    it('exposes the closed N3.2 signal enum in contract order', () => {
        expect(CONTRIBUTE_SIGNALS).toEqual([
            'install_script',
            'network',
            'credential_access',
            'child_process',
            'runtime_execution',
            'obfuscation',
            'encoded_payload',
            'filesystem',
            'binary',
            'download',
            'config_tampering',
            'suspicious_url',
        ]);
    });

    it('produces install_script for lifecycle scripts', () => {
        expect(
            findingsToSignals([
                finding('LIFECYCLE_CURL_BASH', { subcode: 'LIF-CURL-BASH' }),
            ])
        ).toContain('install_script');
        expect(
            findingsToSignals([
                finding('LIFECYCLE_CURL_BASH', { subcode: 'LIF-SHELL' }),
            ])
        ).toContain('install_script');
        expect(findingsToSignals([finding('LIFECYCLE_OBFUSCATED')])).toContain('install_script');
    });

    it('produces network for network activity', () => {
        expect(findingsToSignals([finding('NETWORK_ACTIVITY')])).toContain('network');
    });

    it('produces credential_access for secrets, env access and token risk', () => {
        for (const type of [
            'SECRET_GITHUB_TOKEN',
            'SECRET_AWS_KEY_ID',
            'SECRET_DB_PASSWORD',
            'SECRET_HARDCODED_TOKEN',
            'SECRET_ENV_FILE',
            'SECRET_CREDENTIALS_FILE',
            'SECRET_SSH_KEY_FILE',
            'ENV_ACCESS',
            'TOKEN_RISK',
        ]) {
            expect(findingsToSignals([finding(type)])).toContain('credential_access');
        }
    });

    it('produces child_process for OS process spawning', () => {
        expect(findingsToSignals([finding('OS_CAPABILITY')])).toContain('child_process');
    });

    it('produces runtime_execution for dynamic/sandbox/gyp execution', () => {
        for (const type of ['UNSAFE_EVAL', 'SANDBOX_ESCAPE', 'GYP_COMMAND_SUBSTITUTION']) {
            expect(findingsToSignals([finding(type)])).toContain('runtime_execution');
        }
    });

    it('produces obfuscation for obfuscated payloads and high entropy', () => {
        for (const type of ['OBFUSCATED_PAYLOAD', 'HIGH_ENTROPY']) {
            expect(findingsToSignals([finding(type)])).toContain('obfuscation');
        }
    });

    it('produces encoded_payload for base64/decoded payloads', () => {
        expect(findingsToSignals([finding('POTENTIAL_SECRET')])).toContain('encoded_payload');
        expect(findingsToSignals([finding('LIFECYCLE_OBFUSCATED')])).toContain('encoded_payload');
    });

    it('produces filesystem for unrestricted file-write capability', () => {
        expect(
            findingsToSignals([finding('AGENT_RISK', { subcode: 'AS-002' })])
        ).toContain('filesystem');
    });

    it('produces binary for native build integration', () => {
        expect(findingsToSignals([finding('NODE_GYP_CAPABILITY')])).toContain('binary');
    });

    it('produces download for lifecycle/gyp/workflow download vectors', () => {
        expect(
            findingsToSignals([finding('LIFECYCLE_CURL_BASH', { subcode: 'LIF-CURL-BASH' })])
        ).toContain('download');
        expect(findingsToSignals([finding('GYP_DOWNLOADER')])).toContain('download');
        expect(
            findingsToSignals([finding('WORKFLOW_RISK', { subcode: 'WF-005' })])
        ).toContain('download');
    });

    it('produces config_tampering for workflow self-modification', () => {
        expect(
            findingsToSignals([finding('WORKFLOW_RISK', { subcode: 'WF-004' })])
        ).toContain('config_tampering');
    });

    it('produces suspicious_url for darknet addresses', () => {
        expect(findingsToSignals([finding('DARKNET_ADDRESS')])).toContain('suspicious_url');
    });

    it('maps each closed enum value from at least one finding kind', () => {
        const every = new Set<string>();
        for (const signal of CONTRIBUTE_SIGNALS) {
            expect(signal).toBeTypeOf('string');
            every.add(signal);
        }
        const produced = findingsToSignals([
            finding('LIFECYCLE_CURL_BASH', { subcode: 'LIF-CURL-BASH' }),
            finding('LIFECYCLE_OBFUSCATED'),
            finding('NETWORK_ACTIVITY'),
            finding('SECRET_GITHUB_TOKEN'),
            finding('OS_CAPABILITY'),
            finding('UNSAFE_EVAL'),
            finding('OBFUSCATED_PAYLOAD'),
            finding('POTENTIAL_SECRET'),
            finding('AGENT_RISK', { subcode: 'AS-002' }),
            finding('NODE_GYP_CAPABILITY'),
            finding('GYP_DOWNLOADER'),
            finding('WORKFLOW_RISK', { subcode: 'WF-004' }),
            finding('DARKNET_ADDRESS'),
        ]);
        expect(new Set(produced)).toEqual(every);
    });

    it('deduplicates signals across multiple findings', () => {
        const signals = findingsToSignals([
            finding('SECRET_GITHUB_TOKEN'),
            finding('ENV_ACCESS'),
            finding('TOKEN_RISK'),
            finding('SECRET_AWS_KEY_ID'),
        ]);
        expect(new Set(signals).size).toBe(signals.length);
        expect(signals).toEqual(['credential_access']);
    });

    it('keeps a stable enum-defined order regardless of finding order', () => {
        const first = findingsToSignals([
            finding('DARKNET_ADDRESS'),
            finding('LIFECYCLE_CURL_BASH', { subcode: 'LIF-CURL-BASH' }),
            finding('NETWORK_ACTIVITY'),
        ]);
        const second = findingsToSignals([
            finding('NETWORK_ACTIVITY'),
            finding('DARKNET_ADDRESS'),
            finding('LIFECYCLE_CURL_BASH', { subcode: 'LIF-CURL-BASH' }),
        ]);
        expect(first).toEqual(second);
        expect(first).toEqual(['install_script', 'network', 'download', 'suspicious_url']);
    });

    it('caps the signal list at the contract maximum of 32', () => {
        const signals = findingsToSignals([finding('SECRET_GITHUB_TOKEN')]);
        expect(signals.length).toBeLessThanOrEqual(32);
    });

    it('distinguishes LIF-SHELL (shell exec) from LIF-CURL-BASH (download+exec)', () => {
        expect(
            findingsToSignals([finding('LIFECYCLE_CURL_BASH', { subcode: 'LIF-SHELL' })])
        ).toEqual(['install_script']);
        expect(
            findingsToSignals([finding('LIFECYCLE_CURL_BASH', { subcode: 'LIF-CURL-BASH' })])
        ).toEqual(['install_script', 'download']);
    });

    it('omits ambiguous finding kinds instead of forcing a signal', () => {
        const ambiguous = [
            finding('DOM_INJECTION'),
            finding('WORKFLOW_RISK', { subcode: 'WF-001' }),
            finding('WORKFLOW_RISK', { subcode: 'WF-002' }),
            finding('WORKFLOW_RISK', { subcode: 'WF-006' }),
            finding('WORKFLOW_RISK', { subcode: 'WF-007' }),
            finding('WORKFLOW_RISK', { subcode: 'WF-INFO' }),
            finding('AGENT_RISK', { subcode: 'AS-001' }),
            finding('AGENT_RISK', { subcode: 'AS-003' }),
            finding('AGENT_RISK', { subcode: 'AS-008' }),
            finding('AGENT_RISK', { subcode: 'AS-INFO' }),
            finding('BINDING_GYP'),
            finding('SIZE_ANOMALY'),
            finding('UNKNOWN_FINDING_TYPE'),
        ];
        expect(findingsToSignals(ambiguous)).toEqual([]);
    });

    it('returns an empty array for no findings or empty input', () => {
        expect(findingsToSignals([])).toEqual([]);
    });
});

describe('extractIdentity', () => {
    it('extracts ecosystem/package/version from a manifest', () => {
        expect(extractIdentity('{"name":"evil-pkg","version":"1.2.3"}')).toEqual({
            ecosystem: 'npm',
            package: 'evil-pkg',
            version: '1.2.3',
        });
    });

    it('omits version when absent but keeps the identity', () => {
        expect(extractIdentity('{"name":"pkg"}')).toEqual({
            ecosystem: 'npm',
            package: 'pkg',
        });
    });

    it('omits the whole identity when name is missing', () => {
        expect(extractIdentity('{"version":"1.0.0"}')).toBeUndefined();
        expect(extractIdentity('{}')).toBeUndefined();
    });

    it('omits the identity when name is not a non-empty string', () => {
        expect(extractIdentity('{"name":123}')).toBeUndefined();
        expect(extractIdentity('{"name":{}}')).toBeUndefined();
        expect(extractIdentity('{"name":null}')).toBeUndefined();
        expect(extractIdentity('{"name":""}')).toBeUndefined();
        expect(extractIdentity('{"name":"   "}')).toBeUndefined();
    });

    it('trims surrounding whitespace from name and version', () => {
        expect(extractIdentity('{"name":"  spaced-pkg  ","version":" 1.0.0 "}')).toEqual({
            ecosystem: 'npm',
            package: 'spaced-pkg',
            version: '1.0.0',
        });
    });

    it('preserves package name casing', () => {
        expect(extractIdentity('{"name":"Evil-Pkg"}')).toEqual({
            ecosystem: 'npm',
            package: 'Evil-Pkg',
        });
    });

    it('caps the package name at 128 characters', () => {
        const long = 'p'.repeat(200);
        const identity = extractIdentity(`{"name":"${long}"}`);
        expect(identity).toBeDefined();
        expect(identity!.package.length).toBe(128);
        expect(identity!.package).toBe('p'.repeat(128));
    });

    it('omits version when it is not a string', () => {
        expect(extractIdentity('{"name":"pkg","version":1.2}')).toEqual({
            ecosystem: 'npm',
            package: 'pkg',
        });
        expect(extractIdentity('{"name":"pkg","version":null}')).toEqual({
            ecosystem: 'npm',
            package: 'pkg',
        });
    });

    it('returns undefined for invalid JSON or non-object manifests', () => {
        expect(extractIdentity('not json')).toBeUndefined();
        expect(extractIdentity('[]')).toBeUndefined();
        expect(extractIdentity('"a string"')).toBeUndefined();
        expect(extractIdentity('42')).toBeUndefined();
        expect(extractIdentity('null')).toBeUndefined();
    });
});
