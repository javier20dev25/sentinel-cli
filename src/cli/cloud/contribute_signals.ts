import type { LiteFinding } from '../../core/lite/lite_scanner';

/**
 * N3.2 contribute contract — closed enum of dependency signals.
 * @public — exported for tests and consumers of the contribution payload.
 */
export const CONTRIBUTE_SIGNALS = [
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
] as const;

export type ContributeSignal = (typeof CONTRIBUTE_SIGNALS)[number];

const MAX_SIGNALS = 32;

/**
 * Signal mapping keyed by LiteScanner finding type. Conservative: only
 * clear-cut findings are mapped; ambiguous finding kinds are intentionally
 * omitted (a finding is never forced onto a signal it does not evidence).
 */
const TYPE_SIGNALS: Readonly<Record<string, ReadonlyArray<ContributeSignal>>> = {
    UNSAFE_EVAL: ['runtime_execution'],
    OS_CAPABILITY: ['child_process'],
    NETWORK_ACTIVITY: ['network'],
    ENV_ACCESS: ['credential_access'],
    POTENTIAL_SECRET: ['encoded_payload'],
    SANDBOX_ESCAPE: ['runtime_execution'],
    SECRET_AWS_KEY_ID: ['credential_access'],
    SECRET_AWS_SECRET: ['credential_access'],
    SECRET_GITHUB_TOKEN: ['credential_access'],
    SECRET_STRIPE_KEY: ['credential_access'],
    SECRET_SENDGRID_KEY: ['credential_access'],
    SECRET_SSH_KEY: ['credential_access'],
    SECRET_SLACK_TOKEN: ['credential_access'],
    SECRET_SLACK_WEBHOOK: ['credential_access'],
    SECRET_JWT: ['credential_access'],
    SECRET_DB_PASSWORD: ['credential_access'],
    SECRET_ENCRYPTION_KEY: ['credential_access'],
    SECRET_API_KEY: ['credential_access'],
    SECRET_HARDCODED_PASSWORD: ['credential_access'],
    SECRET_HARDCODED_TOKEN: ['credential_access'],
    DARKNET_ADDRESS: ['suspicious_url'],
    GYP_COMMAND_SUBSTITUTION: ['runtime_execution'],
    GYP_DOWNLOADER: ['download'],
    LIFECYCLE_OBFUSCATED: ['install_script', 'encoded_payload'],
    OBFUSCATED_PAYLOAD: ['obfuscation'],
    HIGH_ENTROPY: ['obfuscation'],
    NODE_GYP_CAPABILITY: ['binary'],
    SECRET_ENV_FILE: ['credential_access'],
    SECRET_CREDENTIALS_FILE: ['credential_access'],
    SECRET_SSH_KEY_FILE: ['credential_access'],
    TOKEN_RISK: ['credential_access'],
};

/**
 * Subcode-level refinements. LIFECYCLE_CURL_BASH fires for both "download+exec"
 * (LIF-CURL-BASH) and "invokes a shell" (LIF-SHELL); only the former also
 * evidences a download. WF-004/WF-005/AS-002 carry workflow/agent signals that
 * their bare type does not.
 */
const SUBCODE_SIGNALS: Readonly<Record<string, ReadonlyArray<ContributeSignal>>> = {
    'LIF-CURL-BASH': ['install_script', 'download'],
    'LIF-SHELL': ['install_script'],
    'WF-004': ['config_tampering'],
    'WF-005': ['download'],
    'AS-002': ['filesystem'],
};

/**
 * Maps LiteScanner findings onto the closed N3.2 signal enum. Deduplicated,
 * capped at MAX_SIGNALS, in a stable (enum-defined) order. Conservative:
 * findings that do not clearly evidence any signal are omitted.
 */
export function findingsToSignals(findings: LiteFinding[]): ContributeSignal[] {
    const seen = new Set<ContributeSignal>();
    for (const finding of findings) {
        const subcode = finding.subcode ?? '';
        const mapped = SUBCODE_SIGNALS[subcode] ?? TYPE_SIGNALS[finding.type];
        if (!mapped) continue;
        for (const signal of mapped) {
            seen.add(signal);
        }
        if (seen.size >= MAX_SIGNALS) break;
    }
    return CONTRIBUTE_SIGNALS.filter((signal) => seen.has(signal)).slice(0, MAX_SIGNALS);
}
