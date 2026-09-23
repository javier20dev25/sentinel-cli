import * as os from 'os';
import * as path from 'path';
import * as fs from 'fs';

/** Persisted toggle: when enabled, code scans route through the Sentinel Cloud
 * full engine (each full-engine API call consumes a "pulso" of the
 * subscription). Local-only scans are unaffected. */

export const PULSE_MODE_CONFIG_PATH = path.join(os.homedir(), '.sentinel', 'pulse-mode.json');

export interface PulseModeConfig {
    enabled: boolean;
    updatedAt: string;
}

interface LoadOptions {
    configPath?: string;
}

export function getPulseModePath(opts?: LoadOptions): string {
    return opts?.configPath ?? PULSE_MODE_CONFIG_PATH;
}

export function loadPulseMode(opts?: LoadOptions): PulseModeConfig {
    const configPath = getPulseModePath(opts);
    try {
        const raw = fs.readFileSync(configPath, 'utf8');
        const parsed = JSON.parse(raw) as { enabled?: unknown; updatedAt?: unknown };
        return {
            enabled: parsed.enabled === true,
            updatedAt: typeof parsed.updatedAt === 'string' ? parsed.updatedAt : new Date(0).toISOString(),
        };
    } catch {
        return { enabled: false, updatedAt: new Date(0).toISOString() };
    }
}

export function isPulseModeEnabled(opts?: LoadOptions): boolean {
    return loadPulseMode(opts).enabled;
}

export function savePulseMode(enabled: boolean, opts?: LoadOptions): PulseModeConfig {
    const configPath = getPulseModePath(opts);
    const config: PulseModeConfig = { enabled: enabled === true, updatedAt: new Date().toISOString() };
    fs.mkdirSync(path.dirname(configPath), { recursive: true });
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n', { mode: 0o600 });
    return config;
}