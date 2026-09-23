import { loadSession } from './cloud_client';
import { isPulseModeEnabled } from './pulse_mode';
import { runRemoteScan, type RemoteScanCommandOptions, type RemoteScanRunContext, type RemoteScanRunResult, type RemoteScanOutputLine } from './remote-scan';

/**
 * `pulse-scan`: run a full-engine Sentinel Cloud scan (a "pulso"). Only runs
 * when pulse mode is enabled in ~/.sentinel/pulse-mode.json and the session
 * has the remote_scan capability. Otherwise it explains what is missing.
 */

export async function runPulseScan(
    options: RemoteScanCommandOptions & { pulseModePath?: string },
    ctx: RemoteScanRunContext & { pulseConfigPath?: string } = {}
): Promise<RemoteScanRunResult> {
    const lines: RemoteScanOutputLine[] = [];
    const out = (text: string): void => {
        lines.push({ stream: 'stdout', text });
    };
    const errOut = (text: string): void => {
        lines.push({ stream: 'stderr', text });
    };
    const fail = (message: string, exitCode: number): RemoteScanRunResult => {
        if (options.json) {
            out(JSON.stringify({ error: message }));
        } else if (exitCode !== 0) {
            errOut(message);
        } else {
            out(message);
        }
        return { exitCode, lines };
    };

    const enabled = isPulseModeEnabled({ configPath: ctx.pulseConfigPath });
    if (!enabled) {
        return fail(
            "Pulse mode is OFF. Enable it with 'sentinel pulse on' to run full-engine scans that consume subscription pulses.",
            1,
        );
    }

    const session = loadSession({ sessionDir: ctx.sessionDir });
    if (!session) {
        return fail(
            "Pulse mode is ON but there is no Cloud session. Run 'sentinel login' with a consumer API token first.",
            1,
        );
    }
    if (session.planActive === false) {
        return fail('No active subscription. Choose a plan to continue.', 1);
    }
    if (session.capabilities?.remote_scan !== true) {
        return fail(
            "Pulse mode is ON but your plan does not include the remote full engine (remote_scan capability).",
            1,
        );
    }

    return runRemoteScan({ ...options, pulse: true }, ctx);
}