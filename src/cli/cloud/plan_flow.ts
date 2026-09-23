import * as readline from 'readline';
import { spawn } from 'child_process';
import { isLoopbackHost } from './cloud_client';

/**
 * Subscription gate UX. When the subject has no active plan the CLI must NOT
 * burn a pulso; instead it explains, waits for ENTER (interactive sessions)
 * and opens Sentinel Cloud's plan landing page.
 *
 * Security: the URL that is opened is only ever https:// (or http:// to a
 * loopback host, i.e. local development). The browser is launched with the OS
 * default handler through a NON-shell child (explorer/open/xdg-open) so a
 * hostile URL can never reach a shell parser.
 */

export type PlanOfferResult = 'opened' | 'shown';

export interface PlanFlowDeps {
    /** Opens the URL in the default browser. Tests inject a no-op. */
    open?: (url: string) => boolean;
    /** Resolves when the user presses ENTER. Tests inject an immediate no-op. */
    prompt?: (question: string) => Promise<void>;
    /** Forced TTY flag (tests). Defaults to process.stdin.isTTY. */
    isTTY?: boolean;
}

export function isSafePlanUrl(rawUrl: string): boolean {
    let parsed: URL;
    try {
        parsed = new URL(rawUrl);
    } catch {
        return false;
    }
    if (parsed.protocol === 'https:') return true;
    return parsed.protocol === 'http:' && isLoopbackHost(parsed.hostname);
}

/**
 * Prefers the server-advertised landingUrl when it is safe to open; otherwise
 * falls back to `<baseUrl>/#pricing`.
 */
export function resolvePlanLandingUrl(baseUrl: string, landingUrl?: string | null): string {
    if (landingUrl && isSafePlanUrl(landingUrl)) return landingUrl;
    return baseUrl.replace(/\/+$/, '') + '/#pricing';
}

/**
 * Opens a URL with the system's default browser handler. Uses a direct
 * non-shell spawn (explorer | open | xdg-open) so the URL never reaches a
 * shell; refuses to open anything that is not https or loopback http.
 * Returns true when the opener was launched.
 */
export function openBrowser(url: string): boolean {
    if (!isSafePlanUrl(url)) return false;
    try {
        const opener =
            process.platform === 'win32'
                ? { cmd: 'explorer.exe', args: [url] }
                : process.platform === 'darwin'
                    ? { cmd: 'open', args: [url] }
                    : { cmd: 'xdg-open', args: [url] };
        const child = spawn(opener.cmd, opener.args, { stdio: 'ignore', detached: true });
        child.on('error', () => {
            // opener missing/unavailable: the printed URL is the fallback
        });
        child.unref();
        return true;
    } catch {
        return false;
    }
}

export function defaultPrompt(question: string): Promise<void> {
    return new Promise((resolve) => {
        const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
        let settled = false;
        const done = (): void => {
            if (settled) return;
            settled = true;
            rl.close();
            resolve();
        };
        rl.question(question, done);
        rl.on('close', done);
    });
}

/**
 * No-active-subscription UX. In an interactive terminal it shows a message,
 * waits for ENTER and opens the plan landing page. In a non-interactive
 * session it never blocks and never spawns a browser; it prints the URL so
 * automated callers can still act on it. Returns 'opened' when a browser was
 * launched, 'shown' otherwise.
 */
export async function offerPlanLanding(
    url: string,
    deps?: PlanFlowDeps
): Promise<PlanOfferResult> {
    const open = deps?.open ?? openBrowser;
    const prompt = deps?.prompt ?? defaultPrompt;
    const isTTY = deps?.isTTY ?? Boolean(process.stdin.isTTY);
    if (!isTTY) {
        console.log(`Choose a plan at: ${url}`);
        return 'shown';
    }
    await prompt('Press ENTER to open the Sentinel Cloud plans page ');
    return open(url) ? 'opened' : 'shown';
}