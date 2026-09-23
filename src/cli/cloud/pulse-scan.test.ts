import { describe, it, expect, vi, beforeEach } from 'vitest';
import { runPulseScan } from './pulse-scan';

const mocks = vi.hoisted(() => ({
    isPulseModeEnabled: vi.fn(),
    loadSession: vi.fn(),
    runRemoteScan: vi.fn(),
}));

vi.mock('./pulse_mode', () => ({
    isPulseModeEnabled: mocks.isPulseModeEnabled,
    loadPulseMode: () => ({ enabled: mocks.isPulseModeEnabled(), updatedAt: '' }),
    savePulseMode: () => {},
}));

vi.mock('./cloud_client', () => ({
    loadSession: mocks.loadSession,
}));

vi.mock('./remote-scan', () => ({
    runRemoteScan: mocks.runRemoteScan,
    resolveManifestPath: () => '/fake/package.json',
}));

const BASE_OPTS = { targetPath: '/fake' };

describe('pulse-scan', () => {
    beforeEach(() => {
        mocks.isPulseModeEnabled.mockReset();
        mocks.loadSession.mockReset();
        mocks.runRemoteScan.mockReset();
        mocks.loadSession.mockReturnValue(null);
    });

    it('refuses when pulse mode is OFF (exit 1 with guidance)', async () => {
        mocks.isPulseModeEnabled.mockReturnValue(false);
        const result = await runPulseScan(BASE_OPTS, {});
        expect(result.exitCode).toBe(1);
        expect(result.lines[0].stream).toBe('stderr');
        expect(result.lines[0].text).toContain('Pulse mode is OFF');
    });

    it('requires a Cloud session when mode is ON', async () => {
        mocks.isPulseModeEnabled.mockReturnValue(true);
        mocks.loadSession.mockReturnValue(null);
        const result = await runPulseScan(BASE_OPTS, {});
        expect(result.exitCode).toBe(1);
        expect(result.lines[0].text).toContain('no Cloud session');
    });

    it('requires remote_scan capability when mode is ON', async () => {
        mocks.isPulseModeEnabled.mockReturnValue(true);
        mocks.loadSession.mockReturnValue({ capabilities: { remote_scan: false } });
        const result = await runPulseScan(BASE_OPTS, {});
        expect(result.exitCode).toBe(1);
        expect(result.lines[0].text).toContain('remote_scan');
    });

    it('delegates to remote scan with pulse framing enabled', async () => {
        mocks.isPulseModeEnabled.mockReturnValue(true);
        mocks.loadSession.mockReturnValue({ capabilities: { remote_scan: true }, token: 'tok' });
        mocks.runRemoteScan.mockResolvedValue({ exitCode: 0, lines: [{ stream: 'stdout', text: 'ok' }] });
        const result = await runPulseScan(BASE_OPTS, {});
        expect(result.exitCode).toBe(0);
        expect(mocks.runRemoteScan).toHaveBeenCalledWith({ ...BASE_OPTS, pulse: true }, {});
    });

    it('JSON mode surfaces errors as JSON objects', async () => {
        mocks.isPulseModeEnabled.mockReturnValue(false);
        const result = await runPulseScan({ ...BASE_OPTS, json: true }, {});
        expect(result.exitCode).toBe(1);
        expect(() => JSON.parse(result.lines[0].text)).not.toThrow();
    });
});