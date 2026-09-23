import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { loadPulseMode, savePulseMode, isPulseModeEnabled, getPulseModePath } from './pulse_mode';

const TEST_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'pulse-mode-test-'));

describe('pulse_mode', () => {
    const configPath = path.join(TEST_DIR, 'sub', 'pulse-mode.json');

    beforeEach(() => {
        for (const p of [configPath, getPulseModePath()]) {
            try {
                fs.unlinkSync(p);
            } catch {
                // ignore
            }
        }
    });

    afterEach(() => {
        fs.rmSync(TEST_DIR, { recursive: true, force: true });
    });

    it('defaults to disabled when no config file exists', () => {
        expect(isPulseModeEnabled({ configPath })).toBe(false);
        expect(loadPulseMode({ configPath })).toMatchObject({ enabled: false });
    });

    it('persists enable/disable and reads it back', () => {
        savePulseMode(true, { configPath });
        expect(isPulseModeEnabled({ configPath })).toBe(true);
        expect(loadPulseMode({ configPath }).enabled).toBe(true);
        expect(fs.existsSync(configPath)).toBe(true);

        savePulseMode(false, { configPath });
        expect(isPulseModeEnabled({ configPath })).toBe(false);
    });

    it('treats malformed/JSON-not-bool configs as disabled', () => {
        fs.mkdirSync(path.dirname(configPath), { recursive: true });
        for (const content of ['not-json', '{"enabled":"yes"}', '{"enabled":1}', '{}']) {
            fs.writeFileSync(configPath, content);
            expect(isPulseModeEnabled({ configPath })).toBe(false);
        }
    });
});