import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { OSVIntegrator } from './osv_integrator';
import { summarizeFindings } from './audit_deps_report';
import { TyposquatDetector } from './typosquat_detector';
import { TrustCache } from './trust_cache';
import { DepsScanner } from './deps_scanner';

// ─── OSV Integrator ────────────────────────────────────────────────────────

describe('OSVIntegrator', () => {
    const osv = new OSVIntegrator();

    describe('getMaxSeverity', () => {
        it('returns null for empty severity array', () => {
            expect(OSVIntegrator.getMaxSeverity({ id: 'GHSA-1', summary: '', aliases: [], severity: [], published: '', modified: '' })).toBeNull();
        });

        it('returns the highest CVSS score', () => {
            const result = OSVIntegrator.getMaxSeverity({
                id: 'GHSA-2', summary: '', aliases: [],
                severity: [{ type: 'CVSS_V3', score: '5.5' }, { type: 'CVSS_V3', score: '7.5' }],
                published: '', modified: ''
            });
            expect(result).toEqual({ type: 'CVSS_V3', score: 7.5 });
        });

        it('parses float scores correctly', () => {
            const result = OSVIntegrator.getMaxSeverity({
                id: 'GHSA-3', summary: '', aliases: [],
                severity: [{ type: 'CVSS_V3', score: '9.8' }],
                published: '', modified: ''
            });
            expect(result!.score).toBeCloseTo(9.8);
        });
    });

    describe('toSentinelSeverity', () => {
        it('maps 9.0+ to CRITICAL', () => { expect(OSVIntegrator.toSentinelSeverity(9.0)).toBe('CRITICAL'); });
        it('maps 7.0-8.9 to HIGH', () => { expect(OSVIntegrator.toSentinelSeverity(7.5)).toBe('HIGH'); });
        it('maps 4.0-6.9 to MEDIUM', () => { expect(OSVIntegrator.toSentinelSeverity(5.5)).toBe('MEDIUM'); });
        it('maps <4.0 to LOW', () => { expect(OSVIntegrator.toSentinelSeverity(3.9)).toBe('LOW'); });
    });

    describe('getMaxSeverity with CVSS vectors', () => {
        it('scores a CVSS v3.1 vector instead of NaN', () => {
            const result = OSVIntegrator.getMaxSeverity({
                id: 'GHSA-v', summary: '', aliases: [],
                severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N' }],
                published: '', modified: ''
            });
            expect(result).toEqual({ type: 'CVSS_V3', score: 7.5 });
        });

        it('does not score CVSS v4.0 vectors (returns null)', () => {
            expect(OSVIntegrator.parseCvssV3Vector('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N')).toBeNull();
        });
    });

    describe('getSourceSeverity', () => {
        it('prefers the published database_specific.severity', () => {
            const r = OSVIntegrator.getSourceSeverity({
                id: 'GHSA-1', summary: '', aliases: [], severity: [], published: '', modified: '',
                database_specific: { severity: 'HIGH' }
            });
            expect(r.level).toBe('HIGH');
            expect(r.source).toBe('osv.database_specific.severity');
        });

        it('normalizes MODERATE to MEDIUM', () => {
            const r = OSVIntegrator.getSourceSeverity({
                id: 'GHSA-2', summary: '', aliases: [], severity: [], published: '', modified: '',
                database_specific: { severity: 'MODERATE' }
            });
            expect(r.level).toBe('MEDIUM');
        });

        it('derives severity from a CVSS v3 vector when no published label exists', () => {
            const r = OSVIntegrator.getSourceSeverity({
                id: 'GHSA-3', summary: '', aliases: [], published: '', modified: '',
                severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N' }]
            });
            expect(r.level).toBe('HIGH');
            expect(r.cvssScore).toBe(7.5);
            expect(r.source).toBe('osv.severity.cvss_vector');
        });

        it('returns UNKNOWN (never MEDIUM) when no severity is available', () => {
            const r = OSVIntegrator.getSourceSeverity({ id: 'GHSA-4', summary: '', aliases: [], severity: [], published: '', modified: '' });
            expect(r.level).toBe('UNKNOWN');
            expect(r.source).toBe('none');
        });

        it('records a CVSS v4.0 vector as unmapped UNKNOWN', () => {
            const r = OSVIntegrator.getSourceSeverity({
                id: 'GHSA-5', summary: '', aliases: [], published: '', modified: '',
                severity: [{ type: 'CVSS_V4', score: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N' }]
            });
            expect(r.level).toBe('UNKNOWN');
            expect(r.source).toBe('osv.severity.cvss_v4_unmapped');
        });
    });

    describe('getFixedVersions', () => {
        it('collects first-fixed versions from affected ranges', () => {
            const fixes = OSVIntegrator.getFixedVersions({
                id: 'GHSA-f', summary: '', aliases: [], severity: [], published: '', modified: '',
                affected: [{ ranges: [{ events: [{ introduced: '5.0.0' }, { fixed: '5.0.7' }] }] }]
            });
            expect(fixes).toEqual(['5.0.7']);
        });
    });
});

// ─── audit-deps summary ──────────────────────────────────────────────────────

describe('summarizeFindings', () => {
    const mkVuln = (id: string, severity: string) => ({
        id, summary: '', aliases: [], severity: [], published: '', modified: '',
        database_specific: { severity }
    });

    it('separates instances, package@version×advisory and unique advisories', () => {
        const results: any[] = [
            {
                packageName: 'brace-expansion', version: '1.1.12', queryTimeMs: 0,
                vulnerabilities: [mkVuln('GHSA-x', 'HIGH'), mkVuln('GHSA-y', 'MODERATE')]
            },
            {
                packageName: 'brace-expansion', version: '5.0.3', queryTimeMs: 0,
                vulnerabilities: [mkVuln('GHSA-x', 'HIGH')] // same GHSA, different version
            },
        ];
        const s = summarizeFindings(results);
        expect(s.instances).toBe(3);
        expect(s.pkgVersionGhsa).toBe(3);
        expect(s.uniqueGhsa).toBe(2);
        expect(s.bySourceSeverity.HIGH).toBe(1); // GHSA-x counted once
        expect(s.bySourceSeverity.MEDIUM).toBe(1); // MODERATE normalized
    });

    it('counts unscored advisories as UNKNOWN, never MEDIUM', () => {
        const results: any[] = [
            { packageName: 'p', version: '1.0.0', queryTimeMs: 0, vulnerabilities: [mkVuln('GHSA-z', undefined as any)] }
        ];
        const s = summarizeFindings(results);
        expect(s.bySourceSeverity.UNKNOWN).toBe(1);
        expect(s.bySourceSeverity.MEDIUM).toBeUndefined();
    });
});

// ─── Typosquat Detector ─────────────────────────────────────────────────────

describe('TyposquatDetector', () => {
    const td = new TyposquatDetector();

    it('does not flag exact matches of popular packages', () => {
        const result = td.check('lodash');
        expect(result.isSuspicious).toBe(false);
    });

    it('detects Levenshtein typosquatting (lodash → lodsh)', () => {
        const result = td.check('lodsh');
        expect(result.isSuspicious).toBe(true);
        expect(result.matches.some(m => m.target === 'lodash')).toBe(true);
    });

    it('detects Levenshtein typosquatting (chalk → chak)', () => {
        const result = td.check('chak');
        expect(result.isSuspicious).toBe(true);
        expect(result.matches.some(m => m.target === 'chalk')).toBe(true);
    });

    it('does not flag completely unrelated names', () => {
        const result = td.check('my-awesome-package-12345');
        expect(result.isSuspicious).toBe(false);
    });

    it('detects missing character typos (express → expres)', () => {
        const result = td.check('expres');
        expect(result.isSuspicious).toBe(true);
    });

    it('detects single-character substitution (axios → axos)', () => {
        const result = td.check('axos');  // distance 1: missing 'i'
        expect(result.isSuspicious).toBe(true);
        expect(result.matches.some(m => m.target === 'axios')).toBe(true);
    });

    it('detects homoglyph substitution in popular names', () => {
        const result = td.check('lоdash');  // Cyrillic 'о'
        expect(result.isSuspicious).toBe(true);
    });

    it('limits to top 3 closest matches', () => {
        const result = td.check('reakt');
        expect(result.matches.length).toBeLessThanOrEqual(3);
    });
});

// ─── Trust Cache ────────────────────────────────────────────────────────────

describe('TrustCache', () => {
    let cache: TrustCache;

    beforeEach(() => {
        cache = new TrustCache();
        // Clear between tests to avoid state leakage
        cache.clear();
    });

    it('returns UNKNOWN for uncached packages', () => {
        const result = cache.get('nonexistent', '1.0.0');
        expect(result.found).toBe(false);
        expect(result.recencyBand).toBe('UNKNOWN');
    });

    it('stores and retrieves entries', () => {
        cache.set('test-pkg', '1.0.0', 'SAFE', 2, 0);
        const result = cache.get('test-pkg', '1.0.0');
        expect(result.found).toBe(true);
        expect(result.entry!.verdict).toBe('SAFE');
        expect(result.entry!.findingCount).toBe(2);
    });

    it('marks entries < 1 hour as FRESH', () => {
        cache.set('fresh-pkg', '1.0.0', 'SAFE', 0, 0);
        const result = cache.get('fresh-pkg', '1.0.0');
        expect(result.recencyBand).toBe('FRESH');
    });

    it('returns correct stats', () => {
        cache.set('a', '1', 'SAFE', 0, 0);
        cache.set('b', '2', 'SAFE', 0, 0);
        const s = cache.stats();
        expect(s.entries).toBe(2);
    });

    it('clears all entries', () => {
        cache.set('x', '1', 'SAFE', 0, 0);
        cache.clear();
        expect(cache.stats().entries).toBe(0);
        const result = cache.get('x', '1');
        expect(result.found).toBe(false);
    });

    it('prunes old entries', () => {
        cache.set('old', '1', 'SAFE', 0, 0);
        const removed = cache.prune(0);
        expect(removed).toBe(1);
        expect(cache.stats().entries).toBe(0);
    });
});

// ─── Deps Scanner ──────────────────────────────────────────────────────────

describe('DepsScanner', () => {
    let scanner: DepsScanner;
    let testDir: string;

    beforeEach(() => {
        scanner = new DepsScanner();
        testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-test-deps-'));
    });

    afterEach(() => {
        try { fs.rmSync(testDir, { recursive: true, force: true }); } catch {}
    });

    it('returns empty for non-existent node_modules', () => {
        const nodes = scanner.walkTree(path.join(os.tmpdir(), 'nonexistent-' + Date.now()));
        expect(nodes).toHaveLength(0);
    });

    it('scans a simple node_modules with one package', () => {
        const nmDir = path.join(testDir, 'node_modules');
        fs.mkdirSync(nmDir, { recursive: true });

        const pkgDir = path.join(nmDir, 'test-pkg');
        fs.mkdirSync(pkgDir, { recursive: true });
        fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify({ name: 'test-pkg', version: '1.0.0' }));
        fs.writeFileSync(path.join(pkgDir, 'index.js'), 'console.log("hello")');

        const nodes = scanner.walkTree(nmDir, 1);
        expect(nodes.length).toBeGreaterThanOrEqual(1);
        expect(nodes.some(n => n.name === 'test-pkg')).toBe(true);
    });

    it('scans scoped packages (@scope/name)', () => {
        const nmDir = path.join(testDir, 'node_modules');
        fs.mkdirSync(nmDir, { recursive: true });

        const scopeDir = path.join(nmDir, '@scope');
        fs.mkdirSync(scopeDir);
        const pkgDir = path.join(scopeDir, 'my-pkg');
        fs.mkdirSync(pkgDir);
        fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify({ name: '@scope/my-pkg', version: '2.0.0' }));

        const nodes = scanner.walkTree(nmDir, 1);
        expect(nodes.some(n => n.name === '@scope/my-pkg')).toBe(true);
    });

    it('scanTree returns empty findings for clean packages', () => {
        const nmDir = path.join(testDir, 'node_modules');
        fs.mkdirSync(nmDir, { recursive: true });

        const pkgDir = path.join(nmDir, 'clean-pkg');
        fs.mkdirSync(pkgDir);
        fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify({ name: 'clean-pkg', version: '1.0.0' }));
        fs.writeFileSync(path.join(pkgDir, 'index.js'), 'const x = 1;');

        const nodes = scanner.walkTree(nmDir, 1);
        const result = scanner.scanTree(nodes);
        expect(result.totalFindings).toBe(0);
    });
});
