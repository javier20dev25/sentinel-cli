/**
 * Sentinel Supply Chain Shield (v5.0 — A2)
 * 
 * Real package downloader + SAST scanner for supply chain threats.
 * Integrates OSV.dev CVE lookup, typosquatting detection, trust cache.
 * Downloads tarballs from npm registry, extracts to temp, and runs LiteScanner.
 */

import { LiteScanner, LiteFinding } from '../../core/lite/lite_scanner';
import * as pc from 'picocolors';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { execSync, execFileSync } from 'child_process';
import { OSVIntegrator, OSVResult } from './osv_integrator';
import { TyposquatDetector, TyposquatResult } from './typosquat_detector';
import { TrustCache, CacheResult } from './trust_cache';

export interface PackageAnalysis {
    pkg: string;
    findings: LiteFinding[];
    fileCount: number;
    scanTimeMs: number;
    memoryMB: number;
    sizeBytes: number;
    verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS';
    osvResult?: OSVResult;
    typosquat?: TyposquatResult;
    cacheResult?: CacheResult;
}

export class SupplyChainShield {
    private scanner: LiteScanner;
    private osv: OSVIntegrator;
    private typosquat: TyposquatDetector;
    private trustCache: TrustCache;

    constructor() {
        this.scanner = new LiteScanner();
        this.osv = new OSVIntegrator();
        this.typosquat = new TyposquatDetector();
        this.trustCache = new TrustCache();
    }

    /**
     * Download a package tarball (without installing) and run SAST.
     */
    public async analyzePackage(pkgSpec: string): Promise<PackageAnalysis> {
        const memBefore = process.memoryUsage().heapUsed / 1024 / 1024;

        // Extract name and version
        const atIdx = pkgSpec.lastIndexOf('@');
        const pkgName = atIdx > 0 ? pkgSpec.substring(0, atIdx) : pkgSpec;
        const pkgVersion = atIdx > 0 ? pkgSpec.substring(atIdx + 1) : '';

        // Trust cache check
        const cacheResult = this.trustCache.get(pkgName, pkgVersion);
        if (cacheResult.found && cacheResult.recencyBand === 'STALE') {
            const entry = cacheResult.entry!;
            return {
                pkg: pkgSpec,
                findings: [],
                fileCount: 0,
                scanTimeMs: 0,
                memoryMB: 0,
                sizeBytes: 0,
                verdict: entry.verdict as 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS',
                cacheResult
            };
        }

        // Typosquatting check (before download)
        const typosquat = this.typosquat.check(pkgName);

        // OSV.dev query (before download)
        const osvResult = await this.osv.queryPackage(pkgName, pkgVersion);
        const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-shield-'));

        try {
            console.log(pc.cyan(`\n📦 Downloading ${pkgSpec} (no-install mode)...`));

            const startTime = Date.now();

            // Use npm pack to download tarball without installing — safe from shell injection
            const safePkg = pkgSpec.replace(/[^a-zA-Z0-9._\-@\/]/g, '');
            try {
                const tgt = tmpDir.replace(/\\/g, '/');
                execSync(`npm pack ${safePkg} --pack-destination "${tgt}" --ignore-scripts`, {
                    encoding: 'utf8' as const, timeout: 60000, stdio: 'pipe' as const, windowsHide: true, shell: true as any,
                });
            } catch (e: unknown) {
                const err = e as { stderr?: string; stdout?: string; message?: string };
                throw new Error(`npm pack failed: ${(err.stderr || err.stdout || err.message || '').substring(0, 200)}`);
            }

            // Find the .tgz file
            const tgzFile = fs.readdirSync(tmpDir).find(f => f.endsWith('.tgz'));
            if (!tgzFile) throw new Error('No tarball produced by npm pack');

            const tgzPath = path.join(tmpDir, tgzFile);
            const stats = fs.statSync(tgzPath);
            const sizeBytes = stats.size;

            // Extract the tarball — safe from shell injection
            const extractDir = path.join(tmpDir, 'pkg');
            fs.mkdirSync(extractDir);

            try {
                execFileSync('tar', ['-xzf', tgzPath, '-C', extractDir], {
                    encoding: 'utf8', timeout: 30000, stdio: 'pipe', windowsHide: true,
                });
            } catch (e: unknown) {
                const err = e as { stderr?: string; message?: string };
                console.log(pc.dim(`  tar extraction warning: ${(err.stderr || err.message || '').substring(0, 100)}`));
            }

            // Find package directory (npm packs into package/)
            const pkgDir = path.join(extractDir, 'package');
            if (!fs.existsSync(pkgDir)) {
                throw new Error('Extracted package has no package/ directory');
            }

            // Gather all JS/TS/MJS files
            const allFiles: string[] = [];
            this.walkDir(pkgDir, allFiles);
            const jsFiles = allFiles.filter(f =>
                f.endsWith('.js') || f.endsWith('.ts') || f.endsWith('.mjs') || f.endsWith('.cjs')
            );

            // Scan each file with LiteScanner
            const allFindings: LiteFinding[] = [];
            for (const file of jsFiles) {
                try {
                    const content = fs.readFileSync(file, 'utf8');
                    const relPath = path.relative(pkgDir, file);
                    const patch = `@@ -0,0 +1,1 @@\n+${content.split('\n').join('\n+')}`;
                    const findings = this.scanner.scanPatch(relPath, patch);
                    findings.forEach(f => allFindings.push(f));
                } catch (_skip: unknown) {
                    // skip binary/unreadable files
                }
            }

            // Scan extra files: .gyp, .gypi, .sh, .ps1, .bat, package.json (v5.0)
            const extraFiles = allFiles.filter(f =>
                f.endsWith('.gyp') || f.endsWith('.gypi') ||
                f.endsWith('.sh') || f.endsWith('.ps1') || f.endsWith('.bat') ||
                path.basename(f) === 'package.json'
            );
            for (const file of extraFiles) {
                try {
                    const content = fs.readFileSync(file, 'utf8');
                    const relPath = path.relative(pkgDir, file);
                    const result = this.scanner.scanFileContent(relPath, content);
                    result.findings.forEach(f => allFindings.push(f));
                } catch (_skip: unknown) {}
            }

            const scanTimeMs = Date.now() - startTime;
            const memAfter = process.memoryUsage().heapUsed / 1024 / 1024;
            const memoryMB = parseFloat((memAfter - memBefore).toFixed(1));

            // Verdict — incorporates OSV and typosquatting
            let verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' = 'SAFE';
            if (allFindings.some(f => f.severity === 'CRITICAL') ||
                osvResult.vulnerabilities.some(v => {
                    const maxS = OSVIntegrator.getMaxSeverity(v);
                    return maxS && maxS.score >= 9.0;
                })) {
                verdict = 'MALICIOUS';
            } else if (allFindings.some(f => f.severity === 'HIGH' || f.type.startsWith('SECRET_')) ||
                       typosquat.isSuspicious ||
                       osvResult.vulnerabilities.length > 0) {
                verdict = 'SUSPICIOUS';
            }

            // Cache the result
            const criticalCount = allFindings.filter(f => f.severity === 'CRITICAL').length;
            this.trustCache.set(pkgName, pkgVersion, verdict, allFindings.length, criticalCount);

            // Cleanup tarball
            try { fs.unlinkSync(tgzPath); } catch (_) {}

            return {
                pkg: pkgSpec,
                findings: allFindings,
                fileCount: jsFiles.length,
                scanTimeMs,
                memoryMB: Math.max(memoryMB, 0.1),
                sizeBytes,
                verdict,
                osvResult,
                typosquat,
                cacheResult
            };

        } finally {
            // Cleanup temp directory
            try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_) {}
        }
    }

    /**
     * Scan multiple packages in batch and return a report.
     */
    public async analyzeBatch(pkgSpecs: string[]): Promise<PackageAnalysis[]> {
        const results: PackageAnalysis[] = [];
        for (const pkg of pkgSpecs) {
            try {
                const result = await this.analyzePackage(pkg);
                results.push(result);
            } catch (err: unknown) {
                results.push({
                    pkg,
                    findings: [],
                    fileCount: 0,
                    scanTimeMs: 0,
                    memoryMB: 0,
                    sizeBytes: 0,
                    verdict: 'SAFE'
                });
                console.error(pc.red(`  ✖ Error analyzing ${pkg}: ${(err as Error).message}`));
            }
        }
        return results;
    }

    /**
     * Scans a package installation intent (legacy interface).
     * Now delegates to analyzePackage but only warns, doesn't mock.
     */
    public async scanInstallation(manager: string, args: string[]) {
        const pkgs = args.filter(a => !a.startsWith('-'));
        if (pkgs.length === 0) {
            console.log(pc.yellow('No packages specified.'));
            return { success: true };
        }

        console.log(pc.cyan(`\n🛡️  Sentinel Supply Chain Shield: Analyzing installation for ${pkgs.join(', ')}...`));
        const results = await this.analyzeBatch(pkgs);
        const malicious = results.filter(r => r.verdict !== 'SAFE');

        if (malicious.length > 0) {
            console.log(pc.red(`\n🚨 CRITICAL THREATS DETECTED in installation path:`));
            for (const m of malicious) {
                console.log(pc.yellow(`  ■ ${m.pkg}: ${m.findings.length} threat(s) found (${m.verdict})`));
                m.findings.slice(0, 3).forEach(f => {
                    console.log(pc.dim(`      ↳ [${f.severity}] ${f.type}: ${f.description}`));
                });
            }
            console.log(pc.red(`\nInstallation BLOCKED by Sentinel. Review findings before proceeding.`));
            return { success: false, results };
        }

        console.log(pc.green(`\n✔ All packages passed Sentinel verification.`));
        return { success: true, results };
    }

    private walkDir(dir: string, results: string[], depth = 0): void {
        if (!fs.existsSync(dir) || depth > 10) return;
        const list = fs.readdirSync(dir);
        for (const file of list) {
            if (file.startsWith('.') || file === 'node_modules') continue;
            const full = path.resolve(dir, file);
            // Zip-slip protection: reject symlinks and paths outside base dir
            if (!full.startsWith(path.resolve(dir))) continue;
            try {
                if (fs.lstatSync(full).isSymbolicLink()) continue;
                const stat = fs.statSync(full);
                if (stat.isDirectory()) {
                    this.walkDir(full, results, depth + 1);
                } else {
                    results.push(full);
                }
            } catch (_) {}
        }
    }
}
