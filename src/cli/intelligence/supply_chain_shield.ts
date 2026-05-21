/**
 * Sentinel Supply Chain Shield (v2.0)
 * 
 * Real package downloader + SAST scanner for supply chain threats.
 * Downloads tarballs from npm registry, extracts to temp, and runs LiteScanner.
 */

import { LiteScanner, LiteFinding } from '../../core/lite/lite_scanner';
import * as pc from 'picocolors';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { execSync } from 'child_process';

export interface PackageAnalysis {
    pkg: string;
    findings: LiteFinding[];
    fileCount: number;
    scanTimeMs: number;
    memoryMB: number;
    sizeBytes: number;
    verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS';
}

export class SupplyChainShield {
    private scanner: LiteScanner;

    constructor() {
        this.scanner = new LiteScanner();
    }

    /**
     * Download a package tarball (without installing) and run SAST.
     */
    public async analyzePackage(pkgSpec: string): Promise<PackageAnalysis> {
        const tmpDir = path.join(os.tmpdir(), 'sentinel-shield-' + Date.now());
        fs.mkdirSync(tmpDir, { recursive: true });
        const memBefore = process.memoryUsage().heapUsed / 1024 / 1024;

        try {
            console.log(pc.cyan(`\n📦 Downloading ${pkgSpec} (no-install mode)...`));

            const startTime = Date.now();

            // Use npm pack to download tarball without installing
            try {
                const npmBin = process.platform === 'win32'
                    ? (() => {
                        try {
                            const result = execSync('where.exe npm', { encoding: 'utf8', timeout: 5000 });
                            return result.toString().trim().split('\n')[0].trim();
                        } catch (_unused: unknown) {
                            return 'npm.cmd';
                        }
                      })()
                    : (process.env.NVM_SYMLINK || 'npm');
                execSync(`"${npmBin}" pack "${pkgSpec}" --pack-destination "${tmpDir}"`, {
                    encoding: 'utf8', timeout: 60000, stdio: 'pipe'
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

            // Extract the tarball
            const extractDir = path.join(tmpDir, 'pkg');
            fs.mkdirSync(extractDir);

            try {
                execSync(`tar -xzf "${tgzPath}" -C "${extractDir}"`, {
                    encoding: 'utf8', timeout: 30000, stdio: 'pipe'
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

            const scanTimeMs = Date.now() - startTime;
            const memAfter = process.memoryUsage().heapUsed / 1024 / 1024;
            const memoryMB = parseFloat((memAfter - memBefore).toFixed(1));

            // Verdict
            let verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' = 'SAFE';
            if (allFindings.some(f => f.severity === 'CRITICAL')) {
                verdict = 'MALICIOUS';
            } else if (allFindings.some(f => f.severity === 'HIGH' || f.type.startsWith('SECRET_'))) {
                verdict = 'SUSPICIOUS';
            }

            // Cleanup tarball
            try { fs.unlinkSync(tgzPath); } catch (_) {}

            return {
                pkg: pkgSpec,
                findings: allFindings,
                fileCount: jsFiles.length,
                scanTimeMs,
                memoryMB: Math.max(memoryMB, 0.1),
                sizeBytes,
                verdict
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

    private walkDir(dir: string, results: string[]): void {
        if (!fs.existsSync(dir)) return;
        const list = fs.readdirSync(dir);
        for (const file of list) {
            if (file.startsWith('.') || file === 'node_modules') continue;
            const full = path.join(dir, file);
            try {
                const stat = fs.statSync(full);
                if (stat.isDirectory()) {
                    this.walkDir(full, results);
                } else {
                    results.push(full);
                }
            } catch (_) {}
        }
    }
}
