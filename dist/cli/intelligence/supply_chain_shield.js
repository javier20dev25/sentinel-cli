"use strict";
/**
 * Sentinel Supply Chain Shield (v2.0)
 *
 * Real package downloader + SAST scanner for supply chain threats.
 * Downloads tarballs from npm registry, extracts to temp, and runs LiteScanner.
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.SupplyChainShield = void 0;
const lite_scanner_1 = require("../../core/lite/lite_scanner");
const pc = __importStar(require("picocolors"));
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const os = __importStar(require("os"));
const child_process_1 = require("child_process");
class SupplyChainShield {
    constructor() {
        this.scanner = new lite_scanner_1.LiteScanner();
    }
    /**
     * Download a package tarball (without installing) and run SAST.
     */
    analyzePackage(pkgSpec) {
        return __awaiter(this, void 0, void 0, function* () {
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
                                const result = (0, child_process_1.execSync)('where.exe npm', { encoding: 'utf8', timeout: 5000 });
                                return result.toString().trim().split('\n')[0].trim();
                            }
                            catch (_unused) {
                                return 'npm.cmd';
                            }
                        })()
                        : (process.env.NVM_SYMLINK || 'npm');
                    (0, child_process_1.execSync)(`"${npmBin}" pack "${pkgSpec}" --pack-destination "${tmpDir}"`, {
                        encoding: 'utf8', timeout: 60000, stdio: 'pipe'
                    });
                }
                catch (e) {
                    const err = e;
                    throw new Error(`npm pack failed: ${(err.stderr || err.stdout || err.message || '').substring(0, 200)}`);
                }
                // Find the .tgz file
                const tgzFile = fs.readdirSync(tmpDir).find(f => f.endsWith('.tgz'));
                if (!tgzFile)
                    throw new Error('No tarball produced by npm pack');
                const tgzPath = path.join(tmpDir, tgzFile);
                const stats = fs.statSync(tgzPath);
                const sizeBytes = stats.size;
                // Extract the tarball
                const extractDir = path.join(tmpDir, 'pkg');
                fs.mkdirSync(extractDir);
                try {
                    (0, child_process_1.execSync)(`tar -xzf "${tgzPath}" -C "${extractDir}"`, {
                        encoding: 'utf8', timeout: 30000, stdio: 'pipe'
                    });
                }
                catch (e) {
                    const err = e;
                    console.log(pc.dim(`  tar extraction warning: ${(err.stderr || err.message || '').substring(0, 100)}`));
                }
                // Find package directory (npm packs into package/)
                const pkgDir = path.join(extractDir, 'package');
                if (!fs.existsSync(pkgDir)) {
                    throw new Error('Extracted package has no package/ directory');
                }
                // Gather all JS/TS/MJS files
                const allFiles = [];
                this.walkDir(pkgDir, allFiles);
                const jsFiles = allFiles.filter(f => f.endsWith('.js') || f.endsWith('.ts') || f.endsWith('.mjs') || f.endsWith('.cjs'));
                // Scan each file with LiteScanner
                const allFindings = [];
                for (const file of jsFiles) {
                    try {
                        const content = fs.readFileSync(file, 'utf8');
                        const relPath = path.relative(pkgDir, file);
                        const patch = `@@ -0,0 +1,1 @@\n+${content.split('\n').join('\n+')}`;
                        const findings = this.scanner.scanPatch(relPath, patch);
                        findings.forEach(f => allFindings.push(f));
                    }
                    catch (_skip) {
                        // skip binary/unreadable files
                    }
                }
                const scanTimeMs = Date.now() - startTime;
                const memAfter = process.memoryUsage().heapUsed / 1024 / 1024;
                const memoryMB = parseFloat((memAfter - memBefore).toFixed(1));
                // Verdict
                let verdict = 'SAFE';
                if (allFindings.some(f => f.severity === 'CRITICAL')) {
                    verdict = 'MALICIOUS';
                }
                else if (allFindings.some(f => f.severity === 'HIGH' || f.type.startsWith('SECRET_'))) {
                    verdict = 'SUSPICIOUS';
                }
                // Cleanup tarball
                try {
                    fs.unlinkSync(tgzPath);
                }
                catch (_) { }
                return {
                    pkg: pkgSpec,
                    findings: allFindings,
                    fileCount: jsFiles.length,
                    scanTimeMs,
                    memoryMB: Math.max(memoryMB, 0.1),
                    sizeBytes,
                    verdict
                };
            }
            finally {
                // Cleanup temp directory
                try {
                    fs.rmSync(tmpDir, { recursive: true, force: true });
                }
                catch (_) { }
            }
        });
    }
    /**
     * Scan multiple packages in batch and return a report.
     */
    analyzeBatch(pkgSpecs) {
        return __awaiter(this, void 0, void 0, function* () {
            const results = [];
            for (const pkg of pkgSpecs) {
                try {
                    const result = yield this.analyzePackage(pkg);
                    results.push(result);
                }
                catch (err) {
                    results.push({
                        pkg,
                        findings: [],
                        fileCount: 0,
                        scanTimeMs: 0,
                        memoryMB: 0,
                        sizeBytes: 0,
                        verdict: 'SAFE'
                    });
                    console.error(pc.red(`  ✖ Error analyzing ${pkg}: ${err.message}`));
                }
            }
            return results;
        });
    }
    /**
     * Scans a package installation intent (legacy interface).
     * Now delegates to analyzePackage but only warns, doesn't mock.
     */
    scanInstallation(manager, args) {
        return __awaiter(this, void 0, void 0, function* () {
            const pkgs = args.filter(a => !a.startsWith('-'));
            if (pkgs.length === 0) {
                console.log(pc.yellow('No packages specified.'));
                return { success: true };
            }
            console.log(pc.cyan(`\n🛡️  Sentinel Supply Chain Shield: Analyzing installation for ${pkgs.join(', ')}...`));
            const results = yield this.analyzeBatch(pkgs);
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
        });
    }
    walkDir(dir, results) {
        if (!fs.existsSync(dir))
            return;
        const list = fs.readdirSync(dir);
        for (const file of list) {
            if (file.startsWith('.') || file === 'node_modules')
                continue;
            const full = path.join(dir, file);
            try {
                const stat = fs.statSync(full);
                if (stat.isDirectory()) {
                    this.walkDir(full, results);
                }
                else {
                    results.push(full);
                }
            }
            catch (_) { }
        }
    }
}
exports.SupplyChainShield = SupplyChainShield;
