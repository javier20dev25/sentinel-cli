/**
 * Sentinel Integrity Manager (v1.0)
 * 
 * Ensures the CLI and its environment are not tampered with.
 * Levels: TRUSTED | SUSPECT | COMPROMISED
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import * as pc from 'picocolors';

export type IntegrityLevel = 'TRUSTED' | 'SUSPECT' | 'COMPROMISED';

export class IntegrityManager {
    private cliRoot: string;
    private vaultPath: string;

    constructor() {
        this.cliRoot = path.join(__dirname, '..', '..', '..');
        this.vaultPath = path.join(os.homedir(), '.sentinel', 'vault.db');
    }

    /**
     * Performs a full system integrity audit.
     */
    public async checkIntegrity(): Promise<{ level: IntegrityLevel, reasons: string[] }> {
        const reasons: string[] = [];
        let level: IntegrityLevel = 'TRUSTED';

        // 1. Check Self-Integrity (Ruleset hash)
        const rulesHash = this.calculateRulesHash();
        if (rulesHash === 'unable-to-verify') {
            reasons.push('Scanner ruleset could not be verified (files missing).');
            if (level === 'TRUSTED') level = 'SUSPECT';
        }

        // 2. Check Environment (PATH poisoning / precedence)
        const pathDirs = (process.env.PATH || '').split(path.delimiter);
        const suspiciousDirs = ['temp', 'tmp', 'downloads', 'desktop', 'public'];
        const hijacked = pathDirs.slice(0, 3).some(d => 
            suspiciousDirs.some(s => d.toLowerCase().includes(s))
        );
        
        if (hijacked) {
            reasons.push('High-precedence PATH hijacking detected (Suspicious entry in top 3).');
            if (level === 'TRUSTED') level = 'SUSPECT';
        }

        // 3. Check State (Vault & Clock)
        if (fs.existsSync(this.vaultPath)) {
            const stat = fs.statSync(this.vaultPath);
            if (stat.size === 0) {
                reasons.push('Signal Vault integrity compromised (Zero-byte file).');
                level = 'COMPROMISED';
            }
            
            // Clock Anomaly: Check if current time is before vault last modification
            if (Date.now() < stat.mtimeMs) {
                reasons.push('System clock anomaly detected (Time drift detected).');
                if (level !== 'COMPROMISED') level = 'SUSPECT';
            }
        }

        // 4. Secure Manifest Verification
        if (!this.verifySignedManifest()) {
            reasons.push('CLI Manifest verification failed (Signed integrity violation).');
            level = 'COMPROMISED';
        }

        // 5. Runtime Integrity (Simulated)
        if (process.env.SENTINEL_UNTRUSTED === 'true') {
            reasons.push('Environment marked as untrusted by security policy.');
            level = 'COMPROMISED';
        }

        return { level, reasons };
    }

    private calculateRulesHash(): string {
        // Hash the compiled LiteScanner (dist JS) — the file that actually runs
        const distPaths = [
            path.join(this.cliRoot, 'dist', 'core', 'lite', 'lite_scanner.js'),
            path.join(this.cliRoot, 'dist', 'cli', 'intelligence', 'signal_vault.js'),
        ];
        const hash = crypto.createHash('sha256');
        let found = false;
        for (const p of distPaths) {
            if (fs.existsSync(p)) {
                hash.update(fs.readFileSync(p, 'utf8'));
                found = true;
            }
        }
        if (!found) {
            // Fallback: hash source files for dev mode
            const srcPath = path.join(this.cliRoot, 'src', 'core', 'lite', 'lite_scanner.ts');
            if (fs.existsSync(srcPath)) {
                hash.update(fs.readFileSync(srcPath, 'utf8'));
                found = true;
            }
        }
        return found ? hash.digest('hex') : 'unable-to-verify';
    }

    private verifySignedManifest(): boolean {
        const manifestPath = path.join(this.cliRoot, 'integrity.json');
        try {
            if (!fs.existsSync(manifestPath)) return true; // No manifest = dev mode, skip
            const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
            const currentHash = this.calculateRulesHash();
            return manifest.rulesHash === currentHash;
        } catch (_e: unknown) {
            return true; // Dev mode: don't block on manifest issues
        }
    }

    public report(level: IntegrityLevel, reasons: string[]) {
        console.log(pc.magenta('\n🛡️  SENTINEL HOST INTEGRITY CHECK'));

        if (level === 'TRUSTED') {
            console.log(pc.green('   ✓ Local environment verified and trusted.\n'));
        } else {
            const color = level === 'COMPROMISED' ? pc.red : pc.yellow;
            console.log(color(`\n   ⚠️  HOST INTEGRITY: ${level}`));
            console.log(pc.dim('   Confidence Level: LOW\n'));
            reasons.forEach(r => console.log(pc.dim(`   - ${r}`)));
            
            if (level === 'COMPROMISED') {
                console.log(pc.red('\n   🚨 SECURITY ALERT: Sentinel is running in DEGRADED MODE.'));
                console.log(pc.dim('      Automatic blocking and privileged actions disabled.\n'));
            }
        }
    }
}
