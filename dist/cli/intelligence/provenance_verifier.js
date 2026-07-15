"use strict";
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
exports.ProvenanceVerifier = void 0;
const child_process_1 = require("child_process");
class ProvenanceVerifier {
    checkCommandAvailable() {
        try {
            (0, child_process_1.execSync)('npm attestation --help', { encoding: 'utf8', stdio: 'pipe', shell: true });
            return true;
        }
        catch (_a) {
            return false;
        }
    }
    verify(packageName, version) {
        return __awaiter(this, void 0, void 0, function* () {
            const pkgSpec = version ? `${packageName}@${version}` : packageName;
            try {
                const stdout = (0, child_process_1.execSync)(`npm attestation verify ${pkgSpec}`, {
                    encoding: 'utf8', stdio: 'pipe', shell: true
                });
                const raw = JSON.parse(stdout);
                const items = Array.isArray(raw) ? raw : [raw];
                const attestations = [];
                let allVerified = true;
                for (const item of items) {
                    const vr = item.verificationResult || {};
                    const results = Array.isArray(vr.results) ? vr.results : [];
                    const firstResult = results[0] || {};
                    const signer = firstResult.signer || item.signer || {};
                    const att = item.attestation || {};
                    const subjects = Array.isArray(att.subject) ? att.subject : (att.subject ? [att.subject] : []);
                    const firstSubject = subjects[0] || {};
                    const type = item.type || 'attestation';
                    const issuer = signer.issuer || item.issuer || '';
                    const subject = typeof firstSubject === 'string' ? firstSubject : (firstSubject.name || '');
                    const predicateType = att.predicateType || item.predicateType || '';
                    const timestamp = firstResult.timestamp || item.timestamp || '';
                    let slsaLevel;
                    if (predicateType && predicateType.includes('slsa.dev')) {
                        const m = predicateType.match(/v(\d+)/);
                        if (m)
                            slsaLevel = `SLSA v${m[1]}`;
                    }
                    if (vr.verified !== true)
                        allVerified = false;
                    attestations.push({ type, issuer, subject, predicateType, timestamp, slsaLevel });
                }
                return {
                    packageName,
                    version: version || '',
                    verified: attestations.length > 0 && allVerified,
                    attestations
                };
            }
            catch (e) {
                return {
                    packageName,
                    version: version || '',
                    verified: false,
                    attestations: [],
                    error: e.stderr || e.stdout || e.message || 'Unknown error'
                };
            }
        });
    }
}
exports.ProvenanceVerifier = ProvenanceVerifier;
