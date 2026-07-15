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
exports.RegistryReputation = void 0;
const child_process_1 = require("child_process");
class RegistryReputation {
    score(packageName) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const data = yield this.npmView(packageName);
                return this.calculateScore(packageName, data);
            }
            catch (_a) {
                return {
                    packageName,
                    version: 'unknown',
                    score: 0,
                    label: 'NEUTRAL',
                    factors: [{ name: 'error', impact: 0, detail: 'Package not found or npm error' }]
                };
            }
        });
    }
    npmView(packageName) {
        return __awaiter(this, void 0, void 0, function* () {
            const output = (0, child_process_1.execSync)(`npm view ${packageName} --json`, { shell: true, encoding: 'utf8' });
            return JSON.parse(output);
        });
    }
    calculateScore(packageName, data) {
        var _a, _b;
        const factors = [];
        let score = 0;
        const version = ((_a = data['dist-tags']) === null || _a === void 0 ? void 0 : _a.latest) || 'unknown';
        const now = new Date();
        if ((_b = data.time) === null || _b === void 0 ? void 0 : _b.created) {
            const created = new Date(data.time.created);
            const days = (now.getTime() - created.getTime()) / 86400000;
            if (days < 30) {
                factors.push({ name: 'age', impact: -20, detail: `Package is ${Math.round(days)} days old` });
                score -= 20;
            }
            else if (days < 90) {
                factors.push({ name: 'age', impact: -5, detail: `Package is ${Math.round(days)} days old` });
                score -= 5;
            }
            else if (days > 365) {
                factors.push({ name: 'age', impact: 10, detail: `Package is ${Math.round(days)} days old` });
                score += 10;
            }
        }
        const maintainers = data.maintainers;
        if (maintainers) {
            const count = maintainers.length;
            if (count === 1) {
                factors.push({ name: 'maintainers', impact: -10, detail: `Only ${count} maintainer` });
                score -= 10;
            }
            else if (count >= 4) {
                factors.push({ name: 'maintainers', impact: 5, detail: `${count} maintainers` });
                score += 5;
            }
            else {
                factors.push({ name: 'maintainers', impact: 0, detail: `${count} maintainers` });
            }
        }
        const versionKeys = data.versions ? Object.keys(data.versions) : [];
        if (versionKeys.length < 5) {
            factors.push({ name: 'versions', impact: -10, detail: `${versionKeys.length} versions` });
            score -= 10;
        }
        else if (versionKeys.length > 50) {
            factors.push({ name: 'versions', impact: 5, detail: `${versionKeys.length} versions` });
            score += 5;
        }
        if (data.versions) {
            const hasDeprecated = Object.values(data.versions).some((v) => v.deprecated);
            if (hasDeprecated) {
                factors.push({ name: 'deprecation', impact: -30, detail: 'Package has deprecated versions' });
                score -= 30;
            }
        }
        const desc = data.description;
        if (!desc || (typeof desc === 'string' && desc.length < 10)) {
            factors.push({ name: 'description', impact: -5, detail: !desc ? 'No description' : 'Description too short' });
            score -= 5;
        }
        if (!data.homepage) {
            factors.push({ name: 'homepage', impact: -5, detail: 'No homepage URL' });
            score -= 5;
        }
        if (desc && typeof desc === 'string' && desc.length >= 10) {
            factors.push({ name: 'description', impact: 10, detail: 'Description present and adequate' });
            score += 10;
        }
        if (data.homepage) {
            factors.push({ name: 'homepage', impact: 10, detail: 'Homepage URL provided' });
            score += 10;
        }
        if (data.versions) {
            const hasDeprecated = Object.values(data.versions).some((v) => v.deprecated);
            if (!hasDeprecated) {
                factors.push({ name: 'deprecation', impact: 10, detail: 'No deprecated versions' });
                score += 10;
            }
        }
        return {
            packageName,
            version,
            score,
            label: this.getLabel(score),
            factors
        };
    }
    getLabel(score) {
        if (score >= 50)
            return 'TRUSTED';
        if (score >= 0)
            return 'NEUTRAL';
        if (score >= -30)
            return 'SUSPICIOUS';
        return 'MALICIOUS';
    }
}
exports.RegistryReputation = RegistryReputation;
