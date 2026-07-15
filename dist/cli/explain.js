"use strict";
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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.renderExplain = renderExplain;
exports.explainFiles = explainFiles;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const lite_scanner_1 = require("../core/lite/lite_scanner");
const agency_score_1 = require("../core/agency_score");
const picocolors_1 = __importDefault(require("picocolors"));
function walkDir(dir) {
    const files = [];
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            files.push(...walkDir(fullPath));
        }
        else {
            files.push(fullPath);
        }
    }
    return files;
}
function colorForScore(score) {
    if (score >= 70)
        return picocolors_1.default.red;
    if (score >= 30)
        return picocolors_1.default.yellow;
    return picocolors_1.default.green;
}
function colorForVerdict(verdict) {
    if (verdict === 'BLOCK')
        return picocolors_1.default.red;
    if (verdict === 'REVIEW')
        return picocolors_1.default.yellow;
    return picocolors_1.default.green;
}
function renderScoreBar(score) {
    const filled = Math.round(score / 10);
    const empty = 10 - filled;
    const color = colorForScore(score);
    return color('█'.repeat(filled)) + picocolors_1.default.dim('░'.repeat(empty));
}
function renderExplain(result, filePaths) {
    const lines = [];
    const scoreColor = colorForScore(result.agencyScore);
    const verdictColor = colorForVerdict(result.verdict);
    lines.push('');
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('  ═══════════════════════════════════════════════')));
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('   WHY BLOCK? — SENTINEL EXPLAIN')));
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('  ═══════════════════════════════════════════════')));
    lines.push('');
    lines.push(`  ${picocolors_1.default.bold('Files scanned:')} ${picocolors_1.default.cyan(String(filePaths.length))}`);
    lines.push(`  ${picocolors_1.default.bold('Total findings:')} ${picocolors_1.default.cyan(String(result.totalFindings))}` +
        (result.criticalCount > 0 ? `  ${picocolors_1.default.red(`${result.criticalCount} critical`)}` : '') +
        (result.highCount > 0 ? `  ${picocolors_1.default.yellow(`${result.highCount} high`)}` : ''));
    lines.push('');
    lines.push(`  ${picocolors_1.default.bold('Agency Score')}`);
    lines.push(`    ${picocolors_1.default.bold(scoreColor(String(result.agencyScore)))}/100  ${renderScoreBar(result.agencyScore)}`);
    lines.push(`    ${picocolors_1.default.bold('Blast Radius:')} ${scoreColor(result.blastRadius)}`);
    lines.push(`    ${picocolors_1.default.bold('Verdict:')} ${verdictColor(picocolors_1.default.bold(result.verdict))}  ${result.verdict === 'BLOCK' ? picocolors_1.default.dim('(threshold: 70)') : result.verdict === 'REVIEW' ? picocolors_1.default.dim('(threshold: 30)') : ''}`);
    lines.push('');
    if (result.drivers.length > 0) {
        lines.push(picocolors_1.default.white(picocolors_1.default.bold('  Drivers (ranked by contribution):')));
        lines.push('');
        for (const driver of result.drivers) {
            const contribColor = driver.contribution >= 70 ? picocolors_1.default.red : driver.contribution >= 30 ? picocolors_1.default.yellow : picocolors_1.default.white;
            const location = driver.file ? picocolors_1.default.dim(`${driver.file}:${driver.line}`) : '';
            lines.push(`    ${contribColor(String(driver.contribution).padStart(3))}  ${picocolors_1.default.cyan(driver.subcode.padEnd(12))}  ${picocolors_1.default.white(driver.title.padEnd(40))}  ${location}`);
        }
        lines.push('');
    }
    if (result.correlations.length > 0) {
        lines.push(picocolors_1.default.white(picocolors_1.default.bold('  Correlations (cross-pattern signals):')));
        lines.push('');
        for (const corr of result.correlations) {
            lines.push(`    ${picocolors_1.default.magenta(String(corr.bonus).padStart(3))}  ${picocolors_1.default.dim(corr.description)}`);
            if (corr.involved.length > 0) {
                lines.push(`         ${picocolors_1.default.dim('→')} ${picocolors_1.default.dim(corr.involved.join(', '))}`);
            }
        }
        lines.push('');
    }
    if (result.recommendation && result.recommendation !== 'No action required') {
        lines.push(picocolors_1.default.white(picocolors_1.default.bold('  Recommendation:')));
        lines.push('');
        const steps = result.recommendation.split('; ');
        for (const step of steps) {
            lines.push(`    ${picocolors_1.default.cyan('▸')} ${step}`);
        }
        lines.push('');
    }
    return lines.join('\n');
}
function explainFiles(targetPaths) {
    const scanner = new lite_scanner_1.LiteScanner();
    const allFindings = [];
    const scannedFiles = [];
    for (const target of targetPaths) {
        const absPath = path.resolve(target);
        if (!fs.existsSync(absPath)) {
            console.error(picocolors_1.default.red(`  Error: path not found: ${target}`));
            continue;
        }
        const filesToScan = fs.statSync(absPath).isDirectory() ? walkDir(absPath) : [absPath];
        for (const file of filesToScan) {
            try {
                const content = fs.readFileSync(file, 'utf8');
                const relPath = path.relative(process.cwd(), file);
                const result = scanner.scanFileContent(relPath, content);
                allFindings.push(...result.findings);
                scannedFiles.push(relPath);
            }
            catch (_a) {
                // skip binary files
            }
        }
    }
    const result = (0, agency_score_1.calculateAgencyScore)(allFindings);
    return { result, files: scannedFiles };
}
