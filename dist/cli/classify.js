"use strict";
/**
 * Sentinel Classified (v1.1)
 *
 * Protects sensitive files by marking them as "Classified" and enforcing
 * local pre-commit hooks to prevent exfiltration.
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
exports.readClassifiedDb = readClassifiedDb;
exports.saveClassifiedDb = saveClassifiedDb;
exports.findLocalProjects = findLocalProjects;
exports.getProjectFiles = getProjectFiles;
exports.installPreCommitHook = installPreCommitHook;
exports.checkClassifiedHook = checkClassifiedHook;
exports.handleClassifiedMenu = handleClassifiedMenu;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const os = __importStar(require("os"));
const child_process_1 = require("child_process");
function getSentinelGlobalDir() {
    const dir = path.join(os.homedir(), '.sentinel');
    if (!fs.existsSync(dir))
        fs.mkdirSync(dir, { recursive: true });
    return dir;
}
function getClassifiedDbPath() {
    return path.join(getSentinelGlobalDir(), 'classified.json');
}
function readClassifiedDb() {
    const file = getClassifiedDbPath();
    if (!fs.existsSync(file))
        return {};
    try {
        return JSON.parse(fs.readFileSync(file, 'utf8'));
    }
    catch (_a) {
        return {};
    }
}
function saveClassifiedDb(db) {
    const normalizedDb = {};
    for (const repo in db) {
        const normalizedRepo = path.resolve(repo).replace(/\\/g, '/');
        normalizedDb[normalizedRepo] = db[repo];
    }
    fs.writeFileSync(getClassifiedDbPath(), JSON.stringify(normalizedDb, null, 2), 'utf8');
}
/**
 * Finds local git repos up to depth 2 in common directories.
 */
function findLocalProjects() {
    const baseDirs = [
        process.cwd(),
        path.join(os.homedir(), 'Desktop'),
        path.join(os.homedir(), 'Documents')
    ];
    const repos = new Set();
    function scan(dir, depth) {
        if (depth < 0)
            return;
        try {
            const items = fs.readdirSync(dir, { withFileTypes: true });
            const isGit = items.some(i => i.isDirectory() && i.name === '.git');
            if (isGit) {
                repos.add(dir);
                return;
            }
            for (const item of items) {
                if (item.isDirectory() && !item.name.startsWith('.') && item.name !== 'node_modules') {
                    scan(path.join(dir, item.name), depth - 1);
                }
            }
        }
        catch (_e) { }
    }
    baseDirs.forEach(d => { if (fs.existsSync(d))
        scan(d, 2); });
    return Array.from(repos);
}
function getProjectFiles(dir) {
    const files = [];
    function scan(currentPath, relPath = '') {
        try {
            const items = fs.readdirSync(currentPath, { withFileTypes: true });
            for (const item of items) {
                if (item.name === '.git' || item.name === 'node_modules')
                    continue;
                const fullPath = path.join(currentPath, item.name);
                const rel = path.join(relPath, item.name).replace(/\\/g, '/');
                // Noise reduction: Ignore test, documentation, and example folders
                const lowerRel = rel.toLowerCase();
                if (lowerRel.includes('/test/') || lowerRel.includes('/example/') ||
                    lowerRel.includes('/benchmark/') || lowerRel.includes('/docs/') ||
                    lowerRel.includes('\\test\\') || lowerRel.includes('\\example\\') ||
                    lowerRel.includes('\\benchmark\\') || lowerRel.includes('\\docs\\')) {
                    continue;
                }
                if (item.isDirectory()) {
                    scan(fullPath, rel);
                }
                else {
                    files.push(rel);
                }
            }
        }
        catch (_e2) { }
    }
    scan(dir);
    return files;
}
function installPreCommitHook(repoPath, lang = 'en') {
    const hooksDir = path.join(repoPath, '.git', 'hooks');
    if (!fs.existsSync(hooksDir))
        return false;
    const hookPath = path.join(hooksDir, 'pre-commit');
    let existingHook = '';
    if (fs.existsSync(hookPath)) {
        existingHook = fs.readFileSync(hookPath, 'utf8');
        if (existingHook.includes('SENTINEL CLASSIFIED FILE PROTECTOR')) {
            const msg = lang === 'es' ? '[Sentinel] Gancho pre-commit ya instalado.' : '[Sentinel] Pre-commit hook already installed.';
            console.log('\x1b[33m' + msg + '\x1b[0m');
            return true;
        }
    }
    const hookScript = `#!/bin/sh
# SENTINEL CLASSIFIED FILE PROTECTOR
# Generated by Sentinel Hub

echo "[Sentinel] Analyzing staged files..."
sentinel check-classified "$PWD" || exit 1

${existingHook.startsWith('#!') ? existingHook.split('\n').slice(1).join('\n') : existingHook}
`;
    fs.writeFileSync(hookPath, hookScript, { mode: 0o755 });
    return true;
}
function checkClassifiedHook(repoPath) {
    const db = readClassifiedDb();
    const normalizedRepo = path.resolve(repoPath).replace(/\\/g, '/').toLowerCase();
    // Find matching key in DB
    const matchingKey = Object.keys(db).find(k => path.resolve(k).replace(/\\/g, '/').toLowerCase() === normalizedRepo);
    const classified = matchingKey ? db[matchingKey] : [];
    if (classified.length === 0)
        return 0;
    try {
        const out = (0, child_process_1.spawnSync)('git', ['diff', '--cached', '--name-only'], { cwd: repoPath, encoding: 'utf8' });
        if (!out.stdout)
            return 0;
        const staged = out.stdout.split('\n').map(s => s.trim()).filter(s => s.length > 0);
        const violations = staged.filter(s => classified.includes(s));
        if (violations.length > 0) {
            console.log('\x1b[41m\x1b[37m\n 🚨 FATAL SECURITY BREACH: CLASSIFIED DATA EXFILTRATION PREVENTED \x1b[0m');
            console.log('\x1b[31m\nSentinel Firewall has blocked this commit because it contains highly sensitive classified files:\n\x1b[0m');
            violations.forEach(v => console.log(`  ■ ${v}`));
            console.log('\x1b[33m\nTo commit these files, declassify them via the Sentinel Hub first.\x1b[0m');
            console.log('\x1b[2mRun: sentinel hub -> 4. Documentos Clasificados\n\x1b[0m');
            return 1;
        }
        console.log('\x1b[32m[Sentinel] All staged files cleared.\x1b[0m');
        return 0;
    }
    catch (_e3) {
        return 0;
    }
}
const pc = __importStar(require("picocolors"));
function handleClassifiedMenu(lang, askQuestion) {
    return __awaiter(this, void 0, void 0, function* () {
        console.clear();
        console.log(pc.magenta(pc.bold('⬡ '.repeat(20))));
        process.stdout.write(pc.magenta(pc.bold('⬡ ')));
        process.stdout.write(pc.cyan(pc.bold('    S E N T I N E L   C L A S S I F I E D   ')));
        console.log(pc.magenta(pc.bold('⬡ ')));
        console.log(pc.magenta(pc.bold('⬡ '.repeat(20))));
        console.log(pc.cyan('\n? ') + pc.bold(lang === 'es' ? 'Buscando proyectos locales...' : 'Scanning for local projects...'));
        const projects = findLocalProjects();
        if (projects.length === 0) {
            console.log(pc.red(lang === 'es' ? 'No se encontraron proyectos locales.' : 'No local projects found.'));
            yield askQuestion(pc.dim('\nPress Enter to return...'));
            return;
        }
        projects.forEach((p, i) => {
            console.log(pc.blue('  │ ') + pc.cyan(`[${i + 1}]`) + ` ${p}`);
        });
        console.log(pc.blue('  │ ') + pc.cyan(`[0]`) + ` 🔙 Cancel`);
        const projIdxStr = yield askQuestion(pc.blue('  ❯ ') + pc.bold('Project ID > '));
        const projIdx = parseInt(projIdxStr) - 1;
        if (projIdx === -1)
            return;
        if (isNaN(projIdx) || projIdx < 0 || projIdx >= projects.length)
            return;
        const selectedProj = projects[projIdx];
        while (true) {
            console.clear();
            console.log(pc.cyan('? ') + pc.bold(lang === 'es' ? 'Gestión de Archivos en:' : 'File Management in:') + ' ' + pc.white(selectedProj));
            const db = readClassifiedDb();
            const classifiedInProj = db[selectedProj] || [];
            console.log(pc.dim('\n  ' + (lang === 'es' ? 'Archivos actuales:' : 'Current files:')));
            const files = getProjectFiles(selectedProj);
            files.slice(0, 50).forEach((f, i) => {
                const isClassified = classifiedInProj.includes(f);
                const prefix = isClassified ? pc.bgRed(pc.white(' CLASSIFIED ')) : pc.dim(' public     ');
                console.log(pc.blue('  │ ') + pc.cyan(`[${String(i + 1).padStart(2, ' ')}]`) + ` ${prefix} ${f}`);
            });
            if (files.length > 50)
                console.log(pc.dim(`  │ ... and ${files.length - 50} more files.`));
            console.log(pc.blue('\n  ❯ ') + pc.bold(lang === 'es' ? 'Escribe el número del archivo para alternar clasificación (o "0" para salir): ' : 'Type file number to toggle classification (or "0" to exit): '));
            const fileIdxStr = yield askQuestion(pc.blue('  > '));
            const fileIdx = parseInt(fileIdxStr) - 1;
            if (fileIdx === -1)
                break;
            if (isNaN(fileIdx) || fileIdx < 0 || fileIdx >= files.length)
                continue;
            const selectedFile = files[fileIdx];
            if (classifiedInProj.includes(selectedFile)) {
                db[selectedProj] = classifiedInProj.filter(f => f !== selectedFile);
                console.log(pc.green(`\n✔ ${selectedFile} un-classified.`));
            }
            else {
                db[selectedProj] = [...classifiedInProj, selectedFile];
                console.log(pc.red(`\n🔒 ${selectedFile} CLASSIFIED. It will be blocked from commits.`));
            }
            saveClassifiedDb(db);
            installPreCommitHook(selectedProj, lang);
            yield new Promise(r => setTimeout(r, 800));
        }
    });
}
