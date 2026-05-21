"use strict";
/**
 * Sentinel Guard (v1.1)
 *
 * Provisions OS-level package manager interception via shell profile aliases.
 * Makes Sentinel ineludible — even when the user types 'npm install' directly.
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.SUPPORTED_MANAGERS = void 0;
exports.getShellProfilePath = getShellProfilePath;
exports.enableGuard = enableGuard;
exports.disableGuard = disableGuard;
exports.isGuardEnabled = isGuardEnabled;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const os = __importStar(require("os"));
exports.SUPPORTED_MANAGERS = ['npm', 'pip', 'pip3', 'yarn', 'pnpm', 'cargo', 'docker'];
function getShellProfilePath() {
    const shell = process.env.SHELL || '';
    if (shell.includes('zsh'))
        return path.join(os.homedir(), '.zshrc');
    if (shell.includes('fish'))
        return path.join(os.homedir(), '.config/fish/config.fish');
    // PowerShell (Windows)
    if (process.platform === 'win32') {
        return path.join(os.homedir(), 'Documents', 'WindowsPowerShell', 'Microsoft.PowerShell_profile.ps1');
    }
    return path.join(os.homedir(), '.bashrc');
}
function generateUnixAliases() {
    return exports.SUPPORTED_MANAGERS.map(mgr => {
        return [
            `# Sentinel Guard: ${mgr} interception`,
            `sentinel_${mgr}() {`,
            `  sentinel install ${mgr} "$@" && \\`,
            `  command ${mgr} "$@"`,
            `}`,
            `alias ${mgr}='sentinel_${mgr}'`
        ].join('\n');
    }).join('\n\n');
}
function generatePowerShellAliases() {
    const exeMap = {
        'npm': 'npm.cmd', 'yarn': 'yarn.cmd', 'pnpm': 'pnpm.cmd',
        'pip': 'pip.exe', 'pip3': 'pip3.exe',
        'cargo': 'cargo.exe', 'docker': 'docker.exe'
    };
    return exports.SUPPORTED_MANAGERS.map(mgr => {
        const exe = exeMap[mgr] || `${mgr}.exe`;
        return [
            `# Sentinel Guard: ${mgr} interception`,
            `function ${mgr} {`,
            `  sentinel install ${mgr} $args`,
            `  if ($LASTEXITCODE -eq 0) { & "${exe}" $args }`,
            `}`
        ].join('\n');
    }).join('\n\n');
}
const SENTINEL_GUARD_BLOCK_START = '# ====== SENTINEL GUARD START ======';
const SENTINEL_GUARD_BLOCK_END = '# ====== SENTINEL GUARD END ======';
function enableGuard() {
    const profilePath = getShellProfilePath();
    const isWindows = process.platform === 'win32';
    const aliases = isWindows ? generatePowerShellAliases() : generateUnixAliases();
    const guardBlock = `\n${SENTINEL_GUARD_BLOCK_START}\n${aliases}\n${SENTINEL_GUARD_BLOCK_END}\n`;
    let existing = '';
    try {
        existing = fs.readFileSync(profilePath, 'utf8');
    }
    catch (_e1) { }
    if (existing.includes(SENTINEL_GUARD_BLOCK_START)) {
        return { success: false, reason: 'Guard is already enabled.', profilePath };
    }
    const dir = path.dirname(profilePath);
    if (!fs.existsSync(dir))
        fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(profilePath, existing + guardBlock);
    return { success: true, profilePath, managers: exports.SUPPORTED_MANAGERS };
}
function disableGuard() {
    const profilePath = getShellProfilePath();
    let existing = '';
    try {
        existing = fs.readFileSync(profilePath, 'utf8');
    }
    catch (_e2) {
        return { success: false, reason: 'Shell profile not found.' };
    }
    const startIdx = existing.indexOf(SENTINEL_GUARD_BLOCK_START);
    const endIdx = existing.indexOf(SENTINEL_GUARD_BLOCK_END);
    if (startIdx === -1)
        return { success: false, reason: 'Guard is not enabled.' };
    const cleaned = existing.slice(0, startIdx) + existing.slice(endIdx + SENTINEL_GUARD_BLOCK_END.length);
    fs.writeFileSync(profilePath, cleaned.replace(/\n{3,}/g, '\n\n'));
    return { success: true, profilePath };
}
function isGuardEnabled() {
    try {
        const profilePath = getShellProfilePath();
        const content = fs.readFileSync(profilePath, 'utf8');
        return content.includes(SENTINEL_GUARD_BLOCK_START);
    }
    catch (_e3) {
        return false;
    }
}
