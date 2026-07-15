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
Object.defineProperty(exports, "__esModule", { value: true });
exports.LockfileParser = void 0;
const fs = __importStar(require("fs"));
class LockfileParser {
    detectFormat(content) {
        const trimmed = content.trim();
        if (!trimmed)
            return 'unknown';
        const firstLine = trimmed.split('\n')[0].trim();
        if (firstLine.startsWith('#')) {
            return 'yarn';
        }
        if (trimmed.startsWith('{')) {
            try {
                const parsed = JSON.parse(trimmed);
                if (parsed.packages)
                    return 'npm-v7';
                if (parsed.dependencies)
                    return 'npm-v6';
            }
            catch (_a) {
                return 'unknown';
            }
        }
        if (/^[a-zA-Z@]/.test(firstLine) && firstLine.includes('@') && firstLine.endsWith(':')) {
            return 'yarn';
        }
        return 'unknown';
    }
    parsePackageLock(content) {
        let parsed;
        try {
            parsed = JSON.parse(content);
        }
        catch (_a) {
            return { entries: [], format: 'unknown' };
        }
        if (parsed.packages && typeof parsed.packages === 'object') {
            return this.parseNpmV7(parsed);
        }
        if (parsed.dependencies && typeof parsed.dependencies === 'object') {
            return this.parseNpmV6(parsed);
        }
        return { entries: [], format: 'unknown' };
    }
    parseNpmV7(parsed) {
        const entries = [];
        for (const [key, val] of Object.entries(parsed.packages)) {
            if (key === '')
                continue;
            const info = val;
            if (!info.version)
                continue;
            const name = key.replace(/^node_modules\//, '');
            const deps = info.dependencies ? Object.keys(info.dependencies) : [];
            entries.push({
                name,
                version: info.version,
                resolved: info.resolved || '',
                integrity: info.integrity || '',
                dependencies: deps,
            });
        }
        return { entries, format: 'npm-v7' };
    }
    parseNpmV6(parsed) {
        const entries = [];
        for (const [name, val] of Object.entries(parsed.dependencies)) {
            const info = val;
            if (!info.version)
                continue;
            const deps = info.dependencies ? Object.keys(info.dependencies) : [];
            entries.push({
                name,
                version: info.version,
                resolved: info.resolved || '',
                integrity: info.integrity || '',
                dependencies: deps,
            });
        }
        return { entries, format: 'npm-v6' };
    }
    parseYarnLock(content) {
        const entries = [];
        const lines = content.split(/\r?\n/);
        let currentName = '';
        let currentVersion = '';
        let currentResolved = '';
        let currentIntegrity = '';
        let currentDeps = [];
        let inBlock = false;
        let inDeps = false;
        for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed.startsWith('#'))
                continue;
            if (!inBlock) {
                const headerMatch = line.match(/^((?:@[^/]+\/)?[^@\s]+)@[^:]*:$/);
                if (headerMatch) {
                    currentName = headerMatch[1];
                    currentVersion = '';
                    currentResolved = '';
                    currentIntegrity = '';
                    currentDeps = [];
                    inBlock = true;
                    inDeps = false;
                }
                continue;
            }
            if (trimmed === '') {
                if (currentName && currentVersion) {
                    entries.push({
                        name: currentName,
                        version: currentVersion,
                        resolved: currentResolved,
                        integrity: currentIntegrity,
                        dependencies: currentDeps,
                    });
                }
                currentName = '';
                currentVersion = '';
                currentResolved = '';
                currentIntegrity = '';
                currentDeps = [];
                inBlock = false;
                inDeps = false;
                continue;
            }
            const nextHeader = line.match(/^((?:@[^/]+\/)?[^@\s]+)@[^:]*:$/);
            if (nextHeader) {
                if (currentName && currentVersion) {
                    entries.push({
                        name: currentName,
                        version: currentVersion,
                        resolved: currentResolved,
                        integrity: currentIntegrity,
                        dependencies: currentDeps,
                    });
                }
                currentName = nextHeader[1];
                currentVersion = '';
                currentResolved = '';
                currentIntegrity = '';
                currentDeps = [];
                inDeps = false;
                continue;
            }
            const versionMatch = line.match(/^\s+version\s+"([^"]+)"/);
            if (versionMatch) {
                currentVersion = versionMatch[1];
                continue;
            }
            const resolvedMatch = line.match(/^\s+resolved\s+"([^"]+)"/);
            if (resolvedMatch) {
                currentResolved = resolvedMatch[1];
                continue;
            }
            const integrityMatch = line.match(/^\s+integrity\s+"([^"]+)"/);
            if (integrityMatch) {
                currentIntegrity = integrityMatch[1];
                continue;
            }
            if (/^\s+dependencies:$/.test(line)) {
                inDeps = true;
                continue;
            }
            if (inDeps) {
                const depMatch = line.match(/^\s{4,}(\S+)\s+"[^"]+"/);
                if (depMatch) {
                    currentDeps.push(depMatch[1]);
                    continue;
                }
            }
        }
        if (currentName && currentVersion) {
            entries.push({
                name: currentName,
                version: currentVersion,
                resolved: currentResolved,
                integrity: currentIntegrity,
                dependencies: currentDeps,
            });
        }
        return { entries, format: 'yarn' };
    }
    parse(path) {
        let content;
        try {
            content = fs.readFileSync(path, 'utf8');
        }
        catch (_a) {
            return { entries: [], format: 'unknown' };
        }
        const format = this.detectFormat(content);
        switch (format) {
            case 'npm-v6':
            case 'npm-v7':
                return this.parsePackageLock(content);
            case 'yarn':
                return this.parseYarnLock(content);
            default:
                return { entries: [], format: 'unknown' };
        }
    }
}
exports.LockfileParser = LockfileParser;
