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
exports.buildOwnershipGraph = buildOwnershipGraph;
exports.parseCodeowners = parseCodeowners;
exports.groupByTeam = groupByTeam;
const child_process_1 = require("child_process");
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
function getGitAuthors(file) {
    try {
        const output = (0, child_process_1.execSync)(`git log --format="%an||%ae" -- "${file}"`, { encoding: 'utf8', timeout: 5000, windowsHide: true, cwd: process.cwd() });
        const seen = new Set();
        const authors = [];
        for (const line of output.trim().split('\n')) {
            const [name, email] = line.split('||');
            const key = `${name}|${email}`;
            if (name && email && !seen.has(key)) {
                seen.add(key);
                authors.push({ name, email });
            }
        }
        return authors;
    }
    catch (_a) {
        return [];
    }
}
function buildOwnershipGraph(findings) {
    return __awaiter(this, void 0, void 0, function* () {
        const fileToFindings = new Map();
        for (const f of findings) {
            if (!fileToFindings.has(f.file))
                fileToFindings.set(f.file, []);
            fileToFindings.get(f.file).push(f);
        }
        const authorMap = new Map();
        for (const [file, fileFindings] of fileToFindings) {
            const authors = getGitAuthors(file);
            for (const author of authors) {
                const key = `${author.name}|${author.email}`;
                if (!authorMap.has(key)) {
                    authorMap.set(key, {
                        name: author.name,
                        email: author.email,
                        files: [],
                        findingCount: 0,
                        riskScore: 0,
                        topSubcodes: new Map(),
                    });
                }
                const info = authorMap.get(key);
                if (!info.files.includes(file))
                    info.files.push(file);
                info.findingCount += fileFindings.length;
                const maxRisk = Math.max(...fileFindings.map(f => f.riskScore || 0));
                info.riskScore += maxRisk;
                for (const f of fileFindings) {
                    const sub = f.subcode || f.type;
                    info.topSubcodes.set(sub, (info.topSubcodes.get(sub) || 0) + 1);
                }
            }
        }
        const authors = Array.from(authorMap.values())
            .sort((a, b) => b.riskScore - a.riskScore);
        return {
            authors,
            totalAuthors: authors.length,
            topAuthor: authors[0] || null,
            riskiestAuthor: authors[0] || null,
        };
    });
}
function findCodeownersFile(repoPath) {
    const candidates = [
        path.join(repoPath, '.github', 'CODEOWNERS'),
        path.join(repoPath, 'docs', 'CODEOWNERS'),
        path.join(repoPath, 'CODEOWNERS'),
    ];
    for (const c of candidates) {
        if (fs.existsSync(c))
            return c;
    }
    return null;
}
function globMatch(pattern, filePath) {
    const normalizedPath = filePath.replace(/\\/g, '/');
    if (pattern.startsWith('**/')) {
        const suffix = pattern.slice(3);
        return normalizedPath.endsWith(suffix) || normalizedPath.includes('/' + suffix);
    }
    if (pattern.endsWith('/**')) {
        const prefix = pattern.slice(0, -3);
        return normalizedPath.startsWith(prefix) || normalizedPath.startsWith(prefix.replace(/\/$/, '') + '/');
    }
    if (pattern.includes('*')) {
        const regexStr = '^' + pattern
            .replace(/\\/g, '/')
            .replace(/\./g, '\\.')
            .replace(/\*\*/g, '.*')
            .replace(/\*/g, '[^/]*')
            .replace(/\?/g, '.') + '$';
        try {
            return new RegExp(regexStr).test(normalizedPath);
        }
        catch (_a) {
            return false;
        }
    }
    return normalizedPath === pattern || normalizedPath.startsWith(pattern + '/');
}
function parseCodeowners(repoPath) {
    const result = new Map();
    const filePath = findCodeownersFile(repoPath);
    if (!filePath)
        return result;
    const content = fs.readFileSync(filePath, 'utf8');
    for (const line of content.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('//'))
            continue;
        const parts = trimmed.split(/\s+/);
        if (parts.length < 2)
            continue;
        const pattern = parts[0];
        const owners = parts.slice(1).filter(o => o.startsWith('@'));
        if (owners.length > 0) {
            result.set(pattern, owners);
        }
    }
    return result;
}
function groupByTeam(ownership, repoPath) {
    const codeowners = parseCodeowners(repoPath);
    if (codeowners.size === 0)
        return [];
    const patternToFiles = new Map();
    for (const [pattern] of codeowners) {
        const matchedFiles = [];
        for (const author of ownership.authors) {
            for (const file of author.files) {
                if (globMatch(pattern, file) && !matchedFiles.includes(file)) {
                    matchedFiles.push(file);
                }
            }
        }
        if (matchedFiles.length > 0) {
            patternToFiles.set(pattern, matchedFiles);
        }
    }
    const teamMap = new Map();
    for (const [pattern, files] of patternToFiles) {
        const owners = codeowners.get(pattern);
        const ownerStr = owners.join(', ');
        if (!teamMap.has(ownerStr)) {
            const members = owners.map(o => o.startsWith('@') ? o : o);
            teamMap.set(ownerStr, {
                name: ownerStr,
                members,
                files: [],
                findingCount: 0,
                riskScore: 0,
            });
        }
        const team = teamMap.get(ownerStr);
        for (const file of files) {
            if (!team.files.includes(file)) {
                team.files.push(file);
            }
        }
    }
    for (const team of teamMap.values()) {
        const matchedFiles = team.files;
        let findingCount = 0;
        let riskScore = 0;
        for (const author of ownership.authors) {
            for (const file of author.files) {
                if (matchedFiles.includes(file)) {
                    findingCount += author.findingCount;
                    riskScore += author.riskScore;
                }
            }
        }
        team.findingCount = findingCount;
        team.riskScore = riskScore;
    }
    return Array.from(teamMap.values()).sort((a, b) => b.riskScore - a.riskScore);
}
