"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ghBridge = exports.GitHubBridge = void 0;
const child_process_1 = require("child_process");
// Whitelist-only input validators
const OWNER_REPO_REGEX = /^[a-zA-Z0-9._-]{1,100}\/[a-zA-Z0-9._-]{1,100}$/;
const PR_NUMBER_REGEX = /^[1-9][0-9]{0,9}$/;
function isValidOwnerRepo(str) {
    return OWNER_REPO_REGEX.test(str);
}
function isValidPRNumber(str) {
    return PR_NUMBER_REGEX.test(String(str));
}
function sanitizeForLog(str) {
    return str.replace(/[\u0000-\u001F\u007F-\u009F]/g, '').substring(0, 500);
}
class GitHubBridge {
    isGHInstalled() {
        try {
            const output = (0, child_process_1.execFileSync)('gh', ['--version'], {
                encoding: 'utf-8',
                timeout: 10000,
                stdio: ['pipe', 'pipe', 'pipe']
            });
            const match = output.match(/gh version ([\d.]+)/);
            return { installed: true, version: match ? match[1] : 'unknown' };
        }
        catch (_a) {
            return { installed: false };
        }
    }
    isGitInstalled() {
        try {
            const output = (0, child_process_1.execFileSync)('git', ['--version'], {
                encoding: 'utf-8',
                timeout: 10000,
                stdio: ['pipe', 'pipe', 'pipe']
            });
            const match = output.match(/git version ([\d.]+)/);
            return { installed: true, version: match ? match[1] : 'unknown' };
        }
        catch (_a) {
            return { installed: false };
        }
    }
    checkAuth() {
        var _a, _b;
        try {
            const output = (0, child_process_1.execFileSync)('gh', ['auth', 'status'], {
                encoding: 'utf-8',
                timeout: 15000,
                stdio: ['pipe', 'pipe', 'pipe']
            });
            const match = output.match(/Logged in to github\.com account (\S+)/i) ||
                output.match(/Logged in to github\.com as (\S+)/i) ||
                output.match(/account (\S+)/i);
            return { authenticated: true, username: match ? match[1] : 'Unknown' };
        }
        catch (e) {
            const err = e;
            const stderr = ((_a = err.stderr) === null || _a === void 0 ? void 0 : _a.toString()) || ((_b = err.stdout) === null || _b === void 0 ? void 0 : _b.toString()) || '';
            if (stderr.includes('Logged in')) {
                const match = stderr.match(/account (\S+)/i);
                return { authenticated: true, username: match ? match[1] : 'Unknown' };
            }
            return { authenticated: false };
        }
    }
    login() {
        return new Promise((resolve) => {
            var _a, _b;
            const ghCmd = process.platform === 'win32' ? 'gh.exe' : 'gh';
            const child = (0, child_process_1.spawn)(ghCmd, ['auth', 'login', '-w', '-p', 'https', '--skip-ssh-key'], {
                shell: false,
                stdio: ['pipe', 'pipe', 'pipe']
            });
            let output = '';
            let resolved = false;
            (_a = child.stdout) === null || _a === void 0 ? void 0 : _a.on('data', (d) => {
                const msg = d.toString();
                output += msg;
                if (msg.toLowerCase().includes('press enter')) {
                    child.stdin.write('\n');
                }
            });
            (_b = child.stderr) === null || _b === void 0 ? void 0 : _b.on('data', (d) => {
                const msg = d.toString();
                output += msg;
                if (msg.toLowerCase().includes('press enter')) {
                    child.stdin.write('\n');
                }
            });
            const timeout = setTimeout(() => {
                if (!resolved) {
                    child.kill();
                    resolve({ success: false, message: 'Authentication timed out after 60 seconds.' });
                }
            }, 60000);
            child.on('close', (code) => {
                clearTimeout(timeout);
                if (resolved)
                    return;
                resolved = true;
                if (code === 0) {
                    const auth = this.checkAuth();
                    resolve({ success: true, username: auth.username });
                }
                else {
                    resolve({ success: false, message: output || 'Login failed. Please try again.' });
                }
            });
            child.on('error', (err) => {
                clearTimeout(timeout);
                if (resolved)
                    return;
                resolved = true;
                resolve({ success: false, message: err.message });
            });
        });
    }
    listUserRepos(limit = 100) {
        try {
            const output = (0, child_process_1.execFileSync)('gh', [
                'repo', 'list',
                '--limit', String(limit),
                '--json', 'name,nameWithOwner,description,visibility,updatedAt'
            ], {
                encoding: 'utf-8',
                timeout: 30000
            });
            const repos = JSON.parse(output);
            return repos.map((r) => ({
                name: r.name,
                fullName: r.nameWithOwner,
                description: r.description || '',
                visibility: r.visibility,
                updatedAt: r.updatedAt,
            }));
        }
        catch (e) {
            console.error('Error listing repos:', sanitizeForLog(e.message));
            return [];
        }
    }
    listPRs(repoFullName) {
        if (!isValidOwnerRepo(repoFullName)) {
            console.error(`[SECURITY] Invalid owner/repo format rejected: ${sanitizeForLog(repoFullName)}`);
            return [];
        }
        try {
            const output = (0, child_process_1.execFileSync)('gh', [
                'pr', 'list',
                '--repo', repoFullName,
                '--state', 'open',
                '--limit', '10',
                '--json', 'number,title,author,updatedAt,headRefName'
            ], {
                encoding: 'utf-8',
                timeout: 10000
            });
            return JSON.parse(output);
        }
        catch (e) {
            console.error(`Error listing PRs for ${sanitizeForLog(repoFullName)}:`, sanitizeForLog(e.message));
            return [];
        }
    }
    getPRDiff(repoFullName, prNumber) {
        if (!isValidOwnerRepo(repoFullName) || !isValidPRNumber(prNumber))
            return null;
        try {
            return (0, child_process_1.execFileSync)('gh', [
                'pr', 'diff', String(prNumber),
                '--repo', repoFullName
            ], {
                encoding: 'utf-8',
                timeout: 30000,
                maxBuffer: 10 * 1024 * 1024 // 10MB
            });
        }
        catch (e) {
            console.error(`Error getting diff for PR #${prNumber}:`, sanitizeForLog(e.message));
            return null;
        }
    }
    listTodayPRs(repoFullName) {
        if (!isValidOwnerRepo(repoFullName))
            return [];
        try {
            const today = new Date().toISOString().split('T')[0];
            const output = (0, child_process_1.execFileSync)('gh', [
                'pr', 'list',
                '--repo', repoFullName,
                '--state', 'open',
                '--limit', '20',
                '--json', 'number,title,author,updatedAt,createdAt,headRefName,state,url,additions,deletions,changedFiles',
                '--search', `created:>=${today}`
            ], {
                encoding: 'utf-8',
                timeout: 15000
            });
            return JSON.parse(output);
        }
        catch (_unused) {
            return [];
        }
    }
    getDashboardStats() {
        const repos = this.listUserRepos(50);
        const repoStats = [];
        let totalOpen = 0;
        let totalToday = 0;
        for (const repo of repos) {
            try {
                const openOutput = (0, child_process_1.execFileSync)('gh', [
                    'pr', 'list',
                    '--repo', repo.fullName,
                    '--state', 'open',
                    '--limit', '30',
                    '--json', 'number,title,author,updatedAt,createdAt,headRefName,state,url,additions,deletions,changedFiles'
                ], { encoding: 'utf-8', timeout: 10000 });
                const openPRs = JSON.parse(openOutput);
                totalOpen += openPRs.length;
                const today = new Date().toISOString().split('T')[0];
                const todayPRs = openPRs.filter(pr => pr.createdAt && pr.createdAt.startsWith(today));
                totalToday += todayPRs.length;
                repoStats.push({
                    name: repo.name,
                    fullName: repo.fullName,
                    openPRs: openPRs.length,
                    todayPRs: todayPRs.length,
                    prs: openPRs
                });
            }
            catch (_e) {
                repoStats.push({ name: repo.name, fullName: repo.fullName, openPRs: 0, todayPRs: 0, prs: [] });
            }
        }
        return {
            totalRepos: repos.length,
            openPRs: totalOpen,
            todayPRs: totalToday,
            unanalyzedPRs: totalOpen, // All open PRs start as unanalyzed
            repos: repoStats
        };
    }
}
exports.GitHubBridge = GitHubBridge;
exports.ghBridge = new GitHubBridge();
