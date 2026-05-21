import { execFileSync, spawn } from 'child_process';

// Whitelist-only input validators
const OWNER_REPO_REGEX = /^[a-zA-Z0-9._-]{1,100}\/[a-zA-Z0-9._-]{1,100}$/;
const PR_NUMBER_REGEX = /^[1-9][0-9]{0,9}$/;

function isValidOwnerRepo(str: string): boolean {
  return OWNER_REPO_REGEX.test(str);
}

function isValidPRNumber(str: string | number): boolean {
  return PR_NUMBER_REGEX.test(String(str));
}

function sanitizeForLog(str: string): string {
  return str.replace(/[\u0000-\u001F\u007F-\u009F]/g, '').substring(0, 500);
}

export interface UserRepo {
  name: string;
  fullName: string;
  description: string;
  visibility: string;
  updatedAt: string;
}

export interface PullRequest {
  number: number;
  title: string;
  author?: { login: string };
  updatedAt: string;
  createdAt: string;
  headRefName?: string;
  state?: string;
  url?: string;
  additions?: number;
  deletions?: number;
  changedFiles?: number;
}

export interface DashboardStats {
  totalRepos: number;
  openPRs: number;
  todayPRs: number;
  unanalyzedPRs: number;
  repos: Array<{
    name: string;
    fullName: string;
    openPRs: number;
    todayPRs: number;
    prs: PullRequest[];
  }>;
}

export class GitHubBridge {
  isGHInstalled(): { installed: boolean; version?: string } {
    try {
      const output = execFileSync('gh', ['--version'], {
        encoding: 'utf-8',
        timeout: 10000,
        stdio: ['pipe', 'pipe', 'pipe']
      });
      const match = output.match(/gh version ([\d.]+)/);
      return { installed: true, version: match ? match[1] : 'unknown' };
    } catch {
      return { installed: false };
    }
  }

  isGitInstalled(): { installed: boolean; version?: string } {
    try {
      const output = execFileSync('git', ['--version'], {
        encoding: 'utf-8',
        timeout: 10000,
        stdio: ['pipe', 'pipe', 'pipe']
      });
      const match = output.match(/git version ([\d.]+)/);
      return { installed: true, version: match ? match[1] : 'unknown' };
    } catch {
      return { installed: false };
    }
  }

  checkAuth(): { authenticated: boolean; username?: string } {
    try {
      const output = execFileSync('gh', ['auth', 'status'], {
        encoding: 'utf-8',
        timeout: 15000,
        stdio: ['pipe', 'pipe', 'pipe']
      });
      const match = output.match(/Logged in to github\.com account (\S+)/i) ||
                    output.match(/Logged in to github\.com as (\S+)/i) ||
                    output.match(/account (\S+)/i);
      return { authenticated: true, username: match ? match[1] : 'Unknown' };
    } catch (e: unknown) {
      const err = e as { stderr?: string; stdout?: string };
      const stderr = err.stderr?.toString() || err.stdout?.toString() || '';
      if (stderr.includes('Logged in')) {
        const match = stderr.match(/account (\S+)/i);
        return { authenticated: true, username: match ? match[1] : 'Unknown' };
      }
      return { authenticated: false };
    }
  }

  login(): Promise<{ success: boolean; username?: string; message?: string }> {
    return new Promise((resolve) => {
      const ghCmd = process.platform === 'win32' ? 'gh.exe' : 'gh';
      const child = spawn(ghCmd, ['auth', 'login', '-w', '-p', 'https', '--skip-ssh-key'], {
        shell: false,
        stdio: ['pipe', 'pipe', 'pipe']
      });

      let output = '';
      let resolved = false;

      child.stdout?.on('data', (d) => {
        const msg = d.toString();
        output += msg;
        if (msg.toLowerCase().includes('press enter')) {
          child.stdin.write('\n');
        }
      });

      child.stderr?.on('data', (d) => { 
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
        if (resolved) return;
        resolved = true;
        if (code === 0) {
          const auth = this.checkAuth();
          resolve({ success: true, username: auth.username });
        } else {
          resolve({ success: false, message: output || 'Login failed. Please try again.' });
        }
      });

      child.on('error', (err) => {
        clearTimeout(timeout);
        if (resolved) return;
        resolved = true;
        resolve({ success: false, message: err.message });
      });
    });
  }

  listUserRepos(limit = 100): UserRepo[] {
    try {
      const output = execFileSync('gh', [
        'repo', 'list',
        '--limit', String(limit),
        '--json', 'name,nameWithOwner,description,visibility,updatedAt'
      ], {
        encoding: 'utf-8',
        timeout: 30000
      });
      const repos: Array<Record<string, unknown>> = JSON.parse(output);
      return repos.map((r) => ({
        name: r.name as string,
        fullName: r.nameWithOwner as string,
        description: (r.description as string) || '',
        visibility: r.visibility as string,
        updatedAt: r.updatedAt as string,
      }));
    } catch (e: unknown) {
      console.error('Error listing repos:', sanitizeForLog((e as Error).message));
      return [];
    }
  }

  listPRs(repoFullName: string): PullRequest[] {
    if (!isValidOwnerRepo(repoFullName)) {
      console.error(`[SECURITY] Invalid owner/repo format rejected: ${sanitizeForLog(repoFullName)}`);
      return [];
    }
    try {
      const output = execFileSync('gh', [
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
    } catch (e: unknown) {
      console.error(`Error listing PRs for ${sanitizeForLog(repoFullName)}:`, sanitizeForLog((e as Error).message));
      return [];
    }
  }

  getPRDiff(repoFullName: string, prNumber: number): string | null {
    if (!isValidOwnerRepo(repoFullName) || !isValidPRNumber(prNumber)) return null;
    try {
      return execFileSync('gh', [
        'pr', 'diff', String(prNumber),
        '--repo', repoFullName
      ], {
        encoding: 'utf-8',
        timeout: 30000,
        maxBuffer: 10 * 1024 * 1024 // 10MB
      });
    } catch (e: unknown) {
      console.error(`Error getting diff for PR #${prNumber}:`, sanitizeForLog((e as Error).message));
      return null;
    }
  }

  listTodayPRs(repoFullName: string): PullRequest[] {
    if (!isValidOwnerRepo(repoFullName)) return [];
    try {
      const today = new Date().toISOString().split('T')[0];
      const output = execFileSync('gh', [
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
    } catch (_unused: unknown) {
      return [];
    }
  }

  getDashboardStats(): DashboardStats {
    const repos = this.listUserRepos(50);
    const repoStats: DashboardStats['repos'] = [];
    let totalOpen = 0;
    let totalToday = 0;

    for (const repo of repos) {
      try {
        const openOutput = execFileSync('gh', [
          'pr', 'list',
          '--repo', repo.fullName,
          '--state', 'open',
          '--limit', '30',
          '--json', 'number,title,author,updatedAt,createdAt,headRefName,state,url,additions,deletions,changedFiles'
        ], { encoding: 'utf-8', timeout: 10000 });
        const openPRs: PullRequest[] = JSON.parse(openOutput);
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
      } catch (_e: unknown) {
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

export const ghBridge = new GitHubBridge();
