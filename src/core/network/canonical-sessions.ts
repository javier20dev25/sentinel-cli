'use strict';

import { SessionProfile, SessionEnvironment, SessionPrivateMetadata } from './types';
import * as os from 'os';
import * as child_process from 'child_process';

// ─── Canonical Session Profiles ─────────────────────────────────────

export const CANONICAL_PROFILES: SessionProfile[] = [
  // Benign — Git
  { id: 'git-clone', category: 'benign', tool: 'git', action: 'clone', expectedRisk: 'LOW', description: 'Clone a public repository', tags: ['git', 'clone', 'network'] },
  { id: 'git-fetch', category: 'benign', tool: 'git', action: 'fetch', expectedRisk: 'LOW', description: 'Fetch from remote', tags: ['git', 'fetch', 'network'] },
  { id: 'git-pull', category: 'benign', tool: 'git', action: 'merge', expectedRisk: 'LOW', description: 'Pull with merge', tags: ['git', 'pull', 'network'] },
  { id: 'git-rebase', category: 'benign', tool: 'git', action: 'other', expectedRisk: 'LOW', description: 'Interactive rebase', tags: ['git', 'rebase'] },
  { id: 'git-push', category: 'benign', tool: 'git', action: 'other', expectedRisk: 'LOW', description: 'Push to remote', tags: ['git', 'push', 'network'] },
  { id: 'git-log', category: 'benign', tool: 'git', action: 'log', expectedRisk: 'LOW', description: 'View commit history', tags: ['git', 'log'] },
  { id: 'git-status', category: 'benign', tool: 'git', action: 'other', expectedRisk: 'LOW', description: 'Check working tree status', tags: ['git', 'status'] },
  { id: 'git-diff', category: 'benign', tool: 'git', action: 'other', expectedRisk: 'LOW', description: 'View uncommitted changes', tags: ['git', 'diff'] },

  // Benign — Package managers
  { id: 'npm-install', category: 'benign', tool: 'npm', action: 'install', expectedRisk: 'LOW', description: 'Install npm dependencies', tags: ['npm', 'install', 'network'] },
  { id: 'npm-test', category: 'benign', tool: 'npm', action: 'test', expectedRisk: 'LOW', description: 'Run npm test', tags: ['npm', 'test'] },
  { id: 'cargo-build', category: 'benign', tool: 'cargo', action: 'build', expectedRisk: 'LOW', description: 'Build Rust project', tags: ['cargo', 'build'] },
  { id: 'go-mod-download', category: 'benign', tool: 'go', action: 'download', expectedRisk: 'LOW', description: 'Download Go modules', tags: ['go', 'download', 'network'], requires: ['go'] },

  // Benign — Build & infra
  { id: 'docker-build', category: 'benign', tool: 'docker', action: 'build', expectedRisk: 'LOW', description: 'Build Docker image', tags: ['docker', 'build', 'network'], requires: ['docker'] },
  { id: 'docker-pull', category: 'benign', tool: 'docker', action: 'pull', expectedRisk: 'LOW', description: 'Pull Docker image', tags: ['docker', 'pull', 'network'], requires: ['docker'] },
  { id: 'terraform-plan', category: 'benign', tool: 'terraform', action: 'plan', expectedRisk: 'LOW', description: 'Terraform plan', tags: ['terraform', 'plan'], requires: ['terraform'] },
  { id: 'terraform-apply', category: 'benign', tool: 'terraform', action: 'apply', expectedRisk: 'LOW', description: 'Terraform apply', tags: ['terraform', 'apply', 'network'], requires: ['terraform'] },

  // IA — AI coding tools
  { id: 'cursor-edit', category: 'ia', tool: 'cursor', action: 'edit', expectedRisk: 'MEDIUM', description: 'Cursor AI editing code', tags: ['cursor', 'ai', 'edit'] },
  { id: 'cursor-refactor', category: 'ia', tool: 'cursor', action: 'refactor', expectedRisk: 'MEDIUM', description: 'Cursor AI refactoring across files', tags: ['cursor', 'ai', 'refactor', 'mass_read'] },
  { id: 'copilot-chat', category: 'ia', tool: 'copilot', action: 'chat', expectedRisk: 'LOW', description: 'GitHub Copilot Chat session', tags: ['copilot', 'chat', 'network'] },
  { id: 'claude-code', category: 'ia', tool: 'claude-code', action: 'code', expectedRisk: 'MEDIUM', description: 'Claude Code CLI coding session', tags: ['claude', 'code', 'ai'] },

  // Suspicious — Recon
  { id: 'grep-secrets', category: 'suspicious', tool: 'grep', action: 'search', expectedRisk: 'MEDIUM', description: 'Grep for secret patterns in codebase', tags: ['grep', 'recon', 'secrets'] },
  { id: 'read-env', category: 'suspicious', tool: 'cat', action: 'read', expectedRisk: 'MEDIUM', description: 'Read .env files across project', tags: ['env', 'read', 'secrets'] },
  { id: 'read-git', category: 'suspicious', tool: 'git', action: 'inspect', expectedRisk: 'MEDIUM', description: 'Inspect .git directory contents', tags: ['git', 'inspect', 'recon'] },
  { id: 'read-ssh', category: 'suspicious', tool: 'cat', action: 'read', expectedRisk: 'HIGH', description: 'Read SSH private keys', tags: ['ssh', 'read', 'secrets'] },
  { id: 'mass-file-read', category: 'suspicious', tool: 'find', action: 'read', expectedRisk: 'HIGH', description: 'Read many files rapidly (embedding-like)', tags: ['mass_read', 'recon', 'ai'] },

  // Malicious — Exfiltration
  { id: 'exfil-pastebin', category: 'malicious', tool: 'curl', action: 'upload', expectedRisk: 'CRITICAL', description: 'Upload data to Pastebin', tags: ['exfil', 'pastebin', 'network'] },
  { id: 'exfil-gist', category: 'malicious', tool: 'gh', action: 'create', expectedRisk: 'CRITICAL', description: 'Create GitHub Gist with exfiltrated data', tags: ['exfil', 'gist', 'network'] },
  { id: 'exfil-discord', category: 'malicious', tool: 'curl', action: 'webhook', expectedRisk: 'CRITICAL', description: 'POST to Discord webhook', tags: ['exfil', 'discord', 'webhook'] },
  { id: 'exfil-dns', category: 'malicious', tool: 'dig', action: 'tunnel', expectedRisk: 'CRITICAL', description: 'DNS tunneling exfiltration', tags: ['exfil', 'dns', 'tunnel'] },
  { id: 'exfil-git-bundle', category: 'malicious', tool: 'git', action: 'bundle', expectedRisk: 'CRITICAL', description: 'Git bundle + upload of entire repo', tags: ['exfil', 'git', 'bundle'] },
  { id: 'exfil-tar-git', category: 'malicious', tool: 'tar', action: 'archive', expectedRisk: 'CRITICAL', description: 'Tar .git directory and upload', tags: ['exfil', 'tar', 'git'] },
];

// ─── Environment Snapshot ───────────────────────────────────────────

export function captureEnvironment(): SessionEnvironment {
  let gitVersion = '';
  try {
    gitVersion = child_process.execSync('git --version', { encoding: 'utf-8', timeout: 3000, stdio: ['pipe', 'pipe', 'ignore'] }).trim();
  } catch {}

  return {
    os: os.platform(),
    osVersion: os.release(),
    cpu: os.cpus()[0]?.model ?? 'unknown',
    memoryGb: Math.round(os.totalmem() / (1024 * 1024 * 1024) * 10) / 10,
    nodeVersion: process.version,
    gitVersion,
    editor: process.env.EDITOR || process.env.VISUAL || 'unknown',
    sentinelVersion: '1.0.0',
    policyVersion: '1.0.0',
    corpusVersion: '1.0.0',
    recordedAt: new Date().toISOString(),
  };
}

export function capturePrivateMetadata(): SessionPrivateMetadata {
  return {
    hostname: os.hostname(),
    username: os.userInfo().username,
    workingDirectory: process.cwd(),
  };
}

export function findProfile(id: string): SessionProfile | undefined {
  return CANONICAL_PROFILES.find(p => p.id === id);
}
