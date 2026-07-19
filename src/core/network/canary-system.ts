'use strict';

import * as fs from 'fs';
import * as path from 'path';
import { CanaryConfig, CanaryEvent, FileAccessEvent, generateId } from './types';

const DECOY_FILE_NAMES = [
  'customer_data_2026_q2.csv',
  'api_keys_internal.json',
  'database_dump_backup.sql',
  'company_secrets.txt',
  'vpn_credentials.ovpn',
  'ssh_private_bastion.key',
  'github_token_recovery.md',
  'aws_credentials_prod.json',
  'master_decryption_key.asc',
  'board_minutes_confidential.pdf',
  'contract_nda_signed.pdf',
  'employee_salary_export.xlsx',
  'prod_env_backup.env',
  'kubeconfig_prod_cluster.yaml',
  'saml_certificate_pkcs12.p12',
];

const FAKE_SECRET_PATTERNS = [
  'sk-live-', 'sk-proj-', 'ghp_', 'gho_', 'AKIA',
  '-----BEGIN RSA PRIVATE KEY-----',
  '-----BEGIN OPENSSH PRIVATE KEY-----',
  'api_key = "', 'password = "', 'secret = "',
  'token = "', 'jdbc:mysql://', 'mongodb+srv://',
];

const SENTINEL_CANARY_MARKER = 'SENTINEL_CANARY_TOKEN_';

export class CanarySystem {
  private config: CanaryConfig;
  private deployedFiles: Map<string, { path: string; hash: string; content: string }> = new Map();
  private canaryEvents: CanaryEvent[] = [];

  constructor(config: CanaryConfig) {
    this.config = config;
  }

  registerMockCanary(name: string, filePath: string, content: string): void {
    this.deployedFiles.set(name, {
      path: filePath,
      hash: this.hashContent(content),
      content,
    });
  }

  deployCanaries(workspacePath: string): void {
    if (!this.config.enabled) return;
    this.deployDecoyFiles(workspacePath);
    if (this.config.fakeSecrets) this.deployFakeSecrets(workspacePath);
    if (this.config.contaminatedGitHistory) this.deployContaminatedGit(workspacePath);
  }

  private deployDecoyFiles(workspacePath: string): void {
    const decoyDir = path.join(workspacePath, '.sentinel', 'canaries');
    if (!fs.existsSync(decoyDir)) {
      fs.mkdirSync(decoyDir, { recursive: true });
    }

    for (const name of DECOY_FILE_NAMES.slice(0, 5)) {
      const filePath = path.join(decoyDir, name);
      if (fs.existsSync(filePath)) continue;

      const marker = `${SENTINEL_CANARY_MARKER}${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
      const content = this.generateDecoyContent(name, marker);
      fs.writeFileSync(filePath, content, 'utf8');

      const hash = this.hashContent(content);
      this.deployedFiles.set(name, { path: filePath, hash, content });
    }
  }

  private deployFakeSecrets(workspacePath: string): void {
    const secretsPath = path.join(workspacePath, '.sentinel', 'canaries', '.secrets.env');
    if (fs.existsSync(secretsPath)) return;

    const marker = `${SENTINEL_CANARY_MARKER}${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
    const content = [
      '# Sentinel Canary — Do not remove',
      `CANARY_MARKER=${marker}`,
      '',
      '# FAKE PRODUCTION CREDENTIALS — DO NOT USE',
      `AWS_ACCESS_KEY_ID=AKIA${Math.random().toString(36).toUpperCase().substring(2, 18)}`,
      `AWS_SECRET_ACCESS_KEY=${Math.random().toString(36).substring(2, 40)}`,
      `GITHUB_TOKEN=ghp_${Math.random().toString(36).substring(2, 38)}`,
      `OPENAI_API_KEY=sk-live-${Math.random().toString(36).substring(2, 48)}`,
      `DB_PASSWORD=${Math.random().toString(36).substring(2, 24)}`,
      `SSH_PRIVATE_KEY=-----BEGIN OPENSSH PRIVATE KEY-----\n${Buffer.from(Math.random().toString(36).repeat(10)).toString('base64')}\n-----END OPENSSH PRIVATE KEY-----`,
    ].join('\n');

    fs.writeFileSync(secretsPath, content, 'utf8');
    const hash = this.hashContent(content);
    this.deployedFiles.set('.secrets.env', { path: secretsPath, hash, content: marker });
  }

  private deployContaminatedGit(workspacePath: string): void {
    const gitDir = path.join(workspacePath, '.git');
    if (!fs.existsSync(gitDir)) return;

    const canaryGitPath = path.join(workspacePath, '.sentinel', 'canaries', '.git_canary_commit');
    if (fs.existsSync(canaryGitPath)) return;

    const marker = `${SENTINEL_CANARY_MARKER}${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
    fs.writeFileSync(canaryGitPath, marker, 'utf8');
    this.deployedFiles.set('.git_canary_commit', {
      path: canaryGitPath,
      hash: this.hashContent(marker),
      content: marker,
    });
  }

  checkFileAccess(event: FileAccessEvent, sessionId: string): CanaryEvent | null {
    const eventPath = path.resolve(event.filePath).toLowerCase();
    const eventBase = path.basename(eventPath);

    for (const [name, deployed] of this.deployedFiles) {
      const deployedPath = path.resolve(deployed.path).toLowerCase();
      const deployedBase = path.basename(deployedPath);

      // Exact match on resolved path OR exact match on basename
      const matches = eventPath === deployedPath ||
        (deployedBase.length > 0 && eventBase === deployedBase);
      if (!matches) continue;

      let canaryType: CanaryEvent['type'];

      const isSecretFile = name === '.secrets.env' ||
        ['key', 'secret', 'credential', 'token', 'aws'].some(k => name.toLowerCase().includes(k));

      if (isSecretFile) {
        canaryType = 'fake_secret_read';
      } else if (name === '.git_canary_commit') {
        canaryType = 'contaminated_git_read';
      } else {
        canaryType = event.operation === 'read' ? 'decoy_file_read' : 'decoy_file_modified';
      }

      const ce: CanaryEvent = {
        id: generateId(),
        sessionId,
        type: canaryType,
        canaryName: name,
        confidence: 0.95,
        timestamp: event.timestamp,
        processName: event.processName,
        pid: event.pid,
        detail: `Canary '${name}' ${event.operation} by ${event.processName}`
      };

      this.canaryEvents.push(ce);
      return ce;
    }

    return null;
  }

  checkFlowForCanary(hostname: string, bodyPreview: string | undefined, sessionId: string): CanaryEvent | null {
    if (!bodyPreview) return null;

    for (const [, deployed] of this.deployedFiles) {
      const marker = deployed.content;
      if (bodyPreview.includes(marker)) {
        const ce: CanaryEvent = {
          id: generateId(),
          sessionId,
          type: 'decoy_exfiltrated',
          canaryName: path.basename(deployed.path),
          confidence: 0.99,
          timestamp: new Date(),
          detail: `Canary marker '${marker.substring(0, 30)}...' detected in outbound traffic to ${hostname}`
        };
        this.canaryEvents.push(ce);
        return ce;
      }
    }

    return null;
  }

  getCanaryEvents(): CanaryEvent[] {
    return this.canaryEvents;
  }

  hasCanaryTrigger(): boolean {
    return this.canaryEvents.length > 0;
  }

  getDeployedCount(): number {
    return this.deployedFiles.size;
  }

  cleanup(): void {
    for (const [, deployed] of this.deployedFiles) {
      try {
        if (fs.existsSync(deployed.path)) fs.unlinkSync(deployed.path);
      } catch {
      }
    }
    this.deployedFiles.clear();
    this.canaryEvents = [];
  }

  private generateDecoyContent(name: string, marker: string): string {
    return [
      `# Sentinel Canary — ${name}`,
      `# ${marker}`,
      `# This file is a decoy. Any access outside of ${SENTINEL_CANARY_MARKER} is unauthorized.`,
      '',
      `timestamp: ${new Date().toISOString()}`,
      `id: ${generateId()}`,
      '',
      JSON.stringify({
        type: name.replace(/\.\w+$/, ''),
        created: new Date().toISOString(),
        canary: true,
        marker,
      }, null, 2)
    ].join('\n');
  }

  private hashContent(content: string): string {
    let hash = 0;
    for (let i = 0; i < content.length; i++) {
      const char = content.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash |= 0;
    }
    return hash.toString(36);
  }
}
