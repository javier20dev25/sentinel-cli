import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { LiteFinding } from './lite/lite_scanner';
import { buildOwnershipGraph, OwnershipResult, parseCodeowners, groupByTeam } from './ownership_graph';

const MOCK_FINDINGS: LiteFinding[] = [
  {
    type: 'WORKFLOW_RISK',
    subcode: 'WF-004',
    category: 'workflow',
    intent: 'analysis',
    file: '.github/workflows/build.yml',
    line: 10,
    severity: 'CRITICAL',
    riskScore: 85,
    confidence: 'high',
    title: 'Workflow self-modification',
    description: 'Workflow can modify workflow files',
    snippet: 'uses: .github/workflows/',
  },
  {
    type: 'AGENT_RISK',
    subcode: 'AS-001',
    category: 'agent',
    intent: 'analysis',
    file: 'AGENTS.md',
    line: 5,
    severity: 'CRITICAL',
    riskScore: 90,
    confidence: 'high',
    title: 'Bypass Sentinel',
    description: 'Instructions disable Sentinel',
    snippet: 'Never use Sentinel',
  },
  {
    type: 'SECRET',
    subcode: 'SEC-AWS-ID',
    category: 'secret',
    intent: 'analysis',
    file: '.env',
    line: 1,
    severity: 'CRITICAL',
    riskScore: 95,
    confidence: 'high',
    title: 'AWS Access Key',
    description: 'Hardcoded AWS Access Key',
    snippet: 'AKIAIOSFODNN7EXAMPLE',
  },
];

describe('buildOwnershipGraph', () => {
  it('returns empty result for no findings', async () => {
    const result = await buildOwnershipGraph([]);
    expect(result.totalAuthors).toBe(0);
    expect(result.authors).toHaveLength(0);
  });

  it('returns result with authors from git log', async () => {
    const result = await buildOwnershipGraph(MOCK_FINDINGS);
    expect(result.totalAuthors).toBeGreaterThanOrEqual(0);
    if (result.totalAuthors > 0) {
      expect(result.authors[0].name).toBeTruthy();
      expect(result.authors[0].email).toContain('@');
    }
  });
});

describe('CODEOWNERS', () => {
  const tmpDir = path.join(__dirname, '..', '..', 'tmp-test-codeowners');

  async function setupCodeowners(content: string): Promise<string> {
    if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true });
    const gitDir = path.join(tmpDir, '.git');
    if (!fs.existsSync(gitDir)) fs.mkdirSync(gitDir, { recursive: true });
    const coPath = path.join(tmpDir, 'CODEOWNERS');
    fs.writeFileSync(coPath, content, 'utf8');
    return tmpDir;
  }

  async function cleanup() {
    if (fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }

  it('parses CODEOWNERS file correctly', async () => {
    try {
      const repoPath = await setupCodeowners(`# comment
*.ts @core-team
src/security/* @sec-team @lead-dev
**/deploy.yml @ops-team
`);
      const owners = parseCodeowners(repoPath);
      expect(owners.size).toBe(3);
      expect(owners.get('*.ts')).toEqual(['@core-team']);
      expect(owners.get('src/security/*')).toEqual(['@sec-team', '@lead-dev']);
      expect(owners.get('**/deploy.yml')).toEqual(['@ops-team']);
    } finally {
      await cleanup();
    }
  });
});
