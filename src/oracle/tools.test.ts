import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockExecFileSync = vi.hoisted(() => vi.fn());
const mockExistsSync = vi.hoisted(() => vi.fn());
const mockMkdtempSync = vi.hoisted(() => vi.fn());
const mockWriteFileSync = vi.hoisted(() => vi.fn());
const mockReaddirSync = vi.hoisted(() => vi.fn());
const mockUnlinkSync = vi.hoisted(() => vi.fn());
const mockRmdirSync = vi.hoisted(() => vi.fn());
const mockStatSync = vi.hoisted(() => vi.fn());
const mockLstatSync = vi.hoisted(() => vi.fn());
const mockReadFileSync = vi.hoisted(() => vi.fn());
const mockTmpdir = vi.hoisted(() => vi.fn(() => '/tmp'));
const mockJoin = vi.hoisted(() => vi.fn((...args: string[]) => args.join('/')));
const mockResolve = vi.hoisted(() => vi.fn((p: string) => p));

const mockLiteScanner = vi.hoisted(() => ({
  scanPatch: vi.fn(),
}));

const mockSupplyChainShield = vi.hoisted(() => ({
  analyzePackage: vi.fn(),
}));

const mockSystemAuditor = vi.hoisted(() => ({
  runDoctor: vi.fn(),
}));

const mockIntegrityManager = vi.hoisted(() => ({
  checkIntegrity: vi.fn(),
  report: vi.fn(),
}));

const mockMemoryManager = vi.hoisted(() => ({
  getStatus: vi.fn(),
  getThresholdAnalysis: vi.fn(),
}));

const mockClassify = vi.hoisted(() => ({
  readClassifiedDb: vi.fn(),
  checkClassifiedHook: vi.fn(),
}));

vi.mock('child_process', () => ({
  execFileSync: mockExecFileSync,
}));

vi.mock('fs', () => ({
  existsSync: mockExistsSync,
  mkdtempSync: mockMkdtempSync,
  writeFileSync: mockWriteFileSync,
  readdirSync: mockReaddirSync,
  unlinkSync: mockUnlinkSync,
  rmdirSync: mockRmdirSync,
  statSync: mockStatSync,
  lstatSync: mockLstatSync,
  readFileSync: mockReadFileSync,
}));

vi.mock('os', () => ({
  tmpdir: mockTmpdir,
}));

vi.mock('path', () => ({
  join: mockJoin,
  resolve: mockResolve,
  relative: vi.fn((_from: string, to: string) => to),
  basename: vi.fn((p: string) => p.split('/').pop() || p.split('\\').pop() || p),
}));

vi.mock('../core/lite/lite_scanner', () => ({
  LiteScanner: class {
    scanPatch(...args: any[]) { return mockLiteScanner.scanPatch(...args); }
  },
}));

vi.mock('../cli/intelligence/supply_chain_shield', () => ({
  SupplyChainShield: class {
    analyzePackage(...args: any[]) { return mockSupplyChainShield.analyzePackage(...args); }
  },
}));

vi.mock('../cli/intelligence/system_auditor', () => ({
  SystemAuditor: class {
    runDoctor(...args: any[]) { return mockSystemAuditor.runDoctor(...args); }
  },
}));

vi.mock('../cli/intelligence/integrity_manager', () => ({
  IntegrityManager: class {
    checkIntegrity() { return mockIntegrityManager.checkIntegrity(); }
    report(...args: any[]) { return mockIntegrityManager.report(...args); }
  },
}));

vi.mock('../cli/intelligence/memory_manager', () => ({
  MemoryManager: class {
    getStatus() { return mockMemoryManager.getStatus(); }
    getThresholdAnalysis(...args: any[]) { return mockMemoryManager.getThresholdAnalysis(...args); }
  },
}));

vi.mock('../cli/classify', () => ({
  readClassifiedDb: mockClassify.readClassifiedDb,
  checkClassifiedHook: mockClassify.checkClassifiedHook,
}));

vi.mock('../cli/guard', () => ({
  enableGuard: vi.fn(),
  disableGuard: vi.fn(),
  isGuardEnabled: vi.fn(),
}));

import { getToolDefs, runTool, tools } from './tools';

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubGlobal('process', {
    ...process,
    argv: ['node', 'C:\\sentinel\\main.js'],
    chdir: vi.fn(),
    cwd: vi.fn(() => 'C:\\Users\\sleyt\\sentinel-cli'),
  });
  mockExecFileSync.mockReturnValue('ok');
  mockExistsSync.mockReturnValue(true);
  mockMkdtempSync.mockReturnValue('/tmp/sentinel-test-123');
  mockStatSync.mockReturnValue({ size: 1024, isDirectory: () => false });
  mockLstatSync.mockReturnValue({ isSymbolicLink: () => false });
  mockReaddirSync.mockReturnValue([]);
  mockReadFileSync.mockReturnValue('console.log("hello");');
});

// ─── getToolDefs ──────────────────────────────────────────────

describe('getToolDefs', () => {
  it('returns an array of tool definitions', () => {
    const defs = getToolDefs();
    expect(Array.isArray(defs)).toBe(true);
    expect(defs.length).toBeGreaterThan(0);
  });

  it('each tool has name, description, and parameters', () => {
    const defs = getToolDefs();
    for (const t of defs) {
      expect(t).toHaveProperty('name');
      expect(t).toHaveProperty('description');
      expect(t).toHaveProperty('parameters');
      expect(t.parameters).toHaveProperty('type', 'object');
      expect(t.parameters).toHaveProperty('properties');
    }
  });

  it('tool parameters have correct property structure', () => {
    const defs = getToolDefs();
    for (const t of defs) {
      for (const prop of Object.values(t.parameters.properties)) {
        expect(prop).toHaveProperty('type');
      }
    }
  });
});

// ─── tools array ──────────────────────────────────────────────

describe('tools array', () => {
  const requiredTools = [
    'scan', 'verify-pkg', 'doctor', 'check-classified', 'integrity', 'memory',
    'gh-audit-all', 'gh-pr-list', 'gh-pr-view', 'gh-pr-diff', 'gh-pr-comment', 'gh-repo-list',
    'machine-classify', 'machine-integrity', 'machine-memory',
    'download-verify-pkg', 'install-pkg', 'remove-pkg',
  ];

  for (const name of requiredTools) {
    it(`includes tool "${name}"`, () => {
      const tool = tools.find(t => t.name === name);
      expect(tool).toBeDefined();
      expect(tool!.name).toBe(name);
      expect(typeof tool!.description).toBe('string');
      expect(tool!.description.length).toBeGreaterThan(0);
      expect(typeof tool!.run).toBe('function');
    });
  }
});

// ─── runTool ──────────────────────────────────────────────────

describe('runTool', () => {
  it('returns error message for unknown tool', async () => {
    const result = await runTool('nonexistent-tool', {});
    expect(result).toBe('Unknown tool: nonexistent-tool');
  });

  it('calls the tool run function for known tools', async () => {
    const spy = vi.spyOn(tools.find(t => t.name === 'integrity')!, 'run');
    await runTool('integrity', {});
    expect(spy).toHaveBeenCalledWith({});
  });
});

// ─── scan tool ────────────────────────────────────────────────

describe('scan tool', () => {
  it('scans a file with LiteScanner', async () => {
    const findings = [{
      file: 'test.js', line: 1, column: 1, type: 'secret', severity: 'high',
      description: 'Hardcoded secret key', pattern: '.*', context: 'x', snippet: 'x',
    }];
    mockLiteScanner.scanPatch.mockReturnValue(findings);

    const tool = tools.find(t => t.name === 'scan')!;
    const result = await tool.run({ path: 'test.js' });

    expect(mockReadFileSync).toHaveBeenCalledWith('test.js', 'utf8');
    expect(result).toContain('high');
    expect(result).toContain('Hardcoded secret key');
  });

  it('uses default path "." when no path provided', async () => {
    mockLiteScanner.scanPatch.mockReturnValue([]);
    const tool = tools.find(t => t.name === 'scan')!;
    const result = await tool.run({});
    expect(result).toBe('No threats found.');
  });

  it('returns error for non-existent path', async () => {
    mockExistsSync.mockReturnValue(false);
    const tool = tools.find(t => t.name === 'scan')!;
    const result = await tool.run({ path: '/nonexistent' });
    expect(result).toContain('Error');
  });
});

// ─── verify-pkg tool ──────────────────────────────────────────

describe('verify-pkg tool', () => {
  it('calls SupplyChainShield.analyzePackage', async () => {
    mockSupplyChainShield.analyzePackage.mockResolvedValue({
      pkg: 'axios', sizeBytes: 100000, fileCount: 10, scanTimeMs: 500,
      memoryMB: 12, verdict: 'clean', findings: [],
    });

    const tool = tools.find(t => t.name === 'verify-pkg')!;
    const result = await tool.run({ package: 'axios' });

    expect(mockSupplyChainShield.analyzePackage).toHaveBeenCalledWith('axios');
    expect(result).toContain('axios');
    expect(result).toContain('clean');
  });

  it('returns error for invalid package name', async () => {
    const tool = tools.find(t => t.name === 'verify-pkg')!;
    const result = await tool.run({ package: '' });
    expect(result).toBe('Error: invalid package name');
  });

  it('handles errors from analyzePackage', async () => {
    mockSupplyChainShield.analyzePackage.mockRejectedValue(new Error('network error'));
    const tool = tools.find(t => t.name === 'verify-pkg')!;
    const result = await tool.run({ package: 'bad-pkg' });
    expect(result).toContain('Error');
  });
});

// ─── doctor tool ──────────────────────────────────────────────

describe('doctor tool', () => {
  it('runs SystemAuditor.doctor and captures console output', async () => {
    mockSystemAuditor.runDoctor.mockImplementation(async () => {
      console.log('Doctor report: system healthy');
    });

    const tool = tools.find(t => t.name === 'doctor')!;
    const result = await tool.run({});

    expect(mockSystemAuditor.runDoctor).toHaveBeenCalledWith(false);
    expect(result).toContain('Doctor report: system healthy');
  });

  it('passes --deep flag to runDoctor', async () => {
    mockSystemAuditor.runDoctor.mockImplementation(async () => {});
    const tool = tools.find(t => t.name === 'doctor')!;
    await tool.run({ deep: '--deep' });
    expect(mockSystemAuditor.runDoctor).toHaveBeenCalledWith(true);
  });

  it('changes directory when path is provided', async () => {
    mockSystemAuditor.runDoctor.mockImplementation(async () => {});
    const chdirSpy = vi.spyOn(process, 'chdir');
    const tool = tools.find(t => t.name === 'doctor')!;
    await tool.run({ path: './some-project' });
    expect(chdirSpy).toHaveBeenCalled();
  });
});

// ─── check-classified tool ────────────────────────────────────

describe('check-classified tool', () => {
  it('returns success when hook exits 0', () => {
    mockClassify.checkClassifiedHook.mockReturnValue(0);
    const tool = tools.find(t => t.name === 'check-classified')!;
    const result = tool.run({});
    expect(result).toBe('All staged files cleared. No classified files detected.');
  });

  it('returns violation when hook exits non-zero', () => {
    mockClassify.checkClassifiedHook.mockReturnValue(1);
    const tool = tools.find(t => t.name === 'check-classified')!;
    const result = tool.run({});
    expect(result).toContain('commit blocked');
  });
});

// ─── integrity tool ───────────────────────────────────────────

describe('integrity tool', () => {
  it('returns integrity level', async () => {
    mockIntegrityManager.checkIntegrity.mockResolvedValue({ level: 'clean', reasons: [] });
    const tool = tools.find(t => t.name === 'integrity')!;
    const result = await tool.run({});
    expect(result).toContain('clean');
  });

  it('lists issues when reasons present', async () => {
    mockIntegrityManager.checkIntegrity.mockResolvedValue({ level: 'warning', reasons: ['Clock skew detected', 'Vault modified'] });
    const tool = tools.find(t => t.name === 'integrity')!;
    const result = await tool.run({});
    expect(result).toContain('Clock skew detected');
  });
});

// ─── memory tool ──────────────────────────────────────────────

describe('memory tool', () => {
  it('returns vault status', () => {
    mockMemoryManager.getStatus.mockReturnValue({ signals: 5, scans: 3, findings: 10, repos: 2, authors: 1 });
    const tool = tools.find(t => t.name === 'memory')!;
    const result = tool.run({});
    expect(result).toContain('5');
    expect(result).toContain('3');
  });

  it('includes threshold analysis for --findings', () => {
    mockMemoryManager.getStatus.mockReturnValue({ signals: 5, scans: 3, findings: 10, repos: 2, authors: 1 });
    mockMemoryManager.getThresholdAnalysis.mockReturnValue([{ repo: 'test/repo', signalCount: 5, riskTrend: 'increasing' }]);
    const tool = tools.find(t => t.name === 'memory')!;
    const result = tool.run({ action: '--findings' });
    expect(result).toContain('test/repo');
    expect(mockMemoryManager.getThresholdAnalysis).toHaveBeenCalledWith(3);
  });
});

// ─── gh-pr-tools ──────────────────────────────────────────────

describe('gh-pr-list tool', () => {
  it('executes gh pr list with default args', () => {
    const tool = tools.find(t => t.name === 'gh-pr-list')!;
    tool.run({});
    expect(mockExecFileSync).toHaveBeenCalledWith(
      'gh', expect.arrayContaining(['pr', 'list']), expect.any(Object),
    );
  });
});

describe('gh-pr-view tool', () => {
  it('returns error for invalid PR number', () => {
    const tool = tools.find(t => t.name === 'gh-pr-view')!;
    const result = tool.run({ number: 'abc' });
    expect(result).toBe('Error: invalid PR number');
  });

  it('executes gh pr view with valid PR number', () => {
    const tool = tools.find(t => t.name === 'gh-pr-view')!;
    tool.run({ number: '42' });
    expect(mockExecFileSync).toHaveBeenCalledWith(
      'gh', expect.arrayContaining(['pr', 'view', '42']), expect.any(Object),
    );
  });
});

describe('gh-pr-diff tool', () => {
  it('returns error for invalid PR number', () => {
    const tool = tools.find(t => t.name === 'gh-pr-diff')!;
    const result = tool.run({ number: 'abc' });
    expect(result).toBe('Error: invalid PR number');
  });

  it('executes gh pr diff with valid PR number', () => {
    mockExecFileSync.mockReturnValue('diff output');
    const tool = tools.find(t => t.name === 'gh-pr-diff')!;
    tool.run({ number: '1' });
    expect(mockExecFileSync).toHaveBeenCalledWith(
      'gh', expect.arrayContaining(['pr', 'diff', '1']), expect.any(Object),
    );
  });

  it('handles gh error gracefully', () => {
    mockExecFileSync.mockImplementation(() => { throw { stdout: 'Not found', stderr: '' }; });
    const tool = tools.find(t => t.name === 'gh-pr-diff')!;
    const result = tool.run({ number: '1' });
    expect(result).toBe('Not found');
  });
});

describe('gh-pr-comment tool', () => {
  it('returns error for invalid PR number', () => {
    const tool = tools.find(t => t.name === 'gh-pr-comment')!;
    const result = tool.run({ number: 'abc', body: 'test' });
    expect(result).toBe('Error: invalid PR number');
  });

  it('returns error for missing body', () => {
    const tool = tools.find(t => t.name === 'gh-pr-comment')!;
    const result = tool.run({ number: '1', body: '' });
    expect(result).toBe('Error: comment body is required');
  });

  it('writes body to temp file and calls gh pr comment', () => {
    const tool = tools.find(t => t.name === 'gh-pr-comment')!;
    tool.run({ number: '1', body: 'LGTM' });
    expect(mockWriteFileSync).toHaveBeenCalled();
    expect(mockExecFileSync).toHaveBeenCalledWith(
      'gh', expect.arrayContaining(['pr', 'comment', '1', '--body-file']), expect.any(Object),
    );
  });
});

describe('gh-repo-list tool', () => {
  it('executes gh repo list with default limit', () => {
    const tool = tools.find(t => t.name === 'gh-repo-list')!;
    tool.run({});
    expect(mockExecFileSync).toHaveBeenCalledWith(
      'gh', expect.arrayContaining(['repo', 'list', '--limit', '20']), expect.any(Object),
    );
  });

  it('sanitizes owner name', () => {
    const tool = tools.find(t => t.name === 'gh-repo-list')!;
    tool.run({ owner: 'my-org; rm -rf' });
    const call = mockExecFileSync.mock.calls.find((c: any[]) => c[0] === 'gh');
    const args = call[1];
    expect(args).toContain('--owner');
    const ownerIdx = args.indexOf('--owner');
    expect(ownerIdx).toBeGreaterThanOrEqual(0);
    const ownerVal = args[ownerIdx + 1];
    expect(ownerVal).toContain('my-org');
    expect(ownerVal).not.toContain(';');
    expect(ownerVal).not.toContain(' ');
  });
});

// ─── machine tools ────────────────────────────────────────────

describe('machine-classify tool', () => {
  it('returns error for empty file path', () => {
    const tool = tools.find(t => t.name === 'machine-classify')!;
    const result = tool.run({ file: '' });
    expect(result).toBe('Error: invalid file path');
  });

  it('returns Not classified when file not in database', () => {
    mockClassify.readClassifiedDb.mockReturnValue({});
    const tool = tools.find(t => t.name === 'machine-classify')!;
    const result = tool.run({ file: 'secret.txt' });
    expect(result).toBe('Not classified.');
  });

  it('returns CLASSIFIED when file is in database', () => {
    mockClassify.readClassifiedDb.mockReturnValue({
      '': ['secret.txt'],
    });
    const tool = tools.find(t => t.name === 'machine-classify')!;
    const result = tool.run({ file: 'secret.txt' });
    expect(result).toContain('CLASSIFIED');
  });

  it('returns error when file not found', () => {
    mockExistsSync.mockReturnValue(false);
    const tool = tools.find(t => t.name === 'machine-classify')!;
    const result = tool.run({ file: 'missing.txt' });
    expect(result).toBe('Error: file not found');
  });
});

describe('machine-integrity tool', () => {
  it('returns integrity level', async () => {
    mockIntegrityManager.checkIntegrity.mockResolvedValue({ level: 'clean', reasons: [] });
    const tool = tools.find(t => t.name === 'machine-integrity')!;
    const result = await tool.run({});
    expect(result).toContain('clean');
  });
});

describe('machine-memory tool', () => {
  it('returns vault status', () => {
    mockMemoryManager.getStatus.mockReturnValue({ signals: 5, scans: 3, findings: 10, repos: 2, authors: 1 });
    const tool = tools.find(t => t.name === 'machine-memory')!;
    const result = tool.run({});
    expect(result).toContain('5');
  });
});

// ─── gh-audit-all tool ────────────────────────────────────────

describe('gh-audit-all tool', () => {
  it('returns no repos message when no repos found', () => {
    mockExecFileSync.mockReturnValue('[]');
    const tool = tools.find(t => t.name === 'gh-audit-all')!;
    const result = tool.run({});
    expect(result).toBe('No repositories found.');
  });

  it('returns no PRs message across repos', () => {
    mockExecFileSync
      .mockReturnValueOnce('[{"name":"test","owner":{"login":"me"}}]')
      .mockReturnValueOnce('[]');
    const tool = tools.find(t => t.name === 'gh-audit-all')!;
    const result = tool.run({ limit: '5' });
    expect(result).toContain('No open PRs');
  });
});

// ─── download-verify-pkg tool ─────────────────────────────────

describe('download-verify-pkg tool', () => {
  it('returns error for invalid package name', async () => {
    const tool = tools.find(t => t.name === 'download-verify-pkg')!;
    const result = await tool.run({ package: '' });
    expect(result).toBe('Error: invalid package name');
  });

  it('downloads and scans a package', async () => {
    mockSupplyChainShield.analyzePackage.mockResolvedValue({
      pkg: 'safe-pkg', sizeBytes: 5000, fileCount: 3, scanTimeMs: 200,
      memoryMB: 8, verdict: 'clean', findings: [],
    });

    const tool = tools.find(t => t.name === 'download-verify-pkg')!;
    const result = await tool.run({ package: 'safe-pkg' });

    expect(result).toContain('safe-pkg');
    expect(result).toContain('Verdict');
    expect(result).toContain('No threats');
  });

  it('handles errors from analyzePackage', async () => {
    mockSupplyChainShield.analyzePackage.mockRejectedValue(new Error('download failed'));
    const tool = tools.find(t => t.name === 'download-verify-pkg')!;
    const result = await tool.run({ package: 'bad-pkg' });
    expect(result).toContain('Error');
  });
});

// ─── install-pkg / remove-pkg ─────────────────────────────────

describe('install-pkg tool', () => {
  it('returns error for invalid package name', () => {
    const tool = tools.find(t => t.name === 'install-pkg')!;
    const result = tool.run({ package: '' });
    expect(result).toBe('Error: invalid package name');
  });

  it('installs package with npm install', () => {
    const tool = tools.find(t => t.name === 'install-pkg')!;
    tool.run({ package: 'lodash' });
    expect(mockExecFileSync).toHaveBeenCalledWith(
      'npm', expect.arrayContaining(['install', 'lodash']), expect.any(Object),
    );
  });

  it('installs globally with --global flag', () => {
    const tool = tools.find(t => t.name === 'install-pkg')!;
    tool.run({ package: 'nodemon', global: '--global' });
    const call = mockExecFileSync.mock.calls.find((c: any[]) => c[0] === 'npm');
    expect(call[1]).toContain('--global');
  });
});

describe('remove-pkg tool', () => {
  it('returns error for invalid package name', () => {
    const tool = tools.find(t => t.name === 'remove-pkg')!;
    const result = tool.run({ package: '' });
    expect(result).toBe('Error: invalid package name');
  });

  it('removes package with npm uninstall', () => {
    const tool = tools.find(t => t.name === 'remove-pkg')!;
    tool.run({ package: 'bad-pkg' });
    expect(mockExecFileSync).toHaveBeenCalledWith(
      'npm', expect.arrayContaining(['uninstall', 'bad-pkg']), expect.any(Object),
    );
  });
});

// ─── error handling ───────────────────────────────────────────

describe('error handling', () => {
  it('runGh returns error message on gh failure', () => {
    mockExecFileSync.mockImplementation(() => {
      const err: any = new Error('gh error');
      err.stdout = '';
      err.stderr = 'gh not logged in';
      throw err;
    });

    const tool = tools.find(t => t.name === 'gh-pr-list')!;
    const result = tool.run({});
    expect(result).toBe('gh not logged in');
  });

  it('scan tool handles file read error', async () => {
    mockReadFileSync.mockImplementation(() => { throw new Error('permission denied'); });
    mockStatSync.mockReturnValue({ isDirectory: () => false });

    const tool = tools.find(t => t.name === 'scan')!;
    const result = await tool.run({ path: '/restricted' });
    expect(result).toContain('Error');
  });
});
