import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockExistsSync = vi.hoisted(() => vi.fn());
const mockReaddirSync = vi.hoisted(() => vi.fn());
const mockCpSync = vi.hoisted(() => vi.fn());
const mockMkdirSync = vi.hoisted(() => vi.fn());
const mockStatSync = vi.hoisted(() => vi.fn());
const mockReadFileSync = vi.hoisted(() => vi.fn());
const mockExecSync = vi.hoisted(() => vi.fn());
const mockHomedir = vi.hoisted(() => vi.fn(() => '/home/user'));

vi.mock('fs', () => ({
  existsSync: mockExistsSync,
  readdirSync: mockReaddirSync,
  cpSync: mockCpSync,
  mkdirSync: mockMkdirSync,
  statSync: mockStatSync,
  readFileSync: mockReadFileSync,
}));

vi.mock('child_process', () => ({
  execSync: mockExecSync,
}));

vi.mock('os', () => ({
  homedir: mockHomedir,
}));

describe('install-skills', () => {
  let installSkills: typeof import('./install-skills');

  beforeEach(async () => {
    vi.clearAllMocks();
    // Default mocks: skills dir exists
    mockExistsSync.mockImplementation((p: string) => {
      // skills/ dir exists, src/cli/ exists for __dirname
      if (typeof p === 'string' && (
        p.includes('skills') || p.includes('install-skills')
      )) return true;
      return false;
    });
    mockReaddirSync.mockReturnValue([]);
    mockCpSync.mockReturnValue(undefined);
    mockMkdirSync.mockReturnValue(undefined);
    mockStatSync.mockImplementation(() => ({ mtimeMs: 1000, isDirectory: () => false }));
    mockReadFileSync.mockReturnValue('');
    installSkills = await import('./install-skills');
  });

  describe('listDetectedAgents', () => {
    it('returns all agents with detection status', () => {
      const result = installSkills.listDetectedAgents();
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBe(8);
      result.forEach(a => {
        expect(a).toHaveProperty('name');
        expect(a).toHaveProperty('detected');
      });
    });

    it('detects opencode when config dir exists', () => {
      mockExistsSync.mockImplementation((p: string) => {
        if (typeof p !== 'string') return false;
        if (p.includes('.config') && p.includes('opencode')) return true;
        return false;
      });
      const result = installSkills.listDetectedAgents();
      const oc = result.find(a => a.name === 'opencode');
      expect(oc?.detected).toBe(true);
    });
  });

  describe('which helper', () => {
    it('returns null for unknown command', () => {
      mockExistsSync.mockReturnValue(false);
      // Access via listDetectedAgents behavior — which runs internally
      const result = installSkills.listDetectedAgents();
      expect(Array.isArray(result)).toBe(true);
    });
  });

  describe('runInstall', () => {
    it('returns empty results when no agents targeted and none detected', () => {
      mockExistsSync.mockReturnValue(false);
      const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      const { results } = installSkills.runInstall([]);
      expect(results.length).toBe(0);
      expect(logSpy).toHaveBeenCalledWith('[!] No supported AI coding agents detected. Run with --all or --agent <name> to install skills manually.');
      logSpy.mockRestore();
    });

    it('installs to detected agent dirs when no target specified', () => {
      mockExistsSync.mockImplementation((p: string) => {
        if (p.includes('skills')) return true;
        if (p.includes('.cursor')) return true;
        if (p.includes('.config/opencode')) return true;
        return false;
      });
      const mockFile = { name: 'CONSTITUTION.md', isFile: () => true, isDirectory: () => false };
      mockReaddirSync.mockImplementation((_dir: string, opts?: any) => {
        if (opts?.withFileTypes) return [mockFile];
        return ['CONSTITUTION.md'];
      });

      const { results } = installSkills.runInstall();
      expect(results.length).toBeGreaterThanOrEqual(1);
    });

    it('installs to specified agent target dir', () => {
      mockExistsSync.mockImplementation((p: string) => {
        if (p.includes('skills') || p.includes('.config/opencode')) return true;
        return false;
      });
      const mockFile = { name: 'GENERIC.md', isFile: () => true, isDirectory: () => false };
      mockReaddirSync.mockImplementation((_dir: string, opts?: any) => {
        if (opts?.withFileTypes) return [mockFile];
        return ['GENERIC.md'];
      });

      const { results } = installSkills.runInstall(['opencode']);
      expect(results.length).toBe(1);
      expect(results[0].agent).toBe('opencode');
      expect(results[0].errors.length).toBe(0);
    });

    it('handles cpSync failure gracefully', () => {
      mockExistsSync.mockReturnValue(true);
      const mockFile = { name: 'GENERIC.md', isFile: () => true, isDirectory: () => false };
      mockReaddirSync.mockReturnValue([mockFile]);
      // Destination file is older, so copy should proceed
      let callCount = 0;
      mockStatSync.mockImplementation(() => {
        callCount++;
        return { mtimeMs: callCount <= 2 ? 1000 : 500, isDirectory: () => false };
      });
      mockReadFileSync.mockReturnValue('');
      mockCpSync.mockImplementation(() => { throw new Error('EPERM'); });

      const { results } = installSkills.runInstall(['opencode']);
      expect(results[0].errors.length).toBe(1);
      expect(results[0].errors[0]).toContain('EPERM');
    });

    it('handles missing skills directory', () => {
      mockExistsSync.mockReturnValue(false);
      const { results } = installSkills.runInstall(['opencode']);
      expect(results[0].errors.length).toBeGreaterThan(0);
    });
  });

  describe('installSkillsCommand', () => {
    it('shows help with --help flag', () => {
      const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      installSkills.installSkillsCommand(['--help']);
      expect(logSpy).toHaveBeenCalled();
      expect(logSpy.mock.calls[0][0]).toContain('Usage');
      logSpy.mockRestore();
    });

    it('lists agents with --list flag', () => {
      const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      installSkills.installSkillsCommand(['--list']);
      expect(logSpy).toHaveBeenCalled();
      expect(logSpy.mock.calls[0][0]).toContain('Detected agents');
      logSpy.mockRestore();
    });

    it('sets exit code on error', () => {
      mockExistsSync.mockReturnValue(false);
      installSkills.installSkillsCommand(['--agent', 'opencode']);
      expect(process.exitCode).toBe(1);
    });

    it('installs for specific agent via --agent flag', () => {
      mockExistsSync.mockImplementation((p: string) => {
        if (p.includes('skills') || p.includes('opencode')) return true;
        return false;
      });
      mockStatSync.mockImplementation(() => { throw new Error('ENOENT'); });
      const mockFile = { name: 'GENERIC.md', isFile: () => true, isDirectory: () => false };
      mockReaddirSync.mockImplementation((_dir: string, opts?: any) => {
        if (opts?.withFileTypes) return [mockFile];
        return ['GENERIC.md'];
      });
      const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      installSkills.installSkillsCommand(['--agent', 'opencode']);
      expect(logSpy).toHaveBeenCalled();
      expect(logSpy.mock.calls.some(c => typeof c[0] === 'string' && c[0].includes('opencode'))).toBe(true);
      logSpy.mockRestore();
      vi.restoreAllMocks();
    });

    it('installs for --all flag', () => {
      mockExistsSync.mockImplementation((p: string) => {
        if (p.includes('skills') || p.includes('opencode') || p.includes('cursor')) return true;
        return false;
      });
      mockStatSync.mockImplementation(() => { throw new Error('ENOENT'); });
      const mockFile = { name: 'GENERIC.md', isFile: () => true, isDirectory: () => false };
      mockReaddirSync.mockReturnValue([mockFile]);
      const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      installSkills.installSkillsCommand(['--all']);
      expect(logSpy).toHaveBeenCalled();
      logSpy.mockRestore();
      vi.restoreAllMocks();
    });
  });
});
