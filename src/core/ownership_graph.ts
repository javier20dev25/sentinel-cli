import { LiteFinding } from './lite/lite_scanner';
import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

export interface AuthorInfo {
  name: string;
  email: string;
  files: string[];
  findingCount: number;
  riskScore: number;
  topSubcodes: Map<string, number>;
}

export interface OwnershipResult {
  authors: AuthorInfo[];
  totalAuthors: number;
  topAuthor: AuthorInfo | null;
  riskiestAuthor: AuthorInfo | null;
}

function getGitAuthors(file: string): { name: string; email: string }[] {
  try {
    const output = execSync(
      `git log --format="%an||%ae" -- "${file}"`,
      { encoding: 'utf8', timeout: 5000, windowsHide: true, cwd: process.cwd() },
    );
    const seen = new Set<string>();
    const authors: { name: string; email: string }[] = [];
    for (const line of output.trim().split('\n')) {
      const [name, email] = line.split('||');
      const key = `${name}|${email}`;
      if (name && email && !seen.has(key)) {
        seen.add(key);
        authors.push({ name, email });
      }
    }
    return authors;
  } catch {
    return [];
  }
}

export async function buildOwnershipGraph(findings: LiteFinding[]): Promise<OwnershipResult> {
  const fileToFindings = new Map<string, LiteFinding[]>();
  for (const f of findings) {
    if (!fileToFindings.has(f.file)) fileToFindings.set(f.file, []);
    fileToFindings.get(f.file)!.push(f);
  }

  const authorMap = new Map<string, AuthorInfo>();

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
      const info = authorMap.get(key)!;
      if (!info.files.includes(file)) info.files.push(file);
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
}

export interface TeamInfo {
  name: string;
  members: string[];
  files: string[];
  findingCount: number;
  riskScore: number;
}

function findCodeownersFile(repoPath: string): string | null {
  const candidates = [
    path.join(repoPath, '.github', 'CODEOWNERS'),
    path.join(repoPath, 'docs', 'CODEOWNERS'),
    path.join(repoPath, 'CODEOWNERS'),
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }
  return null;
}

function globMatch(pattern: string, filePath: string): boolean {
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
    } catch {
      return false;
    }
  }

  return normalizedPath === pattern || normalizedPath.startsWith(pattern + '/');
}

export function parseCodeowners(repoPath: string): Map<string, string[]> {
  const result = new Map<string, string[]>();
  const filePath = findCodeownersFile(repoPath);
  if (!filePath) return result;

  const content = fs.readFileSync(filePath, 'utf8');
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('//')) continue;

    const parts = trimmed.split(/\s+/);
    if (parts.length < 2) continue;

    const pattern = parts[0];
    const owners = parts.slice(1).filter(o => o.startsWith('@'));
    if (owners.length > 0) {
      result.set(pattern, owners);
    }
  }

  return result;
}

export function groupByTeam(ownership: OwnershipResult, repoPath: string): TeamInfo[] {
  const codeowners = parseCodeowners(repoPath);
  if (codeowners.size === 0) return [];

  const patternToFiles = new Map<string, string[]>();
  for (const [pattern] of codeowners) {
    const matchedFiles: string[] = [];
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

  const teamMap = new Map<string, TeamInfo>();
  for (const [pattern, files] of patternToFiles) {
    const owners = codeowners.get(pattern)!;
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

    const team = teamMap.get(ownerStr)!;
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
