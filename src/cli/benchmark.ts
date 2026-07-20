import * as fs from 'fs';
import * as path from 'path';
import { LiteScanner, LiteFinding } from '../core/lite/lite_scanner';
import { calculateAgencyScore } from '../core/agency_score';

export interface BenchmarkResult {
  scanId: string;
  repoPath: string;
  findingsCount: number;
  criticalCount: number;
  highCount: number;
  agencyScore: number;
  scanTimeMs: number;
  falsePositives: string[];
  falseNegatives: string[];
  precision: number;
  recall: number;
}

export interface CorpusConfig {
  knownVulnerable: string[];
  knownBenign: string[];
  expectedFindings: Record<string, string[]>;
}

function* walkDir(dir: string): Generator<string> {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      yield* walkDir(fullPath);
    } else {
      yield fullPath;
    }
  }
}

export function runBenchmark(corpusRoot: string): BenchmarkResult[] {
  const vulnerableDir = path.join(corpusRoot, 'known-vulnerable');
  const benignDir = path.join(corpusRoot, 'known-benign');

  const scanner = new LiteScanner();
  const results: BenchmarkResult[] = [];

  const vulnerableFiles: string[] = [];
  if (fs.existsSync(vulnerableDir)) {
    for (const f of walkDir(vulnerableDir)) {
      vulnerableFiles.push(f);
    }
  }

  const benignFiles: string[] = [];
  if (fs.existsSync(benignDir)) {
    for (const f of walkDir(benignDir)) {
      benignFiles.push(f);
    }
  }

  const allFixtures = new Map<string, 'vulnerable' | 'benign'>();

  for (const f of vulnerableFiles) {
    const relPath = path.relative(vulnerableDir, f);
    allFixtures.set(relPath, 'vulnerable');
  }
  for (const f of benignFiles) {
    const relPath = path.relative(benignDir, f);
    allFixtures.set(relPath, 'benign');
  }

  for (const [relPath, label] of allFixtures) {
    const fixturePath = label === 'vulnerable'
      ? path.join(vulnerableDir, relPath)
      : path.join(benignDir, relPath);

    const content = fs.readFileSync(fixturePath, 'utf8');
    const startTime = Date.now();

    const result = scanner.scanFileContent(relPath, content);
    const scanTimeMs = Date.now() - startTime;

    const agency = calculateAgencyScore(result.findings);

    const expected: string[] = [];
    for (const [filePattern, entry] of Object.entries(existingExpectedFindings)) {
      const isTuple = entry.length === 2 && (entry[0] === 'vulnerable' || entry[0] === 'benign');
      const matchLabel = isTuple ? entry[0] : 'vulnerable';
      const expects: string[] = isTuple ? (entry[1] as string[]) : (entry as string[]);
      if (!relPath.includes(filePattern) && relPath !== filePattern) continue;
      if (label !== matchLabel) continue;
      expected.push(...expects);
    }

    const actualSubcodes = new Set(result.findings.map(f => f.subcode).filter(Boolean) as string[]);

    const falsePositives: string[] = [];
    const falseNegatives: string[] = [];
    let truePositives = 0;

    for (const subcode of actualSubcodes) {
      if (expected.includes(subcode)) {
        truePositives++;
      } else {
        falsePositives.push(subcode);
      }
    }

    for (const subcode of expected) {
      if (!actualSubcodes.has(subcode)) {
        falseNegatives.push(subcode);
      }
    }

    const tp = truePositives;
    const fp = falsePositives.length;
    const fn = falseNegatives.length;
    const precision = tp + fp > 0 ? tp / (tp + fp) : 1;
    const recall = tp + fn > 0 ? tp / (tp + fn) : label === 'benign' ? 1 : 0;

    results.push({
      scanId: `${label}-${relPath.replace(/[^a-zA-Z0-9_-]/g, '_')}`,
      repoPath: relPath,
      findingsCount: result.findings.length,
      criticalCount: result.findings.filter(f => f.severity === 'CRITICAL').length,
      highCount: result.findings.filter(f => f.severity === 'HIGH').length,
      agencyScore: agency.agencyScore,
      scanTimeMs,
      falsePositives,
      falseNegatives,
      precision,
      recall,
    });
  }

  return results;
}

export function aggregateBenchmark(results: BenchmarkResult[]): {
  totalFixtures: number;
  totalFindings: number;
  avgPrecision: number;
  avgRecall: number;
  worstFp: BenchmarkResult[];
  worstFn: BenchmarkResult[];
} {
  if (results.length === 0) {
    return { totalFixtures: 0, totalFindings: 0, avgPrecision: 1, avgRecall: 1, worstFp: [], worstFn: [] };
  }

  const totalFixtures = results.length;
  const totalFindings = results.reduce((s, r) => s + r.findingsCount, 0);
  const avgPrecision = results.reduce((s, r) => s + r.precision, 0) / totalFixtures;
  const avgRecall = results.reduce((s, r) => s + r.recall, 0) / totalFixtures;

  const sortedByFp = [...results].sort((a, b) => b.falsePositives.length - a.falsePositives.length);
  const sortedByFn = [...results].sort((a, b) => b.falseNegatives.length - a.falseNegatives.length);

  return {
    totalFixtures,
    totalFindings,
    avgPrecision,
    avgRecall,
    worstFp: sortedByFp.slice(0, 5),
    worstFn: sortedByFn.slice(0, 5),
  };
}

type ExpectedEntry = string[] | ['vulnerable' | 'benign', string[]]

const existingExpectedFindings: Record<string, ExpectedEntry> = {
  '.env': ['SEC-ENV-FILE'],
  '.env.production': ['SEC-ENV-FILE'],
  'secrets.env': ['SEC-ENV-FILE', 'SEC-AWS-ID', 'SEC-AWS-ID-BARE', 'SEC-GITHUB-TOKEN', 'SEC-API-KEY', 'SEC-SSH-KEY', 'SEC-DB-PASSWORD'],
  'credentials.json': ['SEC-CREDS-FILE'],
  'secrets.json': ['SEC-CREDS-FILE'],
  'key.json': ['SEC-CREDS-FILE'],
  'id_rsa': ['SEC-SSH-FILE'],
  'binding.gyp': ['GYP-FILE'],
  'node-gyp-build.js': ['GYP-NODE'],
  'malware.js': ['SAST-EVAL', 'SAST-PROCESS', 'OBF-PAYLOAD'],
  'supply-chain.yml': ['WF-001', 'WF-002', 'WF-005'],
  'ast-threat.js': ['SAST-EVAL', 'SAST-PROCESS', 'SAST-NETWORK', 'SAST-ENV', 'SEC-HARDCODED-TOKEN'],
  'package.json': ['vulnerable', ['LIF-CURL-BASH', 'LIF-SHELL']],
  'package-lock.json': ['vulnerable', []],
  'rust-threat.rs': ['vulnerable', ['SAST-PROCESS']],
  'go-threat.go': ['vulnerable', ['SAST-PROCESS']],
}
