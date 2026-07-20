import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { LiteScanner, LiteFinding } from '../../core/lite/lite_scanner';
import { CapabilityAnalyzer, CapabilityType } from './capability_analyzer';

export interface CapabilitySnapshot {
  packageName: string;
  version: string;
  timestamp: string;
  capabilities: Map<string, number>;
  riskScore: number;
}

export interface DriftEntry {
  capability: string;
  previousCount: number;
  currentCount: number;
  change: number;
  severity: 'NEW' | 'INCREASED' | 'DECREASED' | 'REMOVED';
}

export interface DriftResult {
  packageName: string;
  previousVersion: string;
  currentVersion: string;
  drifts: DriftEntry[];
  riskChange: number;
  verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS';
  newCapabilities: string[];
  removedCapabilities: string[];
}

function toDriftCapName(capType: CapabilityType): string {
  const map: Record<string, string> = {
    'NETWORK': 'network',
    'FILESYSTEM': 'file_write',
    'PROCESS_EXEC': 'process_spawn',
    'ENV_ACCESS': 'env_access',
    'DYNAMIC_EXEC': 'eval',
    'DOM_MANIPULATION': 'dom_manipulation',
    'CREDENTIAL_LEAK': 'credential_leak',
  };
  return map[capType] || capType.toLowerCase();
}

const DANGEROUS_CAPABILITIES = new Set(['exec', 'eval', 'network', 'file_write', 'process_spawn']);

function walkDir(dir: string): string[] {
  let results: string[] = [];
  const list = fs.readdirSync(dir);
  for (const file of list) {
    const lowerFile = file.toLowerCase();
    if (lowerFile === 'test' || lowerFile === 'tests' || lowerFile === 'example' ||
        lowerFile === 'examples' || lowerFile === 'benchmark' || lowerFile === 'docs' ||
        lowerFile === 'node_modules' || file.startsWith('.')) {
      continue;
    }
    const fullPath = path.join(dir, file);
    const stat = fs.statSync(fullPath);
    if (stat.isDirectory()) {
      results = results.concat(walkDir(fullPath));
    } else {
      results.push(fullPath);
    }
  }
  return results;
}

export function analyzeCapabilities(packageName: string, version: string, packagePath: string): CapabilitySnapshot {
  const scanner = new LiteScanner();
  const allFindings: LiteFinding[] = [];
  const files = walkDir(packagePath).filter(f => f.endsWith('.js') || f.endsWith('.ts') || f.endsWith('.mjs'));

  for (const file of files) {
    try {
      const content = fs.readFileSync(file, 'utf8');
      const patch = `@@ -0,0 +1,1 @@\n+${content.split('\n').join('\n+')}`;
      const findings = scanner.scanPatch(path.relative(packagePath, file), patch);
      allFindings.push(...findings);
    } catch {}
  }

  const capabilities = CapabilityAnalyzer.analyze(allFindings);
  const capMap = new Map<string, number>();
  let riskScore = 0;
  const riskWeights: Record<string, number> = { 'LOW': 1, 'MEDIUM': 5, 'HIGH': 15, 'CRITICAL': 25 };

  for (const cap of capabilities) {
    const key = toDriftCapName(cap.capability);
    capMap.set(key, (capMap.get(key) || 0) + 1);
    riskScore += riskWeights[cap.risk] || 0;
  }

  return {
    packageName,
    version,
    timestamp: new Date().toISOString(),
    capabilities: capMap,
    riskScore,
  };
}

export function computeDrift(previous: CapabilitySnapshot, current: CapabilitySnapshot): DriftResult {
  const drifts: DriftEntry[] = [];
  const newCapabilities: string[] = [];
  const removedCapabilities: string[] = [];

  const allKeys = new Set([...previous.capabilities.keys(), ...current.capabilities.keys()]);

  for (const key of allKeys) {
    const prevVal = previous.capabilities.get(key) || 0;
    const currVal = current.capabilities.get(key) || 0;
    const change = currVal - prevVal;

    let severity: DriftEntry['severity'];
    if (prevVal === 0 && currVal > 0) {
      severity = 'NEW';
      newCapabilities.push(key);
    } else if (prevVal > 0 && currVal === 0) {
      severity = 'REMOVED';
      removedCapabilities.push(key);
    } else if (change > 0) {
      severity = 'INCREASED';
    } else if (change < 0) {
      severity = 'DECREASED';
    } else {
      continue;
    }

    drifts.push({ capability: key, previousCount: prevVal, currentCount: currVal, change, severity });
  }

  const riskChange = current.riskScore - previous.riskScore;
  let verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' = 'SAFE';

  const hasNewDangerous = newCapabilities.some(c => DANGEROUS_CAPABILITIES.has(c));
  if (hasNewDangerous) {
    verdict = 'MALICIOUS';
  }

  const increasedCount = drifts.filter(d => d.severity === 'INCREASED').length;
  if (increasedCount > 2 && verdict !== 'MALICIOUS') {
    verdict = 'SUSPICIOUS';
  }

  if (riskChange > 30) {
    if (verdict === 'SAFE') verdict = 'SUSPICIOUS';
    else if (verdict === 'SUSPICIOUS') verdict = 'MALICIOUS';
  }

  return {
    packageName: current.packageName,
    previousVersion: previous.version,
    currentVersion: current.version,
    drifts,
    riskChange,
    verdict,
    newCapabilities,
    removedCapabilities,
  };
}

export function saveSnapshot(snapshot: CapabilitySnapshot): void {
  const dir = path.join(os.homedir(), '.sentinel', 'drift', snapshot.packageName);
  fs.mkdirSync(dir, { recursive: true });
  const filePath = path.join(dir, `${snapshot.version}.json`);
  const data = {
    ...snapshot,
    capabilities: Object.fromEntries(snapshot.capabilities),
  };
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

export function loadPreviousSnapshot(packageName: string, currentVersion: string): CapabilitySnapshot | null {
  const dir = path.join(os.homedir(), '.sentinel', 'drift', packageName);
  if (!fs.existsSync(dir)) return null;

  const files = fs.readdirSync(dir)
    .filter(f => f.endsWith('.json'))
    .sort()
    .reverse();

  for (const file of files) {
    const version = file.replace('.json', '');
    if (version !== currentVersion) {
      try {
        const raw = JSON.parse(fs.readFileSync(path.join(dir, file), 'utf8'));
        return {
          ...raw,
          capabilities: new Map(Object.entries(raw.capabilities || {})),
        };
      } catch {}
    }
  }

  return null;
}
