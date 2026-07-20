import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

const CONFIG_DIR = path.join(os.homedir(), '.sentinel');
const CONFIG_FILE = path.join(CONFIG_DIR, 'network-config.json');

export interface NetworkConfig {
  autoStart: boolean;
  alertThreshold: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  trustedHosts: string[];
  trustedProcesses: string[];
  performanceBudget: {
    maxCpuPercent: number;
    maxMemoryMb: number;
    maxEventsPerSecond: number;
    providerTimeoutMs: number;
  };
}

export function getDefaultConfig(): NetworkConfig {
  return {
    autoStart: false,
    alertThreshold: 'MEDIUM',
    trustedHosts: [],
    trustedProcesses: [],
    performanceBudget: {
      maxCpuPercent: 5,
      maxMemoryMb: 128,
      maxEventsPerSecond: 1000,
      providerTimeoutMs: 3000,
    },
  };
}

export function loadConfig(): NetworkConfig {
  try {
    if (fs.existsSync(CONFIG_FILE)) {
      const raw = fs.readFileSync(CONFIG_FILE, 'utf-8');
      return { ...getDefaultConfig(), ...JSON.parse(raw) };
    }
  } catch {
    // ignore
  }
  return getDefaultConfig();
}

export function saveConfig(config: NetworkConfig): void {
  if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
  }
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2), 'utf-8');
}

export function getConfigPath(): string {
  return CONFIG_FILE;
}
