import * as http from 'http';
import * as readline from 'readline';
import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import { runMcpTool } from './tools'

interface JsonRpcMessage {
  jsonrpc: '2.0';
  id?: number;
  method: string;
  params: Record<string, any>;
}

interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: number | null;
  result?: any;
  error?: { code: number; message: string };
}

interface MCPToolDef {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, { type: string; description?: string; enum?: string[] }>;
    required?: string[];
  };
}

const toolDefs: MCPToolDef[] = [
  {
    name: 'scan',
    description: 'Scan a directory or file for security threats using LiteScanner (30 SAST rules including secrets, eval, network, env access)',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'File or directory path to scan (default: current dir)' },
      },
      required: [],
    },
  },
  {
    name: 'verify-pkg',
    description: 'Audit an npm package via npm pack (zero-install) — detects typosquatting, secret leaks, hardcoded credentials, and supply chain threats in the tarball',
    inputSchema: {
      type: 'object',
      properties: {
        package: { type: 'string', description: 'npm package name to audit' },
      },
      required: ['package'],
    },
  },
  {
    name: 'doctor',
    description: 'System health check for npm dependencies — scans for known vulnerabilities, capability risks, and outdated packages',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Project path to scan (default: current dir)' },
        deep: { type: 'string', enum: ['--deep', ''], description: 'Pass --deep for full dependency tree scan' },
      },
      required: [],
    },
  },
  {
    name: 'check-classified',
    description: 'Check staged files in a git repo against the classified documents database',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Git repository path (default: current dir)' },
      },
      required: [],
    },
  },
  {
    name: 'integrity',
    description: 'Verify Sentinel host integrity — checks code hash, PATH poisoning, vault integrity, clock anomalies, signed manifest',
    inputSchema: {
      type: 'object',
      properties: {},
      required: [],
    },
  },
  {
    name: 'memory',
    description: 'Query the Signal Vault (local SQLite) for past scan results, findings, threat correlations, and session history',
    inputSchema: {
      type: 'object',
      properties: {
        action: { type: 'string', description: 'Action like --findings, --sessions, --threats' },
        query: { type: 'string', description: 'Optional search term' },
      },
      required: [],
    },
  },
  {
    name: 'threat-query',
    description: 'Query the threat intelligence database by author name — returns all known threats associated with that author',
    inputSchema: {
      type: 'object',
      properties: {
        author: { type: 'string', description: 'Author name to query' },
      },
      required: ['author'],
    },
  },
  {
    name: 'threat-correlate',
    description: 'Correlate findings with the threat database — checks author reputation, diff hash matches, and known threat patterns',
    inputSchema: {
      type: 'object',
      properties: {
        author: { type: 'string', description: 'Author name to correlate' },
        findings: { type: 'string', description: 'Findings text to match against known patterns' },
        diffHash: { type: 'string', description: 'Diff hash to check for previous sightings' },
      },
      required: [],
    },
  },
  {
    name: 'gh-pr-list',
    description: 'List open pull requests in the current GitHub repository',
    inputSchema: {
      type: 'object',
      properties: {
        repo: { type: 'string', description: 'Repo in format owner/name (default: current dir repo)' },
        limit: { type: 'string', description: 'Max PRs to return (default: 10)' },
        state: { type: 'string', enum: ['open', 'closed', 'all'], description: 'PR state filter' },
      },
      required: [],
    },
  },
  {
    name: 'gh-pr-view',
    description: 'View detailed information about a specific pull request',
    inputSchema: {
      type: 'object',
      properties: {
        number: { type: 'string', description: 'PR number to view' },
        repo: { type: 'string', description: 'Repo in format owner/name (default: current dir repo)' },
      },
      required: ['number'],
    },
  },
  {
    name: 'gh-pr-diff',
    description: 'Get the full diff of a pull request for SAST analysis',
    inputSchema: {
      type: 'object',
      properties: {
        number: { type: 'string', description: 'PR number to get diff from' },
        repo: { type: 'string', description: 'Repo in format owner/name (default: current dir repo)' },
      },
      required: ['number'],
    },
  },
  {
    name: 'gh-repo-list',
    description: 'List GitHub repositories for the authenticated user or organization',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'User or organization name (default: authenticated user)' },
        limit: { type: 'string', description: 'Max repos to return (default: 20)' },
      },
      required: [],
    },
  },
  {
    name: 'audit-deps',
    description: 'Comprehensive dependency audit: lockfile parse, OSV CVE lookup, registry reputation, provenance',
    inputSchema: {
      type: 'object',
      properties: {
        lockfile: { type: 'string', description: 'Path to lockfile (auto-detect: package-lock.json, yarn.lock)' },
        provenance: { type: 'string', description: 'Check npm attestation/provenance for top-level deps' },
        quarantine: { type: 'string', description: 'Auto-quarantine packages with CRITICAL findings' },
        ci: { type: 'string', description: 'CI mode (exit 1 on any vulnerability)' },
      },
      required: [],
    },
  },
  {
    name: 'deps-tree',
    description: 'Scan transitive dependencies (up to depth 3) for supply chain threats',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Path to node_modules (default: node_modules)' },
        depth: { type: 'string', description: 'Max tree depth (default: 3)' },
      },
      required: [],
    },
  },
  {
    name: 'trust-cache',
    description: 'Manage the trust cache for package analysis results',
    inputSchema: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['status', 'clear', 'prune'], description: 'Cache action (status | clear | prune)' },
      },
      required: ['action'],
    },
  },
  {
    name: 'sbom',
    description: 'Generate a CycloneDX SBOM from the project lockfile',
    inputSchema: {
      type: 'object',
      properties: {
        lockfile: { type: 'string', description: 'Path to lockfile (auto-detect: package-lock.json, yarn.lock)' },
      },
      required: [],
    },
  },
  {
    name: 'policy',
    description: 'Configure Sentinel security policies (ci-mode, fail-closed, quarantine)',
    inputSchema: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['set', 'get', 'list'], description: 'Policy action' },
        key: { type: 'string', description: 'Policy key (ci-mode, fail-closed, quarantine)' },
        value: { type: 'string', description: 'Policy value (strict, lenient, on, off)' },
      },
      required: ['action'],
    },
  },
]

async function runA2Tool(name: string, args: Record<string, string>): Promise<string | null> {
  switch (name) {
    case 'audit-deps': {
      const { LockfileParser } = await import('../cli/intelligence/lockfile_parser')
      const { OSVIntegrator } = await import('../cli/intelligence/osv_integrator')
      const { RegistryReputation } = await import('../cli/intelligence/registry_reputation')
      const { ProvenanceVerifier } = await import('../cli/intelligence/provenance_verifier')
      const { QuarantineManager } = await import('../cli/intelligence/quarantine')

      const cwd = process.cwd()
      let lockfilePath = args.lockfile || ''
      if (!lockfilePath) {
        const candidates = ['package-lock.json', 'yarn.lock']
        for (const c of candidates) {
          const testPath = path.join(cwd, c)
          if (fs.existsSync(testPath)) { lockfilePath = testPath; break }
        }
      }
      if (!lockfilePath || !fs.existsSync(lockfilePath)) {
        return JSON.stringify({ error: 'No lockfile found. Run npm install first, or specify --lockfile.' })
      }

      const parser = new LockfileParser()
      const parsed = parser.parse(lockfilePath)
      if (parsed.entries.length === 0) {
        return JSON.stringify({ packages: 0, format: parsed.format, vulnerabilities: 0, bySeverity: {}, suspiciousPackages: 0, provenance: 0, durationMs: 0 })
      }

      const startTime = Date.now()

      const osv = new OSVIntegrator()
      const osvPackages = parsed.entries.map(e => ({ name: e.name, version: e.version }))
      const osvResults = await osv.queryBatch(osvPackages)

      const rep = new RegistryReputation()
      const repResults: any[] = []
      for (const entry of parsed.entries.slice(0, 50)) {
        try { const s = await rep.score(entry.name); repResults.push(s) } catch {}
      }

      let provResults: any[] = []
      const checkProvenance = args.provenance === 'true' || args.provenance === '1'
      if (checkProvenance) {
        const prov = new ProvenanceVerifier()
        if (prov.checkCommandAvailable()) {
          const topLevel = parsed.entries.filter(e => !e.name.startsWith('@types/')).slice(0, 20)
          for (const entry of topLevel) {
            try { const r = await prov.verify(entry.name, entry.version); provResults.push(r) } catch {}
          }
        }
      }

      const doQuarantine = args.quarantine === 'true' || args.quarantine === '1'
      if (doQuarantine) {
        const qm = new QuarantineManager()
        if (qm.isEnabled()) {
          const criticalPkgs = osvResults.filter(r =>
            r.vulnerabilities.some(v => {
              const ms = OSVIntegrator.getMaxSeverity(v)
              return ms && ms.score >= 9.0
            })
          )
          for (const pkg of criticalPkgs) {
            try {
              const pkgPath = path.join(cwd, 'node_modules', pkg.packageName)
              if (fs.existsSync(pkgPath)) {
                qm.quarantinePackage(pkg.packageName, pkg.version, `Critical CVE: ${pkg.vulnerabilities[0]?.id || 'unknown'}`, 'CRITICAL')
              }
            } catch {}
          }
        }
      }

      const vulnsBySeverity = new Map<string, number>()
      let totalVulns = 0
      for (const r of osvResults) {
        for (const v of r.vulnerabilities) {
          totalVulns++
          const maxS = OSVIntegrator.getMaxSeverity(v)
          const sev = maxS ? OSVIntegrator.toSentinelSeverity(maxS.score) : 'MEDIUM'
          vulnsBySeverity.set(sev, (vulnsBySeverity.get(sev) || 0) + 1)
        }
      }

      const suspiciousRep = repResults.filter(r => r.label === 'SUSPICIOUS' || r.label === 'MALICIOUS')
      const verifiedProv = provResults.filter(r => r.verified)

      return JSON.stringify({
        packages: parsed.entries.length,
        format: parsed.format,
        vulnerabilities: totalVulns,
        bySeverity: Object.fromEntries(vulnsBySeverity),
        suspiciousPackages: suspiciousRep.length,
        provenance: verifiedProv.length,
        durationMs: Date.now() - startTime
      })
    }

    case 'deps-tree': {
      const { DepsScanner } = await import('../cli/intelligence/deps_scanner')
      const targetPath = path.resolve(args.path || 'node_modules')
      if (!fs.existsSync(targetPath)) {
        return JSON.stringify({ error: `Path not found: ${args.path || 'node_modules'}` })
      }
      const scanner = new DepsScanner()
      const depth = parseInt(args.depth || '3', 10)
      const nodes = scanner.walkTree(targetPath, depth)
      const result = scanner.scanTree(nodes)
      return JSON.stringify(result)
    }

    case 'trust-cache': {
      const { TrustCache } = await import('../cli/intelligence/trust_cache')
      const cache = new TrustCache()
      const action = args.action || 'status'
      if (action === 'status') {
        const s = cache.stats()
        return JSON.stringify({ entries: s.entries, oldest: s.oldest, newest: s.newest })
      } else if (action === 'clear') {
        cache.clear()
        return JSON.stringify({ action: 'clear', status: 'ok' })
      } else if (action === 'prune') {
        const removed = cache.prune()
        return JSON.stringify({ action: 'prune', removed })
      }
      return JSON.stringify({ error: `Unknown trust-cache action: ${action}` })
    }

    case 'sbom': {
      const { LockfileParser } = await import('../cli/intelligence/lockfile_parser')
      const cwd = process.cwd()
      let lockfilePath = args.lockfile || ''
      if (!lockfilePath) {
        const candidates = ['package-lock.json', 'yarn.lock']
        for (const c of candidates) {
          const testPath = path.join(cwd, c)
          if (fs.existsSync(testPath)) { lockfilePath = testPath; break }
        }
      }
      if (!lockfilePath || !fs.existsSync(lockfilePath)) {
        return JSON.stringify({ error: 'No lockfile found' })
      }

      const parser = new LockfileParser()
      const parsed = parser.parse(lockfilePath)

      const components = parsed.entries.map(e => ({
        type: 'library',
        name: e.name,
        version: e.version,
        purl: `pkg:npm/${e.name.replace('@', '%40')}@${e.version}`,
        ...(e.resolved ? { properties: [{ name: 'resolved', value: e.resolved }] } : {})
      }))

      return JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion: '1.4',
        version: 1,
        metadata: {
          timestamp: new Date().toISOString(),
          tools: [{ vendor: 'Sentinel', name: 'sentinel-cli', version: '5.0' }],
          properties: [{ name: 'lockfile', value: path.basename(lockfilePath) }]
        },
        components
      }, null, 2)
    }

    case 'policy': {
      const policyDir = path.join(os.homedir(), '.sentinel')
      const policyFile = path.join(policyDir, 'policy.json')
      if (!fs.existsSync(policyDir)) fs.mkdirSync(policyDir, { recursive: true })

      let policies: Record<string, string> = {}
      try { policies = JSON.parse(fs.readFileSync(policyFile, 'utf8')) } catch {}

      const action = args.action || 'list'
      if (action === 'list') {
        return JSON.stringify({ action: 'list', policies })
      } else if (action === 'get') {
        const key = args.key || ''
        return JSON.stringify({ action: 'get', key, value: policies[key] || null })
      } else if (action === 'set') {
        const key = args.key || ''
        const value = args.value || ''
        const validKeys = ['ci-mode', 'fail-closed', 'quarantine']
        if (!validKeys.includes(key)) {
          return JSON.stringify({ error: `Invalid key. Valid: ${validKeys.join(', ')}` })
        }
        const validValues: Record<string, string[]> = {
          'ci-mode': ['strict', 'lenient'],
          'fail-closed': ['on', 'off'],
          'quarantine': ['on', 'off']
        }
        if (validValues[key] && !validValues[key].includes(value)) {
          return JSON.stringify({ error: `Invalid value for ${key}. Valid: ${validValues[key].join(' | ')}` })
        }
        policies[key] = value
        fs.writeFileSync(policyFile, JSON.stringify(policies, null, 2))
        return JSON.stringify({ action: 'set', key, value, status: 'ok' })
      }
      return JSON.stringify({ error: `Unknown policy action: ${action}` })
    }

    default:
      return null
  }
}

async function handleMcpMessage(msg: JsonRpcMessage): Promise<JsonRpcResponse | null> {
  if (msg.id === undefined || msg.id === null) {
    return null;
  }

  switch (msg.method) {
    case 'list_tools': {
      return {
        jsonrpc: '2.0',
        id: msg.id,
        result: { tools: toolDefs },
      };
    }

    case 'call_tool': {
      const { name, arguments: args } = msg.params;
      const toolArgs: Record<string, string> = args || {};

      try {
        const text = await runA2Tool(name, toolArgs) ?? await runMcpTool(name, toolArgs);

        return {
          jsonrpc: '2.0',
          id: msg.id,
          result: { content: [{ type: 'text', text }] },
        };
      } catch (e: any) {
        return {
          jsonrpc: '2.0',
          id: msg.id,
          result: { content: [{ type: 'text', text: `Error: ${e.message}` }] },
        };
      }
    }

    default: {
      return {
        jsonrpc: '2.0',
        id: msg.id,
        error: { code: -32601, message: `Method not found: ${msg.method}` },
      };
    }
  }
}

export function startMcpServer(options?: { port?: number; http?: boolean }): void {
  const port = options?.port || 3003;

  if (options?.http) {
    startHttpServer(port);
  } else {
    startStdioServer(port);
  }
}

function startStdioServer(port: number): void {
  const rl = readline.createInterface({ input: process.stdin });

  rl.on('line', async (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    let msg: JsonRpcMessage;
    try {
      msg = JSON.parse(trimmed);
    } catch (e: any) {
      const errResp: JsonRpcResponse = {
        jsonrpc: '2.0',
        id: null,
        error: { code: -32700, message: `Parse error: ${e.message}` },
      };
      process.stdout.write(JSON.stringify(errResp) + '\n');
      return;
    }

    try {
      const response = await handleMcpMessage(msg);
      if (response) {
        process.stdout.write(JSON.stringify(response) + '\n');
      }
    } catch (e: any) {
      const errResp: JsonRpcResponse = {
        jsonrpc: '2.0',
        id: msg.id ?? null,
        error: { code: -32603, message: `Internal error: ${e.message}` },
      };
      process.stdout.write(JSON.stringify(errResp) + '\n');
    }
  });

  rl.on('close', () => {
    process.exit(0);
  });

  console.error(`MCP server running (stdio mode, port ${port})`);
  console.error('Connect any MCP client (Claude Desktop, Cursor, Cline) to this process.');
}

function startHttpServer(port: number): void {
  const server = http.createServer((req, res) => {
    const { method, headers } = req;

    if (method === 'POST') {
      let body = '';
      req.on('data', (chunk: Buffer) => { body += chunk.toString(); });
      req.on('end', async () => {
        let msg: JsonRpcMessage;
        try {
          msg = JSON.parse(body);
        } catch (e: any) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            jsonrpc: '2.0',
            id: null,
            error: { code: -32700, message: `Parse error: ${e.message}` },
          }));
          return;
        }

        try {
          const response = await handleMcpMessage(msg);
          if (response) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(response));
          } else {
            res.writeHead(204);
            res.end();
          }
        } catch (e: any) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            jsonrpc: '2.0',
            id: msg.id ?? null,
            error: { code: -32603, message: `Internal error: ${e.message}` },
          }));
        }
      });
    } else if (method === 'GET' && headers.accept === 'text/event-stream') {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
      });
      res.write(`data: ${JSON.stringify({ jsonrpc: '2.0', method: 'connected', params: {} })}\n\n`);
    } else {
      res.writeHead(405, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Method not allowed' }));
    }
  });

  server.listen(port, () => {
    console.error(`MCP HTTP server listening on http://localhost:${port}`);
    console.error('Connect via SSE at http://localhost:' + port);
  });
}
