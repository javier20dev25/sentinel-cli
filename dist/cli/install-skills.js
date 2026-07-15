"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.listDetectedAgents = listDetectedAgents;
exports.runInstall = runInstall;
exports.installSkillsCommand = installSkillsCommand;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const os = __importStar(require("os"));
const SKILLS_DIR = path.resolve(__dirname, '..', '..', 'skills');
function which(cmd) {
    const paths = process.env.PATH || '';
    const extensions = (process.env.PATHEXT || '').split(path.delimiter).filter(Boolean);
    const dirs = paths.split(path.delimiter);
    for (const dir of dirs) {
        for (const ext of ['', ...extensions]) {
            const full = path.join(dir, cmd + ext);
            if (fs.existsSync(full)) {
                try {
                    const real = fs.realpathSync(full);
                    return real;
                }
                catch (_a) {
                    return full;
                }
            }
        }
    }
    return null;
}
function home() {
    return os.homedir();
}
const agents = [
    {
        name: 'claude',
        detect: () => which('claude') !== null,
        install: () => installToDir(path.join(home(), '.claude', 'commands')),
        configKeys: ['~/.claude/commands/'],
    },
    {
        name: 'cursor',
        detect: () => which('cursor') !== null || fs.existsSync(path.join(home(), '.cursor')),
        install: () => installToDir(path.join(home(), '.cursor', 'rules')),
        configKeys: ['~/.cursor/rules/'],
    },
    {
        name: 'cline',
        detect: () => fs.existsSync(path.join(home(), '.vscode', 'extensions', 'saoudrizwan.claude-dev')),
        install: () => installToDir(path.join(home(), '.vscode', 'extensions', 'saoudrizwan.claude-dev', 'skills')),
        configKeys: ['.vscode/extensions/ saoudrizwan.claude-dev/skills/'],
    },
    {
        name: 'windsurf',
        detect: () => which('windsurf') !== null || fs.existsSync(path.join(home(), '.windsurf')),
        install: () => installToDir(home()),
        configKeys: ['~/.windsurfrules'],
    },
    {
        name: 'opencode',
        detect: () => which('opencode') !== null || fs.existsSync(path.join(home(), '.config', 'opencode')),
        install: () => installToDir(path.join(home(), '.config', 'opencode', 'skills')),
        configKeys: ['~/.config/opencode/skills/'],
    },
    {
        name: 'roo',
        detect: () => which('roo') !== null || fs.existsSync(path.join(home(), '.config', 'roo')),
        install: () => installToDir(path.join(home(), '.config', 'roo', 'skills')),
        configKeys: ['~/.config/roo/skills/'],
    },
    {
        name: 'gemini',
        detect: () => which('gemini') !== null,
        install: () => installToDir(path.join(home(), '.config', 'gemini', 'cli', 'skills')),
        configKeys: ['~/.config/gemini/cli/skills/'],
    },
    {
        name: 'codex',
        detect: () => which('codex') !== null,
        install: () => installToDir(path.join(home(), '.codex', 'skills')),
        configKeys: ['~/.codex/skills/'],
    },
];
function installToDir(targetDir) {
    const installed = [];
    const errors = [];
    if (!fs.existsSync(SKILLS_DIR)) {
        errors.push(`Skills directory not found: ${SKILLS_DIR}`);
        return { installed, errors };
    }
    if (!fs.existsSync(targetDir)) {
        try {
            fs.mkdirSync(targetDir, { recursive: true });
        }
        catch (e) {
            errors.push(`Cannot create target directory ${targetDir}: ${e.message}`);
            return { installed, errors };
        }
    }
    const entries = fs.readdirSync(SKILLS_DIR, { withFileTypes: true });
    for (const entry of entries) {
        const srcPath = path.join(SKILLS_DIR, entry.name);
        const dstPath = path.join(targetDir, entry.name);
        try {
            if (fs.statSync(dstPath)) {
                if (fs.statSync(srcPath).mtimeMs <= fs.statSync(dstPath).mtimeMs &&
                    fs.readFileSync(srcPath, 'utf-8') === fs.readFileSync(dstPath, 'utf-8')) {
                    continue;
                }
            }
        }
        catch (_a) {
            // dst doesn't exist, continue to copy
        }
        try {
            fs.cpSync(srcPath, dstPath, { recursive: true });
            installed.push(`${entry.name} -> ${targetDir}`);
        }
        catch (e) {
            errors.push(`Failed to copy ${entry.name} to ${targetDir}: ${e.message}`);
        }
    }
    return { installed, errors };
}
function listDetectedAgents() {
    return agents.map((a) => ({
        name: a.name,
        detected: a.detect(),
    }));
}
function runInstall(targetAgents) {
    const results = [];
    const selected = targetAgents
        ? agents.filter((a) => targetAgents.includes(a.name))
        : agents.filter((a) => a.detect());
    if (selected.length === 0) {
        const detected = agents.filter((a) => a.detect()).map((a) => a.name);
        if (detected.length === 0) {
            results.push({
                agent: '*',
                installed: [],
                errors: ['No supported agents detected on this system. Install an agent first, or specify one with --agent.'],
            });
        }
        else {
            for (const agent of agents) {
                if (agent.detect()) {
                    results.push(Object.assign({ agent: agent.name }, agent.install()));
                }
            }
        }
        return { results };
    }
    for (const agent of selected) {
        results.push(Object.assign({ agent: agent.name }, agent.install()));
    }
    return { results };
}
function printResults(results) {
    for (const r of results) {
        if (r.installed.length > 0) {
            console.log(`  [OK] ${r.agent}: ${r.installed.length} file(s) installed`);
            for (const f of r.installed) {
                console.log(`       ${f}`);
            }
        }
        if (r.errors.length > 0) {
            console.log(`  [!!] ${r.agent}: ${r.errors.length} error(s)`);
            for (const e of r.errors) {
                console.log(`       ${e}`);
            }
        }
    }
}
function installSkillsCommand(args) {
    const helpFlags = ['--help', '-h'];
    const listFlags = ['--list', '--detect', '-d'];
    const allFlag = ['--all', '-a'];
    const agentFlag = '--agent';
    if (args.some((a) => helpFlags.includes(a))) {
        console.log(`
Usage: sentinel install-skills [options]

Install Sentinel skills files for detected AI coding agents.

Options:
  --list, --detect, -d    List detected agents and exit
  --all, -a               Install for all agents (even if undetected)
  --agent <name>          Target a specific agent (repeatable)
  --help, -h              Show this help

Supported agents: ${agents.map((a) => a.name).join(', ')}

Skill files are copied from skills/ to each agent's config directory:
`);
        for (const agent of agents) {
            console.log(`  ${agent.name}: ${agent.configKeys.join(', ')}`);
        }
        console.log('');
        return;
    }
    if (args.some((a) => listFlags.includes(a))) {
        const detected = listDetectedAgents();
        console.log('Detected agents:');
        for (const a of detected) {
            console.log(`  ${a.detected ? '[OK]' : '[--]'} ${a.name}`);
        }
        return;
    }
    const targetAgents = [];
    if (args.some((a) => allFlag.includes(a))) {
        for (const agent of agents) {
            targetAgents.push(agent.name);
        }
    }
    for (let i = 0; i < args.length; i++) {
        if (args[i] === agentFlag && i + 1 < args.length) {
            targetAgents.push(args[i + 1]);
            i++;
        }
    }
    const { results } = runInstall(targetAgents.length > 0 ? targetAgents : undefined);
    printResults(results);
    const allOk = results.every((r) => r.errors.length === 0);
    if (!allOk) {
        process.exitCode = 1;
    }
}
