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
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.isOllamaInstalled = isOllamaInstalled;
exports.isOllamaRunning = isOllamaRunning;
exports.startOllama = startOllama;
exports.listModels = listModels;
exports.pullModel = pullModel;
exports.checkOllamaStatus = checkOllamaStatus;
exports.ensureOllamaReady = ensureOllamaReady;
/**
 * Ollama Auto-Setup — detecta, inicia y descarga modelos automáticamente.
 * Diseñado para que el usuario no necesite configurar nada manualmente.
 */
const child_process_1 = require("child_process");
const fs = __importStar(require("fs"));
const os = __importStar(require("os"));
const path = __importStar(require("path"));
const readline = __importStar(require("readline"));
const pc = __importStar(require("picocolors"));
const DEFAULT_MODEL = 'qwen3:1.5b';
const OLLAMA_API = 'http://localhost:11434';
const OLLAMA_DOWNLOAD_URL = 'https://ollama.com/download/OllamaSetup.exe';
/** Check if Ollama is installed by looking for the binary */
function isOllamaInstalled() {
    try {
        // Use execFileSync to avoid shell wrapping (no "where" PowerShell messages)
        const bin = process.platform === 'win32' ? 'where' : 'which';
        (0, child_process_1.execFileSync)(bin, ['ollama'], { encoding: 'utf-8', windowsHide: true, timeout: 5000 });
        return true;
    }
    catch (_a) {
        if (process.platform === 'win32') {
            const commonPaths = [
                path.join(process.env.LOCALAPPDATA || '', 'Programs', 'Ollama', 'ollama.exe'),
                path.join(process.env.PROGRAMFILES || '', 'Ollama', 'ollama.exe'),
                'C:\\Users\\' + (process.env.USERNAME || '') + '\\AppData\\Local\\Programs\\Ollama\\ollama.exe',
            ];
            for (const p of commonPaths) {
                if (p && fs.existsSync(p))
                    return true;
            }
        }
        return false;
    }
}
/** Get the Ollama binary path */
function getOllamaBin() {
    try {
        if (process.platform === 'win32') {
            return (0, child_process_1.execFileSync)('where', ['ollama'], { encoding: 'utf-8', windowsHide: true, timeout: 5000 }).trim().split('\n')[0];
        }
        return (0, child_process_1.execFileSync)('which', ['ollama'], { encoding: 'utf-8', timeout: 5000 }).trim();
    }
    catch (_a) {
        if (process.platform === 'win32') {
            const commonPaths = [
                path.join(process.env.LOCALAPPDATA || '', 'Programs', 'Ollama', 'ollama.exe'),
                'C:\\Users\\' + (process.env.USERNAME || '') + '\\AppData\\Local\\Programs\\Ollama\\ollama.exe',
            ];
            for (const p of commonPaths) {
                if (p && fs.existsSync(p))
                    return p;
            }
        }
        return 'ollama';
    }
}
/** Check if Ollama API is reachable */
function isOllamaRunning() {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 3000);
            const res = yield fetch(`${OLLAMA_API}/api/tags`, { signal: controller.signal });
            clearTimeout(timeout);
            return res.ok;
        }
        catch (_a) {
            return false;
        }
    });
}
/** Start Ollama serve in background */
function startOllama() {
    return __awaiter(this, void 0, void 0, function* () {
        const bin = getOllamaBin();
        console.log(pc.gray(`  Starting Ollama service (${bin})...`));
        try {
            const child = (0, child_process_1.spawn)(bin, ['serve'], {
                detached: true,
                stdio: 'ignore',
                windowsHide: true,
            });
            child.unref();
            // Wait up to 10 seconds for it to start
            for (let i = 0; i < 20; i++) {
                yield new Promise(r => setTimeout(r, 500));
                if (yield isOllamaRunning()) {
                    console.log(pc.green('  ✓ Ollama service started'));
                    return true;
                }
            }
            console.log(pc.yellow('  ⚠ Ollama may be slow to start. Continuing anyway...'));
            return yield isOllamaRunning();
        }
        catch (e) {
            console.log(pc.red(`  ✗ Could not start Ollama: ${e.message}`));
            return false;
        }
    });
}
/** List installed models from Ollama API */
function listModels() {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 5000);
            const res = yield fetch(`${OLLAMA_API}/api/tags`, { signal: controller.signal });
            clearTimeout(timeout);
            if (!res.ok)
                return [];
            const data = yield res.json();
            return (data.models || []).map(m => m.name);
        }
        catch (_a) {
            return [];
        }
    });
}
/** Pull a model using Ollama CLI */
function pullModel(model) {
    return __awaiter(this, void 0, void 0, function* () {
        const bin = getOllamaBin();
        console.log(pc.cyan(`\n  Downloading model: ${pc.bold(model)}...`));
        console.log(pc.gray('  This may take a few minutes on first run.\n'));
        try {
            (0, child_process_1.execFileSync)(bin, ['pull', model], {
                encoding: 'utf-8',
                timeout: 600000, // 10 minutes max
                stdio: 'inherit', // Show download progress
                windowsHide: true,
            });
            console.log(pc.green(`\n  ✓ Model ${model} downloaded successfully`));
            return true;
        }
        catch (e) {
            console.log(pc.red(`\n  ✗ Failed to download model: ${e.message}`));
            return false;
        }
    });
}
/** Check full Ollama status */
function checkOllamaStatus(targetModel) {
    return __awaiter(this, void 0, void 0, function* () {
        const model = targetModel || DEFAULT_MODEL;
        const installed = isOllamaInstalled();
        if (!installed) {
            return { installed: false, running: false, models: [], hasModel: false, targetModel: model };
        }
        const running = yield isOllamaRunning();
        if (!running) {
            return { installed: true, running: false, models: [], hasModel: false, targetModel: model };
        }
        const models = yield listModels();
        // Check if any installed model matches (handle tag variations like 'qwen3:1.5b' vs 'qwen3:1.5b-q4_0')
        const hasModel = models.some(m => m.startsWith(model.split(':')[0]) &&
            (m === model || m.startsWith(model)));
        return { installed: true, running: true, models, hasModel, targetModel: model };
    });
}
/**
 * Download Ollama installer and run it silently.
 * Returns true if installation was successful.
 */
function downloadAndInstallOllama() {
    return __awaiter(this, void 0, void 0, function* () {
        const installerPath = path.join(os.tmpdir(), 'OllamaSetup.exe');
        const downloadUrl = OLLAMA_DOWNLOAD_URL;
        console.log(pc.cyan('\n  Downloading Ollama installer...'));
        try {
            const response = yield fetch(downloadUrl);
            if (!response.ok)
                throw new Error(`HTTP ${response.status}`);
            const buffer = Buffer.from(yield response.arrayBuffer());
            fs.writeFileSync(installerPath, buffer);
            console.log(pc.green(`  ✓ Downloaded (${(buffer.length / 1024 / 1024).toFixed(1)} MB)`));
            console.log(pc.cyan('  Running installer (this may require admin approval)...'));
            (0, child_process_1.execFileSync)(installerPath, ['/SILENT'], {
                timeout: 120000,
                windowsHide: true,
                stdio: 'pipe',
            });
            console.log(pc.green('  ✓ Ollama installed successfully'));
            console.log(pc.gray('  Please wait a moment for the service to initialize...\n'));
            return true;
        }
        catch (e) {
            console.log(pc.red(`  ✗ Installation failed: ${e.message}`));
            console.log(pc.gray('  Install manually from: https://ollama.com/download\n'));
            return false;
        }
    });
}
/**
 * Full auto-setup: ensure Ollama is installed, running, and has the target model.
 * Returns true if everything is ready.
 */
function ensureOllamaReady(targetModel) {
    return __awaiter(this, void 0, void 0, function* () {
        const model = targetModel || DEFAULT_MODEL;
        // Step 1: Check if installed
        if (!isOllamaInstalled()) {
            console.log(pc.yellow('\n  ⚠ Ollama is not installed (required for local AI models).'));
            console.log(pc.gray('  Sentinels Oracle uses Ollama to run AI models locally.\n'));
            const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
            const answer = yield new Promise(resolve => {
                rl.question(pc.cyan('  ¿Download and install Ollama automatically? [Y/n] '), resolve);
            });
            rl.close();
            if (answer.toLowerCase() === 'n' || answer.toLowerCase() === 'no') {
                console.log(pc.gray('  Install manually from: https://ollama.com/download'));
                console.log(pc.gray('  Then run sentinel oracle again.\n'));
                return false;
            }
            console.log();
            const installed = yield downloadAndInstallOllama();
            if (!installed)
                return false;
            // Wait for service to register
            yield new Promise(r => setTimeout(r, 3000));
        }
        // Step 2: Start if not running
        if (!(yield isOllamaRunning())) {
            const started = yield startOllama();
            if (!started) {
                console.log(pc.red('\n  ✗ Could not start Ollama service.'));
                console.log(pc.gray('  Try running "ollama serve" in another terminal.\n'));
                return false;
            }
        }
        // Step 3: Check if model exists, pull if not
        const models = yield listModels();
        const hasModel = models.some(m => m.startsWith(model.split(':')[0]) &&
            (m === model || m.startsWith(model)));
        if (!hasModel) {
            console.log(pc.yellow(`\n  Model "${model}" not found locally.`));
            console.log(pc.gray(`  Installed models: ${models.length > 0 ? models.join(', ') : '(none)'}\n`));
            const pulled = yield pullModel(model);
            if (!pulled)
                return false;
        }
        return true;
    });
}
