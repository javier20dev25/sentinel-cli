/**
 * Ollama Auto-Setup — detecta, inicia y descarga modelos automáticamente.
 * Diseñado para que el usuario no necesite configurar nada manualmente.
 */
import { execFileSync, spawn } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as readline from 'readline';
import * as pc from 'picocolors';

const DEFAULT_MODEL = 'qwen3:1.5b';
const OLLAMA_API = 'http://localhost:11434';
const OLLAMA_DOWNLOAD_URL = 'https://ollama.com/download/OllamaSetup.exe';

export interface OllamaStatus {
  installed: boolean;
  running: boolean;
  models: string[];
  hasModel: boolean;
  targetModel: string;
}

/** Check if Ollama is installed by looking for the binary */
export function isOllamaInstalled(): boolean {
  try {
    // Use execFileSync to avoid shell wrapping (no "where" PowerShell messages)
    const bin = process.platform === 'win32' ? 'where' : 'which';
    execFileSync(bin, ['ollama'], { encoding: 'utf-8', windowsHide: true, timeout: 5000 });
    return true;
  } catch {
    if (process.platform === 'win32') {
      const commonPaths = [
        path.join(process.env.LOCALAPPDATA || '', 'Programs', 'Ollama', 'ollama.exe'),
        path.join(process.env.PROGRAMFILES || '', 'Ollama', 'ollama.exe'),
        'C:\\Users\\' + (process.env.USERNAME || '') + '\\AppData\\Local\\Programs\\Ollama\\ollama.exe',
      ];
      for (const p of commonPaths) {
        if (p && fs.existsSync(p)) return true;
      }
    }
    return false;
  }
}

/** Get the Ollama binary path */
function getOllamaBin(): string {
  try {
    if (process.platform === 'win32') {
      return execFileSync('where', ['ollama'], { encoding: 'utf-8', windowsHide: true, timeout: 5000 }).trim().split('\n')[0];
    }
    return execFileSync('which', ['ollama'], { encoding: 'utf-8', timeout: 5000 }).trim();
  } catch {
    if (process.platform === 'win32') {
      const commonPaths = [
        path.join(process.env.LOCALAPPDATA || '', 'Programs', 'Ollama', 'ollama.exe'),
        'C:\\Users\\' + (process.env.USERNAME || '') + '\\AppData\\Local\\Programs\\Ollama\\ollama.exe',
      ];
      for (const p of commonPaths) {
        if (p && fs.existsSync(p)) return p;
      }
    }
    return 'ollama';
  }
}

/** Check if Ollama API is reachable */
export async function isOllamaRunning(): Promise<boolean> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);
    const res = await fetch(`${OLLAMA_API}/api/tags`, { signal: controller.signal });
    clearTimeout(timeout);
    return res.ok;
  } catch {
    return false;
  }
}

/** Start Ollama serve in background */
export async function startOllama(): Promise<boolean> {
  const bin = getOllamaBin();
  console.log(pc.gray(`  Starting Ollama service (${bin})...`));
  try {
    const child = spawn(bin, ['serve'], {
      detached: true,
      stdio: 'ignore',
      windowsHide: true,
    });
    child.unref();

    // Wait up to 10 seconds for it to start
    for (let i = 0; i < 20; i++) {
      await new Promise(r => setTimeout(r, 500));
      if (await isOllamaRunning()) {
        console.log(pc.green('  ✓ Ollama service started'));
        return true;
      }
    }
    console.log(pc.yellow('  ⚠ Ollama may be slow to start. Continuing anyway...'));
    return await isOllamaRunning();
  } catch (e: any) {
    console.log(pc.red(`  ✗ Could not start Ollama: ${e.message}`));
    return false;
  }
}

/** List installed models from Ollama API */
export async function listModels(): Promise<string[]> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    const res = await fetch(`${OLLAMA_API}/api/tags`, { signal: controller.signal });
    clearTimeout(timeout);
    if (!res.ok) return [];
    const data = await res.json() as { models?: { name: string }[] };
    return (data.models || []).map(m => m.name);
  } catch {
    return [];
  }
}

/** Pull a model using Ollama CLI */
export async function pullModel(model: string): Promise<boolean> {
  const bin = getOllamaBin();
  console.log(pc.cyan(`\n  Downloading model: ${pc.bold(model)}...`));
  console.log(pc.gray('  This may take a few minutes on first run.\n'));
  try {
    execFileSync(bin, ['pull', model], {
      encoding: 'utf-8',
      timeout: 600000, // 10 minutes max
      stdio: 'inherit', // Show download progress
      windowsHide: true,
    });
    console.log(pc.green(`\n  ✓ Model ${model} downloaded successfully`));
    return true;
  } catch (e: any) {
    console.log(pc.red(`\n  ✗ Failed to download model: ${e.message}`));
    return false;
  }
}

/** Check full Ollama status */
export async function checkOllamaStatus(targetModel?: string): Promise<OllamaStatus> {
  const model = targetModel || DEFAULT_MODEL;
  const installed = isOllamaInstalled();
  if (!installed) {
    return { installed: false, running: false, models: [], hasModel: false, targetModel: model };
  }
  const running = await isOllamaRunning();
  if (!running) {
    return { installed: true, running: false, models: [], hasModel: false, targetModel: model };
  }
  const models = await listModels();
  // Check if any installed model matches (handle tag variations like 'qwen3:1.5b' vs 'qwen3:1.5b-q4_0')
  const hasModel = models.some(m => m.startsWith(model.split(':')[0]) && 
    (m === model || m.startsWith(model)));
  return { installed: true, running: true, models, hasModel, targetModel: model };
}

/**
 * Download Ollama installer and run it silently.
 * Returns true if installation was successful.
 */
async function downloadAndInstallOllama(): Promise<boolean> {
  const installerPath = path.join(os.tmpdir(), 'OllamaSetup.exe');
  const downloadUrl = OLLAMA_DOWNLOAD_URL;

  console.log(pc.cyan('\n  Downloading Ollama installer...'));
  try {
    const response = await fetch(downloadUrl);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const buffer = Buffer.from(await response.arrayBuffer());
    fs.writeFileSync(installerPath, buffer);
    console.log(pc.green(`  ✓ Downloaded (${(buffer.length / 1024 / 1024).toFixed(1)} MB)`));

    console.log(pc.cyan('  Running installer (this may require admin approval)...'));
    execFileSync(installerPath, ['/SILENT'], {
      timeout: 120000,
      windowsHide: true,
      stdio: 'pipe',
    });
    console.log(pc.green('  ✓ Ollama installed successfully'));
    console.log(pc.gray('  Please wait a moment for the service to initialize...\n'));
    return true;
  } catch (e: any) {
    console.log(pc.red(`  ✗ Installation failed: ${e.message}`));
    console.log(pc.gray('  Install manually from: https://ollama.com/download\n'));
    return false;
  }
}

/**
 * Full auto-setup: ensure Ollama is installed, running, and has the target model.
 * Returns true if everything is ready.
 */
export async function ensureOllamaReady(targetModel?: string): Promise<boolean> {
  const model = targetModel || DEFAULT_MODEL;

  // Step 1: Check if installed
  if (!isOllamaInstalled()) {
    console.log(pc.yellow('\n  ⚠ Ollama is not installed (required for local AI models).'));
    console.log(pc.gray('  Sentinels Oracle uses Ollama to run AI models locally.\n'));

    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const answer = await new Promise<string>(resolve => {
      rl.question(pc.cyan('  ¿Download and install Ollama automatically? [Y/n] '), resolve);
    });
    rl.close();

    if (answer.toLowerCase() === 'n' || answer.toLowerCase() === 'no') {
      console.log(pc.gray('  Install manually from: https://ollama.com/download'));
      console.log(pc.gray('  Then run sentinel oracle again.\n'));
      return false;
    }

    console.log();
    const installed = await downloadAndInstallOllama();
    if (!installed) return false;

    // Wait for service to register
    await new Promise(r => setTimeout(r, 3000));
  }

  // Step 2: Start if not running
  if (!(await isOllamaRunning())) {
    const started = await startOllama();
    if (!started) {
      console.log(pc.red('\n  ✗ Could not start Ollama service.'));
      console.log(pc.gray('  Try running "ollama serve" in another terminal.\n'));
      return false;
    }
  }

  // Step 3: Check if model exists, pull if not
  const models = await listModels();
  const hasModel = models.some(m => m.startsWith(model.split(':')[0]) && 
    (m === model || m.startsWith(model)));
  
  if (!hasModel) {
    console.log(pc.yellow(`\n  Model "${model}" not found locally.`));
    console.log(pc.gray(`  Installed models: ${models.length > 0 ? models.join(', ') : '(none)'}\n`));
    const pulled = await pullModel(model);
    if (!pulled) return false;
  }

  return true;
}
