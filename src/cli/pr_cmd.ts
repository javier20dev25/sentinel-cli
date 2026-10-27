import * as readline from 'readline';
import { execSync } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import * as pc from 'picocolors';
import { listKeys, getKey, maskToken, DISCLAIMER_TEXT, StoredKey } from './cloud_keys_cmd';
import { LiteScanner, LiteFinding } from '../core/lite/lite_scanner';

interface PRInfo {
  number: number;
  title: string;
  author?: { login: string };
  headRefName?: string;
}

function checkGitHubSession(): { authenticated: boolean; account: string; method: string } {
  try {
    const out = execSync('gh auth status', { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    const match = out.match(/account\s+([\w\d_-]+)/i) || out.match(/Logged in to [^\s]+ account ([\w\d_-]+)/i);
    return {
      authenticated: true,
      account: match ? match[1] : 'GitHub CLI active',
      method: 'gh_cli'
    };
  } catch (_) {
    if (process.env.GITHUB_TOKEN || process.env.GH_TOKEN) {
      return {
        authenticated: true,
        account: 'Environment Token',
        method: 'env_token'
      };
    }
    return { authenticated: false, account: '', method: '' };
  }
}

function detectCurrentRepo(): string {
  try {
    const url = execSync('git remote get-url origin', { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
    const m = url.match(/[:/]([\w\d_.-]+)\/([\w\d_.-]+?)(\.git)?$/);
    if (m) return `${m[1]}/${m[2]}`;
  } catch (_) {}
  return 'javier20dev25/Merx';
}

function parseUnifiedDiff(diffText: string): Array<{ filename: string; patch: string }> {
  const files: Array<{ filename: string; patch: string }> = [];
  const fileBlocks = diffText.split(/^diff --git /m);

  for (const block of fileBlocks) {
    if (!block.trim()) continue;
    const lines = block.split('\n');
    let filename = 'unknown';

    for (const l of lines) {
      if (l.startsWith('+++ b/')) {
        filename = l.replace('+++ b/', '').trim();
        break;
      }
    }
    if (filename === 'unknown') {
      const match = lines[0].match(/b\/(.*)$/);
      if (match) filename = match[1].trim();
    }

    files.push({
      filename,
      patch: block
    });
  }

  return files;
}

function exportToMarkdown(result: {
  repo: string;
  prNumber: number;
  author: string;
  verdict: string;
  riskScore: number;
  counts: { critical: number; high: number; medium: number; low: number };
  findings: LiteFinding[];
}): { fullPath: string; bytes: number } {
  const downloadsDir = path.join(os.homedir(), 'Downloads');
  if (!fs.existsSync(downloadsDir)) {
    fs.mkdirSync(downloadsDir, { recursive: true });
  }

  const safeRepo = result.repo.replace('/', '_');
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `sentinel-pr-${result.prNumber}-${safeRepo}-${timestamp}.md`;
  const fullPath = path.join(downloadsDir, filename);

  const lines: string[] = [
    `# 🛡️ Sentinel Security Audit — Reporte de Pull Request`,
    ``,
    `> **AVISO LEGAL:** ${DISCLAIMER_TEXT}`,
    ``,
    `## Metadatos del Análisis`,
    `- **Repositorio:** \`${result.repo}\``,
    `- **Pull Request:** #${result.prNumber}`,
    `- **Autor del PR:** @${result.author}`,
    `- **Fecha de Escaneo:** ${new Date().toISOString()}`,
    `- **Veredicto Sentinel:** **${result.verdict}**`,
    `- **Puntuación de Riesgo:** ${result.riskScore} / 100`,
    `- **Total Hallazgos:** ${result.findings.length}`,
    ``,
    `## Resumen de Severidades`,
    `| Severidad | Total |`,
    `|:---|:---:|`,
    `| 🔴 CRITICAL | ${result.counts.critical} |`,
    `| 🟠 HIGH | ${result.counts.high} |`,
    `| 🟡 MEDIUM | ${result.counts.medium} |`,
    `| 🔵 LOW | ${result.counts.low} |`,
    ``,
    `## Detalle de Hallazgos`,
    ``
  ];

  if (result.findings.length === 0) {
    lines.push(`_No se detectaron vectores maliciosos, credenciales expuestas ni artefactos sospechosos en el diff auditado._\n`);
  } else {
    result.findings.forEach((f, idx) => {
      lines.push(`### ${idx + 1}. [${f.severity}] ${f.title || f.type}`);
      lines.push(`- **Archivo:** \`${f.file}\` (Línea ${f.line || 0})`);
      lines.push(`- **Categoría:** \`${f.category || 'general'}\` | **Subcódigo:** \`${f.subcode || 'N/A'}\``);
      lines.push(`- **Descripción:** ${f.description}`);
      if (f.snippet) {
        lines.push(``);
        lines.push('```javascript');
        lines.push(f.snippet);
        lines.push('```');
      }
      lines.push(``);
    });
  }

  lines.push(`---`);
  lines.push(`*Generado por Sentinel CLI — Security Intelligence for AI Coding Agents*`);

  const content = lines.join('\n');
  fs.writeFileSync(fullPath, content, 'utf8');
  return { fullPath, bytes: Buffer.byteLength(content, 'utf8') };
}

export async function runPRWorkflow(options?: { repo?: string; prNumber?: number }) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const ask = (q: string): Promise<string> => new Promise(res => rl.question(q, a => res(a.trim())));

  try {
    console.log('\n' + pc.cyan('──────────────────────────────────────────────────────────'));
    console.log(pc.bold('🔍 SENTINEL CLI — AUDITORÍA DE PULL REQUESTS'));
    console.log(pc.dim(`⚖ ${DISCLAIMER_TEXT}`));
    console.log(pc.cyan('──────────────────────────────────────────────────────────'));

    // 1. Verificar sesión activa de GitHub
    const gh = checkGitHubSession();
    if (gh.authenticated) {
      console.log(pc.green(`✓ Sesión activa de GitHub: ${gh.account} (vía ${gh.method})`));
    } else {
      console.log(pc.yellow('⚠ No se detectó sesión activa de GitHub en la terminal.'));
      console.log('  1) Iniciar sesión con GitHub CLI (gh auth login)');
      console.log('  2) Ingresar GitHub Personal Access Token manualmente');
      console.log('  3) Continuar sin autenticación (solo repositorios públicos)');
      const authChoice = await ask('Selecciona [1-3] (default 3): ');
      if (authChoice === '1') {
        console.log('Lanzando gh auth login...');
        try {
          execSync('gh auth login -w', { stdio: 'inherit' });
        } catch (e: any) {
          console.log(pc.red(`Error al iniciar sesión: ${e.message}`));
        }
      } else if (authChoice === '2') {
        const token = await ask('Ingresa GITHUB_TOKEN: ');
        if (token) process.env.GITHUB_TOKEN = token;
      }
    }

    let keepRunning = true;
    while (keepRunning) {
      // 2. Repositorio a auditar
      const defaultRepo = options?.repo || detectCurrentRepo();
      const repoInput = await ask(`\nRepositorio [owner/repo] (default: ${defaultRepo}): `);
      const repo = repoInput || defaultRepo;

      // 3. Enumerar PRs abiertos
      console.log(`\nConsultando Pull Requests abiertos en ${repo}...`);
      let prList: PRInfo[] = [];
      try {
        const cmd = `gh pr list --repo ${repo} --json number,title,author,headRefName --limit 15`;
        const raw = execSync(cmd, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
        prList = JSON.parse(raw);
      } catch (err: any) {
        console.log(pc.yellow(`⚠ No se pudo enumerar vía gh (${err.message}).`));
      }

      if (prList.length > 0) {
        console.log(pc.bold(`\nPull Requests abiertos en ${repo}:`));
        prList.forEach(p => {
          const authorLogin = p.author?.login || 'unknown';
          console.log(`  #${p.number.toString().padEnd(4)} | ${p.title.slice(0, 50).padEnd(52)} | por @${authorLogin} (${p.headRefName || 'ref'})`);
        });
      } else {
        console.log('No se encontraron PRs abiertos automáticamente. Puedes especificar el número directamente.');
      }

      let prNumber = options?.prNumber;
      if (!prNumber) {
        const prNumStr = await ask('\nIngresa el número de PR a escanear: ');
        prNumber = parseInt(prNumStr, 10);
      }

      if (isNaN(prNumber) || prNumber <= 0) {
        console.log(pc.red('Número de PR inválido.'));
        return;
      }

      // 4. Seleccionar motor de escaneo
      const keys = listKeys();
      const hasCloudKey = keys.length > 0;

      console.log('\nSelecciona el motor de escaneo:');
      console.log('  1) Escáner Local (Motor Lite — SAST determinista offline)');
      if (hasCloudKey) {
        console.log(`  2) Usar Pulsos (Sentinel Cloud API) [${keys.length} clave(s) disponible(s)]`);
      } else {
        console.log(pc.dim('  2) [No disponible - Sin Cloud API Key configurada]'));
      }

      const engineChoice = await ask('Selecciona [1 o 2]: ');
      let selectedKey: StoredKey | null = null;

      if (engineChoice === '2') {
        if (!hasCloudKey) {
          console.log(pc.yellow('⚠ Opción no disponible. No hay claves de Sentinel Cloud en la máquina.'));
          continue;
        }
        if (keys.length === 1) {
          selectedKey = getKey(1);
          console.log(pc.cyan(`Usando ${selectedKey?.name} (${keys[0].maskedToken})`));
        } else {
          console.log('\nClaves de Sentinel Cloud disponibles:');
          keys.forEach(k => {
            console.log(`  ${k.index}) ${k.name.padEnd(20)} [${k.maskedToken}]`);
          });
          const keyChoice = parseInt(await ask(`Selecciona clave [1-${keys.length}]: `), 10);
          selectedKey = getKey(keyChoice) || getKey(1);
          console.log(pc.cyan(`Seleccionada: ${selectedKey?.name}`));
        }
      }

      // 5. Descargar Diff de GitHub
      console.log(`\nDescargando diff de PR #${prNumber} en ${repo}...`);
      let diff = '';
      try {
        diff = execSync(`gh pr diff ${prNumber} --repo ${repo}`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
      } catch (err: any) {
        console.log(pc.red(`Error al obtener diff de GitHub: ${err.message}`));
        return;
      }

      console.log(`Diff descargado (${Buffer.byteLength(diff, 'utf8')} bytes). Analizando con Motor Lite...`);
      const files = parseUnifiedDiff(diff);
      const scanner = new LiteScanner();
      const authorInfo = prList.find(p => p.number === prNumber)?.author?.login || 'unknown';

      const auditResult = await scanner.auditPR(repo, prNumber, authorInfo, files);
      const findings = auditResult.findings || [];

      const criticalCount = findings.filter(f => f.severity === 'CRITICAL').length;
      const highCount = findings.filter(f => f.severity === 'HIGH').length;
      const mediumCount = findings.filter(f => f.severity === 'MEDIUM').length;
      const lowCount = findings.filter(f => f.severity === 'LOW').length;

      let riskScore = 0;
      if (criticalCount > 0) riskScore = Math.min(100, 70 + criticalCount * 10);
      else if (highCount > 0) riskScore = Math.min(69, 40 + highCount * 10);
      else if (mediumCount > 0) riskScore = Math.min(39, 15 + mediumCount * 5);
      else if (lowCount > 0) riskScore = 10;

      let verdict = 'PASS';
      if (criticalCount > 0 || highCount >= 2) verdict = 'BLOCK';
      else if (highCount > 0 || mediumCount > 0) verdict = 'FLAG';

      console.log('\n' + pc.cyan('══════════════════════════════════════════════════════════'));
      console.log(pc.bold(`RESULTADO DEL ESCANEO: PR #${prNumber} (${repo})`));
      const verdictColor = verdict === 'BLOCK' ? pc.red : (verdict === 'FLAG' ? pc.yellow : pc.green);
      console.log(`VEREDICTO:  ${verdictColor(`[ ${verdict} ]`)}  ·  RIESGO: ${riskScore}/100`);
      console.log(`HALLAZGOS:  CRITICAL: ${criticalCount} | HIGH: ${highCount} | MEDIUM: ${mediumCount} | LOW: ${lowCount}`);
      console.log(pc.cyan('══════════════════════════════════════════════════════════'));

      if (findings.length > 0) {
        findings.slice(0, 10).forEach((f, idx) => {
          console.log(`  ${idx + 1}. [${f.severity}] ${f.title || f.type} (${f.file}:${f.line || 0})`);
          if (f.snippet) console.log(pc.dim(`     > ${f.snippet.replace(/\n/g, ' ').slice(0, 100)}`));
        });
        if (findings.length > 10) {
          console.log(pc.dim(`     ... y ${findings.length - 10} hallazgo(s) más.`));
        }
      } else {
        console.log(pc.green('  ✓ Sin hallazgos sospechosos ni credenciales expuestas.'));
      }

      // Post-scan menu
      while (true) {
        console.log('\nOpciones:');
        console.log('  1) Continuar / Terminar');
        console.log('  2) Volver a escanear otro PR');
        console.log('  3) Descargar reporte completo en Markdown (.md) en Descargas');
        const postChoice = await ask('Selecciona [1-3]: ');

        if (postChoice === '3') {
          const exported = exportToMarkdown({
            repo,
            prNumber,
            author: authorInfo,
            verdict,
            riskScore,
            counts: { critical: criticalCount, high: highCount, medium: mediumCount, low: lowCount },
            findings
          });
          console.log(pc.green(`\n✓ Reporte descargado exitosamente:`));
          console.log(`  📄 ${exported.fullPath} (${exported.bytes} bytes)`);
        } else if (postChoice === '2') {
          break; // re-run loop
        } else {
          keepRunning = false;
          break; // exit
        }
      }
    }
  } finally {
    rl.close();
  }
}
