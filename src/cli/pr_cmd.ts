import * as readline from 'readline';
import { execFileSync, execSync } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import * as pc from 'picocolors';
import { listKeys, getKey, maskToken, DISCLAIMER_TEXT, StoredKey } from './cloud_keys_cmd';
import { LiteScanner, LiteFinding } from '../core/lite/lite_scanner';
import { PRProgressMap } from './pr_progress';
import { fetchCapabilities, fetchCloudPRScan, fetchUsage, getResolvedBaseUrl } from './cloud/cloud_client';

interface PRInfo {
  number: number;
  title: string;
  author?: { login: string };
  headRefName?: string;
  headRefOid?: string;
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
      if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo)) {
        console.log(pc.red('Repositorio inválido. Usa el formato owner/repo.'));
        continue;
      }

      // 3. Enumerar PRs abiertos
      console.log(`\nConsultando Pull Requests abiertos en ${repo}...`);
      let prList: PRInfo[] = [];
      try {
        if (!/^[\w.-]+\/[\w.-]+$/.test(repo)) throw new Error('Repositorio inválido; usa owner/repo.');
        const raw = execFileSync('gh', ['pr', 'list', '--repo', repo, '--json', 'number,title,author,headRefName,headRefOid', '--limit', '15'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
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
      if (engineChoice !== '1' && engineChoice !== '2') {
        console.log(pc.yellow('Selecciona 1 o 2 para elegir un motor.'));
        continue;
      }
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

      const useCloud = engineChoice === '2' && !!selectedKey;
      const progress = new PRProgressMap(useCloud ? 'cloud' : 'lite', prNumber);
      let findings: LiteFinding[] = [];
      let verdict = 'PASS';
      let riskScore = 0;
      let cloudVersion = '';
      let authorInfo = prList.find(p => p.number === prNumber)?.author?.login || 'unknown';
      let activeStage = 'PR';
      try {
        progress.update({ stage: 'PR', state: 'RUNNING', detail: `resolviendo head de PR #${prNumber}` });
        const listed = prList.find(p => p.number === prNumber);
        const metadata = listed?.headRefOid ? listed : JSON.parse(execFileSync('gh', ['pr', 'view', String(prNumber), '--repo', repo, '--json', 'headRefOid,author'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }));
        const headSha = String(metadata.headRefOid || '');
        if (!/^[0-9a-f]{40}$/i.test(headSha)) throw new Error('GitHub no devolvió el SHA completo del head del PR.');
        authorInfo = metadata.author?.login || authorInfo;
        progress.update({ stage: 'PR', state: 'COMPLETE', detail: `head ${headSha.slice(0, 12)}` });

        if (useCloud) {
          activeStage = 'SOURCE';
          progress.update({ stage: 'SOURCE', state: 'COMPLETE', detail: `Cloud resolverá el PR completo en el SHA ${headSha.slice(0, 12)}` });

          activeStage = 'AUTH';
          progress.update({ stage: 'AUTH', state: 'RUNNING', detail: 'validando permiso remote_scan' });
          const baseUrl = getResolvedBaseUrl(undefined, process.env);
          const capabilities = await fetchCapabilities(selectedKey!.token, baseUrl);
          if (!capabilities.ok) throw new Error(`No se pudo validar la clave Sentinel Cloud${capabilities.status ? ` (HTTP ${capabilities.status})` : ''}.`);
          if (!capabilities.data.capabilities.remote_scan) throw new Error('El plan de esta clave no tiene habilitado remote_scan.');
          progress.update({ stage: 'AUTH', state: 'COMPLETE', detail: `plan ${capabilities.data.planLabel}` });

          activeStage = 'ENGINE';
          progress.update({ stage: 'ENGINE', state: 'RUNNING', detail: 'Cloud analiza el PR completo; esta solicitud consume 1 pulso' });
          const remote = await fetchCloudPRScan(repo, prNumber, headSha, selectedKey!.token, baseUrl);
          if (!remote.ok) throw new Error(remote.kind === 'quota' ? 'Cuota de pulsos agotada.' : remote.kind === 'busy' ? 'El motor Cloud está ocupado; no completó este análisis.' : remote.kind === 'auth' ? 'La clave de Sentinel Cloud fue rechazada.' : remote.error || `Sentinel Cloud no completó el análisis${remote.status ? ` (HTTP ${remote.status})` : ''}.`);
          const cloudResult = remote.data;
          cloudVersion = cloudResult.engine_version || 'desconocida';
          verdict = String(cloudResult.level1.status || 'UNKNOWN').toUpperCase();
          riskScore = typeof cloudResult.level1.score === 'number' ? cloudResult.level1.score : 0;
          findings = (cloudResult.level3?.samples || []).map((f) => {
            const severity = String(f.severity || f.riskLevel || 'INFO').toUpperCase();
            const title = String(f.title || f.type || f.detector || 'Cloud finding');
            const description = String(f.description || f.message || f.why || title);
            const file = String(f.file || f._file || f._fullPath || 'unknown');
            const line = Number(f.line || f.line_number || 0) || 0;
            const snippet = String(f.snippet || f.evidence || '');
            return { type: String(f.type || f.detector || 'cloud'), intent: String(f.category || 'Sentinel Cloud finding'), file, line, severity, title, description, snippet };
          });
          progress.update({ stage: 'ENGINE', state: 'COMPLETE', detail: `motor Cloud ${cloudVersion}; ${findings.length} hallazgos; ${cloudResult.scan_degraded ? 'análisis degradado' : verdict}` });
          activeStage = 'RESULT';
          progress.update({ stage: 'RESULT', state: 'COMPLETE', detail: `respuesta agregada ${verdict}` });
          const usage = await fetchUsage(selectedKey!.token, baseUrl);
          if (usage.ok) console.log(pc.dim(`Pulsos: ${usage.data.remaining} restantes de ${usage.data.limit}.`));
        } else {
          activeStage = 'DIFF';
          progress.update({ stage: 'DIFF', state: 'RUNNING', detail: 'descargando diff con GitHub CLI' });
          const diff = execFileSync('gh', ['pr', 'diff', String(prNumber), '--repo', repo], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 32 * 1024 * 1024 });
          progress.update({ stage: 'DIFF', state: 'COMPLETE', detail: `${Buffer.byteLength(diff, 'utf8')} bytes` });
          activeStage = 'ENGINE';
          progress.update({ stage: 'ENGINE', state: 'RUNNING', detail: 'Sentinel Lite analiza el diff local' });
          const files = parseUnifiedDiff(diff);
          const scanner = new LiteScanner();
          const auditResult = await scanner.auditPR(repo, prNumber, authorInfo, files);
          findings = auditResult.findings || [];
          progress.update({ stage: 'ENGINE', state: 'COMPLETE', detail: `${findings.length} señales locales` });
          const c = findings.filter(f => f.severity === 'CRITICAL').length;
          const h = findings.filter(f => f.severity === 'HIGH').length;
          const m = findings.filter(f => f.severity === 'MEDIUM').length;
          const l = findings.filter(f => f.severity === 'LOW').length;
          riskScore = c ? Math.min(100, 70 + c * 10) : h ? Math.min(69, 40 + h * 10) : m ? Math.min(39, 15 + m * 5) : l ? 10 : 0;
          verdict = c || h >= 2 ? 'BLOCK' : h || m ? 'FLAG' : 'PASS';
          activeStage = 'RESULT';
          progress.update({ stage: 'RESULT', state: 'COMPLETE', detail: `resultado Lite ${verdict}` });
        }
      } catch (err: any) {
        progress.update({ stage: activeStage, state: 'FAILED', detail: err.message || String(err) });
        progress.finish();
        console.log(pc.red(`No se completó el análisis: ${err.message || err}`));
        continue;
      } finally {
        progress.finish();
      }
      const criticalCount = findings.filter(f => f.severity.toUpperCase() === 'CRITICAL').length;
      const highCount = findings.filter(f => f.severity.toUpperCase() === 'HIGH').length;
      const mediumCount = findings.filter(f => f.severity.toUpperCase() === 'MEDIUM').length;
      const lowCount = findings.filter(f => ['LOW', 'WARNING'].includes(f.severity.toUpperCase())).length;

      console.log('\n' + pc.cyan('──────────────────────────────────────────────────────────'));
      console.log(pc.bold(`RESULTADO DEL ESCANEO: PR #${prNumber} (${repo})`));
      console.log(pc.dim(cloudVersion ? `Motor: Sentinel Cloud ${cloudVersion}; alcance: análisis completo del PR en el SHA fijado.` : 'Motor: Sentinel Lite local; alcance: diff del pull request.'));
      const verdictColor = verdict === 'BLOCK' ? pc.red : (verdict === 'FLAG' ? pc.yellow : pc.green);
      console.log(`VEREDICTO:  ${verdictColor(`[ ${verdict} ]`)}  ·  RIESGO: ${riskScore}/100`);
      console.log(`HALLAZGOS:  CRITICAL: ${criticalCount} | HIGH: ${highCount} | MEDIUM: ${mediumCount} | LOW: ${lowCount}`);
      console.log(pc.cyan('──────────────────────────────────────────────────────────'));

      if (findings.length > 0) {
        findings.slice(0, 10).forEach((f, idx) => {
          console.log(`  ${idx + 1}. [${f.severity}] ${f.title || f.type} (${f.file}:${f.line || 0})`);
          if (f.snippet) console.log(pc.dim(`     > ${f.snippet.replace(/\n/g, ' ').slice(0, 100)}`));
        });
        if (findings.length > 10) {
          console.log(pc.dim(`     ... y ${findings.length - 10} hallazgo(s) más.`));
        }
      } else {
        console.log(pc.green('  Sin hallazgos reportados por el motor seleccionado.'));
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
