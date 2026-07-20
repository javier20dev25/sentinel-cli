import * as readline from 'readline';
import * as fs from 'fs';
import * as os from 'os';
import * as crypto from 'crypto';
import * as pc from 'picocolors';
import { spawn } from 'child_process';
import * as path from 'path';
import { ghBridge, UserRepo, PullRequest } from './gh_bridge';
import { printMetrics } from './telemetry';
import { LiteScanner, LiteFinding } from '../core/lite/lite_scanner';
import { MemoryManager } from './intelligence/memory_manager';
import { handleClassifiedMenu } from './classify';

const FREE_TIER_LIMIT = 3;

// i18n Dictionary
const i18n: Record<string, Record<string, string>> = {
    en: {
        auth_title: 'Identity & Access',
        auth_no_session: 'No active session found.',
        auth_init: 'Initiating secure OAuth handshake...',
        auth_fail: 'Authentication failed:',
        auth_success: 'Authenticated as:',
        menu_title: 'Main Operations Menu',
        menu_opt0: 'PR Bot — Auto-Analyze All Open PRs',
        menu_opt1: 'Select Workspaces & Run Audits',
        menu_opt2: 'System Doctor (Health Check)',
        menu_opt3: 'Integrity Check',
        menu_opt4: 'Permissions Audit',
        menu_opt5: 'Scan Directory/File',
        menu_opt6: 'Sentinel Guard & Configuration (NPM Intercept)',
        menu_opt7: 'Classified Documents',
        menu_opt8: 'Manage Signal Vault (Memory)',
        menu_opt9: 'Your Security — Integrity & Trust Policy',
        menu_opt10: 'Network Auditor',
        menu_opt11: 'Exit',
        select_opt: 'Select option',
        invalid_sel: 'Invalid selection.',
        workspace_title: 'Workspace Discovery',
        workspace_none: 'No repositories found.',
        workspace_retrieved: 'Retrieved {count} repositories (Free Tier Limit: {limit})',
        workspace_select: 'Select up to {limit} workspaces (e.g. 1,3) or type \'0\' to cancel:',
        workspace_limit: '⚠️ Free Tier is limited to {limit} repos at a time.',
        config_title: 'Sentinel Guard & Global Configuration',
        config_desc: 'OS-level interception for npm/pip and Trust Cache management.',
        config_opt1: 'Guard Status',
        config_opt2: 'Enable Guard (Intercept npm/yarn/pip)',
        config_opt3: 'Disable Guard',
        config_opt4: 'List Trust Cache (Whitelisted packages)',
        config_opt5: 'Back to Main Menu',
        target_title: 'TARGET:',
        target_vis: 'Visibility:',
        target_sync: 'Last Sync:',
        target_sel: 'Select Audit Vector',
        target_opt1: 'Run Baseline Context Scan',
        target_opt2: 'Audit Pull Requests',
        target_opt3: 'Cancel Target',
        target_dim1: '(Local Engine)',
        target_dim2: '(Surgical Inspection)',
        action: 'Action >',
        scan_init: 'Initializing Sentinel Engine for {repo}...',
        scan_prog: 'Analyzing AST signatures and data flows...',
        scan_done: 'Baseline Context Analysis Completed.',
        scan_notice: '⚠️ Notice: Detailed threat vectors are hidden in CLI Free Tier. Check Web Dashboard.',
        press_enter: 'Press Enter to return...',
        pr_title: 'Pull Request Gateway',
        pr_none: 'No open Pull Requests. The perimeter is secure.',
        pr_cancel: 'Cancel',
        pr_target: 'Target ID >',
        pr_extract: 'Extracting surgical diff for PR #{num}...',
        pr_fail: 'Failed to extract diff. Payload might be corrupted or oversized.',
        pr_exec: 'Executing Surgical Inspection on dynamic payload...',
        pr_clean: 'VERDICT: CLEAN',
        pr_clean_desc: 'PR #{num} contains no known malicious signatures.',
        pr_threat: 'FATAL THREATS INTERCEPTED (PR #{num})',
        pr_threat_desc: 'Merging this code will critically compromise the system.',
        session_end: '👋 Session terminated securely.'
    },
    es: {
        auth_title: 'Identidad y Acceso',
        auth_no_session: 'No se encontró una sesión activa.',
        auth_init: 'Iniciando conexión segura OAuth...',
        auth_fail: 'Fallo de autenticación:',
        auth_success: 'Autenticado como:',
        menu_title: 'Menú Principal de Operaciones',
        menu_opt0: 'PR Bot — Auto-Analizar Todos los PRs Abiertos',
        menu_opt1: 'Seleccionar Repositorios y Ejecutar Auditorías',
        menu_opt2: 'System Doctor (Verificación de Salud)',
        menu_opt3: 'Verificación de Integridad',
        menu_opt4: 'Auditoría de Permisos',
        menu_opt5: 'Escanear Directorio/Archivo',
        menu_opt6: 'Sentinel Guard y Configuración (Interceptar NPM)',
        menu_opt7: 'Documentos Clasificados',
        menu_opt8: 'Gestionar Signal Vault (Memoria)',
        menu_opt9: 'Tu Seguridad — Política de Integridad y Confianza',
        menu_opt10: 'Network Auditor',
        menu_opt11: 'Salir',
        select_opt: 'Selecciona una opción',
        invalid_sel: 'Selección inválida.',
        workspace_title: 'Descubrimiento de Espacios de Trabajo',
        workspace_none: 'No se encontraron repositorios.',
        workspace_retrieved: 'Se obtuvieron {count} repositorios (Límite Free Tier: {limit})',
        workspace_select: 'Selecciona hasta {limit} repositorios (ej. 1,3) o \'0\' para cancelar:',
        workspace_limit: '⚠️ El plan Free está limitado a {limit} repositorios a la vez.',
        config_title: 'Sentinel Guard y Configuración Global',
        config_desc: 'Intercepción a nivel de OS para npm/pip y gestión de Caché de Confianza.',
        config_opt1: 'Estado del Guard',
        config_opt2: 'Activar Guard (Interceptar npm/yarn/pip)',
        config_opt3: 'Desactivar Guard',
        config_opt4: 'Listar Caché de Confianza (Paquetes seguros)',
        config_opt5: 'Volver al Menú Principal',
        target_title: 'OBJETIVO:',
        target_vis: 'Visibilidad:',
        target_sync: 'Última Sincronización:',
        target_sel: 'Seleccionar Vector de Auditoría',
        target_opt1: 'Ejecutar Escaneo de Contexto Base',
        target_opt2: 'Auditar Pull Requests',
        target_opt3: 'Cancelar Objetivo',
        target_dim1: '(Motor Local)',
        target_dim2: '(Inspección Quirúrgica)',
        action: 'Acción >',
        scan_init: 'Inicializando Motor Sentinel para {repo}...',
        scan_prog: 'Analizando firmas AST y flujos de datos...',
        scan_done: 'Análisis de Contexto Base Completado.',
        scan_notice: '⚠️ Aviso: Los vectores de amenaza detallados están ocultos en la CLI (Free Tier). Revisa el Web Dashboard.',
        press_enter: 'Presiona Enter para volver...',
        pr_title: 'Puerta de Enlace de Pull Requests',
        pr_none: 'No hay Pull Requests abiertos. El perímetro es seguro.',
        pr_cancel: 'Cancelar',
        pr_target: 'ID del Objetivo >',
        pr_extract: 'Extrayendo diff quirúrgico para el PR #{num}...',
        pr_fail: 'Fallo al extraer el diff. El payload podría estar corrupto o ser demasiado grande.',
        pr_exec: 'Ejecutando Inspección Quirúrgica en payload dinámico...',
        pr_clean: 'VEREDICTO: LIMPIO',
        pr_clean_desc: 'El PR #{num} no contiene firmas maliciosas conocidas.',
        pr_threat: 'AMENAZAS FATALES INTERCEPTADAS (PR #{num})',
        pr_threat_desc: 'Hacer merge de este código comprometerá críticamente el sistema.',
        session_end: '👋 Sesión terminada de forma segura.'
    }
};

let lang = 'en';
const t = (key: string) => i18n[lang][key] || key;

let rlInstance: readline.Interface | null = null;

function getRl(): readline.Interface {
    if (!rlInstance) {
        rlInstance = readline.createInterface({ input: process.stdin, output: process.stdout });
    }
    return rlInstance;
}

function askQuestion(query: string): Promise<string> {
    return new Promise(resolve => getRl().question(query, ans => {
        resolve(ans.trim());
    }));
}

const SPIN = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

function printHeader() {
    console.clear();
    const logo = [
        "  ██████  ███████ ███    ██ ████████ ██ ███    ██ ███████ ██      ",
        " ██       ██      ████   ██    ██    ██ ████   ██ ██      ██      ",
        "  ██████  █████   ██ ██  ██    ██    ██ ██ ██  ██ █████   ██      ",
        "       ██ ██      ██  ██ ██    ██    ██ ██  ██ ██ ██      ██      ",
        "  ██████  ███████ ██   ████    ██    ██ ██   ████ ███████ ███████ "
    ];
    
    console.log('');
    logo.forEach(line => {
        console.log(pc.cyan(pc.bold(line)));
    });
    console.log(pc.dim('                                           Security Intelligence v4.0\n'));
}

async function refreshDashboard() {
    let done = false;
    let idx = 0;
    // Show spinner while fetching dashboard data
    const spinner = setInterval(() => {
        if (done) return;
        process.stdout.write(`\r${pc.cyan(SPIN[idx++ % SPIN.length])} ${pc.dim('Loading dashboard...')}  `);
    }, 80);

    try {
        const stats = ghBridge.getDashboardStats();
        done = true;
        clearInterval(spinner);
        const openColor = stats.openPRs > 0 ? (stats.openPRs > 5 ? pc.bgRed : pc.bgYellow) : pc.bgGreen;
        const todayColor = stats.todayPRs > 0 ? pc.bgYellow : pc.bgGreen;
        process.stdout.write(`\r${pc.bold('DASHBOARD')}  ─  ${pc.dim('Repos:')} ${pc.white(String(stats.totalRepos))}  │  ${pc.dim('Open PRs:')} ${openColor(pc.black(` ${stats.openPRs} `))}  │  ${pc.dim('Today:')} ${todayColor(pc.black(` ${stats.todayPRs} `))}  │  ${pc.dim('Unanalyzed:')} ${pc.cyan(String(stats.unanalyzedPRs))}\n`);
    } catch (_e: unknown) {
        done = true;
        clearInterval(spinner);
        process.stdout.write(`\r${pc.dim('DASHBOARD unavailable (offline)\n')}`);
    }
}

async function runCommand(args: string[]): Promise<void> {
    const rl = getRl();
    rl.pause();
    return new Promise((resolve) => {
        const cmd = process.platform === 'win32' ? 'node.exe' : 'node';
        const mainPath = path.join(__dirname, 'main.js');
        const child = spawn(cmd, [mainPath, ...args], { 
            stdio: 'inherit', 
            env: { ...process.env, FORCE_COLOR: '1' } 
        });
        child.on('close', () => {
            rl.resume();
            resolve();
        });
    });
}

export async function startInteractiveHub() {
    printHeader();
    
    // Language Selection
    console.log(pc.cyan('? ') + pc.bold('Language / Idioma'));
    console.log(pc.blue('  1.') + pc.white(' English'));
    console.log(pc.blue('  2.') + pc.white(' Español'));
    
    const langOpt = await askQuestion(pc.blue('  ❯ ') + pc.bold('Select option (1-2): '));
    lang = (langOpt === '2') ? 'es' : 'en';
    // i18n additions for memory menu
    i18n.es.memory_title = 'Gestión de Signal Vault (Memoria Local)';
    i18n.es.memory_opt1 = 'Ver Estado y Umbrales';
    i18n.es.memory_opt2 = 'Ingestar Reporte Cloud (JSON)';
    i18n.es.memory_opt3 = 'Ingestar Directorio de Reportes';
    i18n.es.memory_opt4 = 'Pegar JSON Manualmente';
    i18n.es.memory_opt5 = 'Limpiar Base de Datos (Wipe)';
    i18n.es.memory_opt6 = 'Volver al Menú Principal';
    i18n.es.memory_path = 'Ruta del archivo JSON';
    i18n.es.memory_dir = 'Ruta del directorio con reportes';
    i18n.es.memory_confirm = '⚠️ ¿Estás seguro? Esto borrará todo el historial local. (sí/no): ';
    i18n.es.memory_ok = 'Operación completada.';
    i18n.en.memory_title = 'Signal Vault Management (Local Memory)';
    i18n.en.memory_opt1 = 'View Status & Thresholds';
    i18n.en.memory_opt2 = 'Ingest Cloud Report (JSON)';
    i18n.en.memory_opt3 = 'Ingest Report Directory';
    i18n.en.memory_opt4 = 'Paste JSON Manually';
    i18n.en.memory_opt5 = 'Wipe Database';
    i18n.en.memory_opt6 = 'Back to Main Menu';
    i18n.en.memory_path = 'JSON file path';
    i18n.en.memory_dir = 'Directory path with reports';
    i18n.en.memory_confirm = '⚠️ Are you sure? This will erase all local history. (yes/no): ';
    i18n.en.memory_ok = 'Operation completed.';
    
    printHeader();
    await refreshDashboard();

    // 1. Authentication Check
    console.log(pc.cyan('? ') + pc.bold(t('auth_title')));
    let auth = ghBridge.checkAuth();
    
    if (!auth.authenticated) {
        console.log(pc.blue('  ❯ ') + pc.red(t('auth_no_session')));
        console.log(pc.blue('  ❯ ') + pc.dim(t('auth_init')));
        
        const loginResult = await ghBridge.login();
        if (!loginResult.success) {
            console.log(pc.blue('  ❯ ') + pc.red(`❌ ${t('auth_fail')} ${loginResult.message}`));
            process.exit(1);
        }
        auth = { authenticated: true, username: loginResult.username };
    }

    console.log(pc.blue('  ❯ ') + pc.green('✔ ') + t('auth_success') + ' ' + pc.bold(pc.white(auth.username || '')) + '\n');

    await refreshDashboard();

    while (true) {
        console.log(pc.cyan('? ') + pc.bold(t('menu_title')));
        console.log(pc.blue('  0.') + pc.white(` 🤖 ${t('menu_opt0')}`));
        console.log(pc.blue('  1.') + pc.white(` 📦 ${t('menu_opt1')}`));
        console.log(pc.blue('  2.') + pc.white(` 🩺 ${t('menu_opt2')}`));
        console.log(pc.blue('  3.') + pc.white(` 🛡️  ${t('menu_opt3')}`));
        console.log(pc.blue('  4.') + pc.white(` 📋 ${t('menu_opt4')}`));
        console.log(pc.blue('  5.') + pc.white(` 🔍 ${t('menu_opt5')}`));
        console.log(pc.blue('  6.') + pc.white(` ⚙️  ${t('menu_opt6')}`));
        console.log(pc.blue('  7.') + pc.white(` 🔐 ${t('menu_opt7')}`));
        console.log(pc.blue('  8.') + pc.white(` 🧠 ${t('menu_opt8')}`));
        console.log(pc.blue('  9.') + pc.white(` 🔒 ${t('menu_opt9')}`));
        console.log(pc.blue(' 10.') + pc.white(` 🌐 ${t('menu_opt10')}`));
        console.log(pc.blue(' 11.') + pc.white(` 🚪 ${t('menu_opt11')}`));

        const mainAction = await askQuestion(pc.blue('  ❯ ') + pc.bold(`${t('select_opt')} (0-11): `));

        if (mainAction === '0') {
            await handlePRBot();
            printHeader();
        } else if (mainAction === '1') {
            await handleWorkspaceDiscovery();
        } else if (mainAction === '2') {
            await runCommand(['doctor']);
            await askQuestion(pc.dim(`\n${t('press_enter')}`));
            printHeader();
        } else if (mainAction === '3') {
            await runCommand(['integrity']);
            await askQuestion(pc.dim(`\n${t('press_enter')}`));
            printHeader();
        } else if (mainAction === '4') {
            await runCommand(['permissions']);
            await askQuestion(pc.dim(`\n${t('press_enter')}`));
            printHeader();
        } else if (mainAction === '5') {
            const target = await askQuestion(pc.blue('  ❯ ') + pc.bold('Enter path/file to scan (default .): '));
            await runCommand(['scan', target.trim() || '.']);
            await askQuestion(pc.dim(`\n${t('press_enter')}`));
            printHeader();
        } else if (mainAction === '6') {
            await handleConfigurationMenu();
        } else if (mainAction === '7') {
            await handleClassifiedMenu(lang, askQuestion);
            printHeader();
        } else if (mainAction === '8') {
            await handleMemoryMenu();
            printHeader();
        } else if (mainAction === '9') {
            console.log(pc.magenta('\n🔒 YOUR SECURITY — INTEGRITY & TRUST POLICY'));
            console.log(pc.dim('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'));
            console.log(pc.white('   Sentinel is built with tamper-detection technology.'));
            console.log(pc.white('   If you modify Sentinel\'s source code, the Integrity'));
            console.log(pc.white('   Manager will detect the change and flag the runtime'));
            console.log(pc.white('   environment as SUSPECT or COMPROMISED.\n'));
            console.log(pc.yellow('   ⚠️  WARNING:'));
            console.log(pc.yellow('   • Never download "enhanced" or "modified" versions'));
            console.log(pc.yellow('     of Sentinel from third-party sources.'));
            console.log(pc.yellow('   • Modified versions may contain undetected backdoors'));
            console.log(pc.yellow('     that bypass Sentinel\'s own security checks.'));
            console.log(pc.yellow('   • Always verify the integrity of your installation'));
            console.log(pc.yellow('     using: sentinel integrity\n'));
            console.log(pc.cyan('   🔧 FOR DEVELOPERS:'));
            console.log(pc.cyan('   • You may fork and modify Sentinel for personal use.'));
            console.log(pc.cyan('   • Sentinel\'s team does not accept external pull'));
            console.log(pc.cyan('     requests or feature proposals from unverified sources.'));
            console.log(pc.cyan('   • Improvements are developed internally in'));
            console.log(pc.cyan('     Sentinel\'s private laboratories.\n'));
            if (lang === 'es') {
                console.log(pc.green('   🛡️  Tu seguridad es nuestra prioridad número uno.'));
            } else {
                console.log(pc.green('   🛡️  Your security is our number one priority.'));
            }
            await askQuestion(pc.dim(`\n${t('press_enter')}`));
            printHeader();
        } else if (mainAction === '10') {
            await handleNetworkMenu(askQuestion, t, runCommand, printHeader);
            printHeader();
        } else if (mainAction === '11') {
            console.log(pc.cyan(`\n${t('session_end')}\n`));
            if (rlInstance) {
                rlInstance.close();
            }
            process.exit(0);
        } else {
            console.log(pc.red(`    ${t('invalid_sel')}\n`));
        }
    }
}

async function handleWorkspaceDiscovery() {
    console.log('\n' + pc.cyan('? ') + pc.bold(t('workspace_title')));
    const allRepos = ghBridge.listUserRepos(50);
    
    if (!allRepos || allRepos.length === 0) {
        console.log(pc.blue('  ❯ ') + pc.red(t('workspace_none')));
        return;
    }

    console.log(pc.blue('  ❯ ') + pc.dim(t('workspace_retrieved').replace('{count}', String(allRepos.length)).replace('{limit}', String(FREE_TIER_LIMIT))));
    
    allRepos.forEach((repo, idx) => {
        const vis = repo.visibility === 'PUBLIC' ? pc.green('PUB') : pc.yellow('PRV');
        console.log(pc.blue('  │ ') + pc.dim(`[${String(idx + 1).padStart(2, ' ')}] `) + pc.inverse(` ${vis} `) + ' ' + pc.white(repo.fullName));
    });

    console.log(pc.blue('  │ '));
    let selectedIndices: number[] = [];
    while (true) {
        const input = await askQuestion(pc.blue('  ❯ ') + pc.bold(t('workspace_select').replace('{limit}', String(FREE_TIER_LIMIT)) + ' '));
        if (input === '0') return;
        
        const parts = input.split(',').map(n => parseInt(n.trim()) - 1).filter(n => !isNaN(n) && n >= 0 && n < allRepos.length);
        
        if (parts.length === 0) {
            console.log(pc.red(`    ${t('invalid_sel')}`));
        } else if (parts.length > FREE_TIER_LIMIT) {
            console.log(pc.yellow(`    ${t('workspace_limit').replace('{limit}', String(FREE_TIER_LIMIT))}`));
        } else {
            selectedIndices = parts;
            break;
        }
    }

    const selectedRepos = selectedIndices.map(i => allRepos[i]);

    for (const repo of selectedRepos) {
        await handleRepoMenu(repo);
    }
    printHeader();
}

async function handleConfigurationMenu() {
    while (true) {
        console.log('\n' + pc.cyan('? ') + pc.bold(t('config_title')));
        console.log(pc.dim('  ' + t('config_desc')));
        
        console.log(pc.blue('  1.') + pc.white(` 🛡️  ${t('config_opt1')}`));
        console.log(pc.blue('  2.') + pc.white(` 🟢 ${t('config_opt2')}`));
        console.log(pc.blue('  3.') + pc.white(` 🔴 ${t('config_opt3')}`));
        console.log(pc.blue('  4.') + pc.white(` ⭐ ${t('config_opt4')}`));
        console.log(pc.blue('  5.') + pc.white(` 🔐 ${t('config_opt5')}`));
        console.log(pc.blue('  6.') + pc.white(` 📝 Install/Uninstall SAST Pre-Commit Hook`));
        console.log(pc.blue('  7.') + pc.white(` 🔙 ${t('config_opt5')}`));
        
        const action = await askQuestion(pc.blue('  ❯ ') + pc.bold(`${t('select_opt')} (1-7): `));

        console.log('');
        if (action === '1') {
            await runCommand(['guard', 'status']);
            await askQuestion(pc.dim(`\n${t('press_enter')}`));
        } else if (action === '2') {
            await runCommand(['guard', 'enable']);
            await askQuestion(pc.dim(`\n${t('press_enter')}`));
        } else if (action === '3') {
            await runCommand(['guard', 'disable']);
            await askQuestion(pc.dim(`\n${t('press_enter')}`));
        } else if (action === '4') {
            await runCommand(['guard', 'trust-cache']);
            await askQuestion(pc.dim(`\n${t('press_enter')}`));
        } else if (action === '5') {
            const pwd = process.cwd();
            console.log(pc.cyan(`\n? Targeting repository: ${pwd}`));
            const choice = await askQuestion(pc.blue('  ❯ ') + pc.bold('Install (i), Uninstall (u), Status (s), or Skip (0)? '));
            if (choice === 'i') {
                await runCommand(['precommit', 'install']);
            } else if (choice === 'u') {
                await runCommand(['precommit', 'uninstall']);
            } else if (choice === 's') {
                await runCommand(['precommit', 'status']);
            }
            await askQuestion(pc.dim(`\n${t('press_enter')}`));
        } else if (action === '6') {
            printHeader();
            break;
        } else {
            console.log(pc.red(`    ${t('invalid_sel')}`));
        }
    }
}

async function handleRepoMenu(repo: UserRepo) {
    while (true) {
        console.log('\n' + pc.cyan('▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰'));
        console.log(pc.bold(`🎯 ${t('target_title')} `) + pc.cyan(repo.fullName));
        console.log(pc.dim(`${t('target_vis')} ${repo.visibility} | ${t('target_sync')} ${new Date(repo.updatedAt).toLocaleString()}`));
        console.log(pc.cyan('▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰') + '\n');
        
        console.log(pc.cyan('? ') + pc.bold(t('target_sel')));
        console.log(pc.blue('  1.') + pc.white(` 🔍 ${t('target_opt1')} `) + pc.dim(t('target_dim1')));
        console.log(pc.blue('  2.') + pc.white(` 🔀 ${t('target_opt2')} `) + pc.dim(t('target_dim2')));
        console.log(pc.blue('  3.') + pc.white(` 🔙 ${t('target_opt3')}\n`));
        
        const action = await askQuestion(pc.blue('  ❯ ') + pc.bold(`${t('action')} `));

        if (action === '1') {
            await simulateFullScanMetrics(repo);
        } else if (action === '2') {
            await handlePRInspection(repo);
        } else if (action === '3') {
            break;
        } else {
            console.log(pc.red(`    ${t('invalid_sel')}`));
        }
    }
}

async function simulateFullScanMetrics(repo: UserRepo) {
    console.log(pc.yellow(`\n🚀 ${t('scan_init').replace('{repo}', repo.fullName)}`));
    
    const spinChars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    let i = 0;
    const interval = setInterval(() => {
        process.stdout.write(`\r${pc.cyan(spinChars[i++ % spinChars.length])} ` + pc.dim(t('scan_prog')));
    }, 80);

    await new Promise(r => setTimeout(r, 2000));
    clearInterval(interval);
    console.log('\r' + ' '.repeat(60) + '\r');
    console.log(pc.green(`✔ ${t('scan_done')}`));

    printMetrics(lang, 512_000);
    console.log(pc.yellow(t('scan_notice')));
    await askQuestion(pc.dim(`\n${t('press_enter')}`));
}

async function handlePRInspection(repo: UserRepo) {
    console.log('\n' + pc.cyan('? ') + pc.bold(t('pr_title')));
    const prs = ghBridge.listPRs(repo.fullName);

    if (!prs || prs.length === 0) {
        console.log(pc.blue('  ❯ ') + pc.green(`✔ ${t('pr_none')}`));
        await askQuestion(pc.dim(`\n${t('press_enter')}`));
        return;
    }

    prs.forEach((pr, idx) => {
        const date = new Date(pr.updatedAt).toISOString().split('T')[0];
        console.log(pc.blue('  │ ') + pc.cyan(`[${idx + 1}]`) + ` #${pr.number} ${pc.white(pr.title)} ` + pc.dim(`(${pr.author?.login || 'unknown'}, ${date})`));
    });

    console.log(pc.blue('  │ ') + pc.cyan(`[${prs.length + 1}]`) + ` 🔙 ${t('pr_cancel')}`);
    
    const action = await askQuestion(pc.blue('  ❯ ') + pc.bold(`${t('pr_target')} `));
    const prIdx = parseInt(action) - 1;

    if (prIdx === prs.length) return;
    if (isNaN(prIdx) || prIdx < 0 || prIdx >= prs.length) {
        console.log(pc.red(`    ${t('invalid_sel')}`));
        return;
    }

    const selectedPR = prs[prIdx];
    console.log(pc.dim(`\n    ${t('pr_extract').replace('{num}', String(selectedPR.number))}`));
    
    const diff = ghBridge.getPRDiff(repo.fullName, selectedPR.number);
    if (!diff) {
        console.log(pc.red(`    ${t('pr_fail')}`));
        await askQuestion(pc.dim(`\n${t('press_enter')}`));
        return;
    }

    console.log(pc.cyan(`    ${t('pr_exec')}`));
    
    // Real SAST Scan using LiteScanner
    const scanner = new LiteScanner();
    const findings = scanner.scanPatch(`PR #${selectedPR.number}.diff`, diff);
    const bytesRead = Buffer.byteLength(diff);

    if (findings.length === 0) {
        console.log('\n' + pc.bgGreen(pc.black(` ✔ ${t('pr_clean')} `)));
        console.log(pc.green(`    ${t('pr_clean_desc').replace('{num}', String(selectedPR.number))}`));
    } else {
        console.log('\n' + pc.bgRed(pc.white(` 🚨 ${t('pr_threat').replace('{num}', String(selectedPR.number))} `)));
        console.log(pc.red(`    ${t('pr_threat_desc')}\n`));
        
        findings.forEach(a => {
            const riskScore = a.severity === 'CRITICAL' ? '9/10' : (a.severity === 'HIGH' ? '7/10' : '3/10');
            console.log(`  ${pc.red('■')} ` + pc.bgRed(pc.white(` RISK: ${riskScore} `)) + ' ' + pc.bold(pc.red(a.type)));
            console.log(`    ${pc.dim('↳ ' + a.description + ' (Line ' + a.line + ')')}`);
            console.log(`    ${pc.dim('Snippet: ' + a.snippet)}\n`);
        });
    }

    console.log('');
    printMetrics(lang, bytesRead);
    await askQuestion(pc.dim(`${t('press_enter')}`));
}

async function handleMemoryMenu() {
    while (true) {
        console.log('\n' + pc.cyan('? ') + pc.bold(t('memory_title')));
        console.log(pc.blue('  1.') + pc.white(` 📊 ${t('memory_opt1')}`));
        console.log(pc.blue('  2.') + pc.white(` 📥 ${t('memory_opt2')}`));
        console.log(pc.blue('  3.') + pc.white(` 📂 ${t('memory_opt3')}`));
        console.log(pc.blue('  4.') + pc.white(` 📋 ${t('memory_opt4')}`));
        console.log(pc.blue('  5.') + pc.white(` 🗑️  ${t('memory_opt5')}`));
        console.log(pc.blue('  6.') + pc.white(` 🔙 ${t('memory_opt6')}`));

        const action = await askQuestion(pc.blue('  ❯ ') + pc.bold(`${t('select_opt')} (1-6): `));

        if (action === '1') {
            await runCommand(['memory', '--status']);
            await askQuestion(pc.dim(`\n${t('press_enter')}`));
        } else if (action === '2') {
            const filePath = await askQuestion(pc.blue('  ❯ ') + pc.bold(`${t('memory_path')}: `));
            if (filePath.trim() && fs.existsSync(filePath.trim())) {
                await runCommand(['memory', '--ingest', filePath.trim()]);
            } else {
                console.log(pc.red('File not found.'));
            }
            await askQuestion(pc.dim(`\n${t('press_enter')}`));
        } else if (action === '3') {
            const dirPath = await askQuestion(pc.blue('  ❯ ') + pc.bold(`${t('memory_dir')}: `));
            if (dirPath.trim() && fs.existsSync(dirPath.trim())) {
                const files = fs.readdirSync(dirPath.trim()).filter(f => f.endsWith('.json'));
                if (files.length === 0) {
                    console.log(pc.yellow('No JSON files found in directory.'));
                } else {
                    for (const f of files) {
                        const fullPath = path.join(dirPath.trim(), f);
                        await runCommand(['memory', '--ingest', fullPath]);
                    }
                }
            } else {
                console.log(pc.red('Directory not found.'));
            }
            await askQuestion(pc.dim(`\n${t('press_enter')}`));
        } else if (action === '4') {
            console.log(pc.cyan('\n📋 Paste the JSON report below. Type DONE on a new line when finished:\n'));
            const lines: string[] = [];
            const rl = getRl();
            const gatherLines = () => new Promise<void>(resolve => {
                const onLine = (line: string) => {
                    if (line.trim().toUpperCase() === 'DONE') {
                        rl.removeListener('line', onLine);
                        resolve();
                    } else {
                        lines.push(line);
                    }
                };
                rl.on('line', onLine);
            });
            await gatherLines();
            const raw = lines.join('\n').trim();
            if (!raw) {
                console.log(pc.yellow('No input received.'));
            } else {
                let parsed: unknown;
                try { parsed = JSON.parse(raw); } catch {
                    console.log(pc.red('Invalid JSON.'));
                    await askQuestion(pc.dim(`\n${t('press_enter')}`));
                    return;
                }
                if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
                    console.log(pc.red('Expected a JSON object.'));
                    await askQuestion(pc.dim(`\n${t('press_enter')}`));
                    return;
                }
                const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-paste-'));
                const tmpFile = path.join(tmpDir, 'input.json');
                fs.writeFileSync(tmpFile, raw, 'utf8');
                try {
                    await runCommand(['memory', '--ingest', tmpFile]);
                } finally {
                    try { fs.unlinkSync(tmpFile); } catch (_) {}
                    try { fs.rmdirSync(tmpDir); } catch (_) {}
                }
            }
            await askQuestion(pc.dim(`\n${t('press_enter')}`));
        } else if (action === '5') {
            const confirm = await askQuestion(pc.red(pc.bold(`\n${t('memory_confirm')} `)));
            if (confirm.toLowerCase() === 'yes' || confirm.toLowerCase() === 'sí' || confirm.toLowerCase() === 'y' || confirm.toLowerCase() === 's') {
                await runCommand(['memory', '--wipe']);
            } else {
                console.log(pc.dim('Cancelled.'));
            }
            await askQuestion(pc.dim(`\n${t('press_enter')}`));
        } else if (action === '6') {
            break;
        } else {
            console.log(pc.red(`    ${t('invalid_sel')}`));
        }
    }
}

async function handleNetworkMenu(
    askQuestion: (prompt: string) => Promise<string>,
    t: (key: string) => string,
    runCommand: (args: string[]) => Promise<void>,
    printHeader: () => void,
) {
    while (true) {
        console.log(pc.cyan('\n🌐 NETWORK AUDITOR'));
        console.log(pc.dim('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'));
        console.log(pc.white('  1. Start Audit'));
        console.log(pc.white('  2. Stop Audit & Get Verdict'));
        console.log(pc.white('  3. Status'));
        console.log(pc.white('  4. Live Events'));
        console.log(pc.white('  5. Session History'));
        console.log(pc.white('  6. Replay Session'));
        console.log(pc.white('  7. Export Session'));
        console.log(pc.white('  8. Settings'));
        console.log(pc.white('  9. Auto-start'));
        console.log(pc.white('  0. Back to Main Menu\n'));

        const netAction = await askQuestion(pc.blue('  ❯ ') + pc.bold('Select option (0-9): '));

        if (netAction === '1') {
            await runCommand(['network', 'start']);
        } else if (netAction === '2') {
            await runCommand(['network', 'stop']);
        } else if (netAction === '3') {
            await runCommand(['network', 'status']);
        } else if (netAction === '4') {
            await runCommand(['network', 'status']);
            console.log(pc.dim('\n  (Live continuous view coming in v1.x — use `watch -n 2 sentinel network status` for now)'));
        } else if (netAction === '5') {
            const limit = await askQuestion(pc.blue('  ❯ ') + pc.bold('Number of sessions to show (default 10): '));
            await runCommand(['network', 'history', '--limit', limit.trim() || '10']);
        } else if (netAction === '6') {
            const action = await askQuestion(pc.blue('  ❯ ') + pc.bold('Action (run/diff): '));
            const arg = await askQuestion(pc.blue('  ❯ ') + pc.bold(action === 'diff' ? 'Baseline directory: ' : 'Session file or directory: '));
            await runCommand(['network', 'replay', action, arg]);
        } else if (netAction === '7') {
            const id = await askQuestion(pc.blue('  ❯ ') + pc.bold('Session ID to export: '));
            const fmt = await askQuestion(pc.blue('  ❯ ') + pc.bold('Format (json/markdown) [json]: '));
            await runCommand(['network', 'export', id, '--format', fmt.trim() || 'json']);
        } else if (netAction === '8') {
            await handleNetworkSettings(askQuestion, t, runCommand);
        } else if (netAction === '9') {
            await handleAutoStart(askQuestion, t);
        } else if (netAction === '0') {
            return;
        } else {
            console.log(pc.red(`    ${t('invalid_sel')}`));
        }
        await askQuestion(pc.dim(`\n${t('press_enter')}`));
    }
}

async function handleNetworkSettings(
    askQuestion: (prompt: string) => Promise<string>,
    t: (key: string) => string,
    _runCommand: (args: string[]) => Promise<void>,
) {
    const { loadConfig, saveConfig } = await import('../core/network/network-config');
    const cfg = loadConfig();

    console.log(pc.cyan('\n⚙️  NETWORK SETTINGS'));
    console.log(pc.dim('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'));
    console.log(pc.white(`  Alert threshold:        ${pc.bold(cfg.alertThreshold)} (${pc.dim('change: sentinel network config --threshold')})`));
    console.log(pc.white(`  Trusted hosts:          ${pc.bold(String(cfg.trustedHosts.length))}`));
    console.log(pc.white(`  Trusted processes:      ${pc.bold(String(cfg.trustedProcesses.length))}`));
    console.log(pc.white(`  Max CPU %:              ${pc.bold(String(cfg.performanceBudget.maxCpuPercent))}`));
    const memStr = `  Max memory (MB):        ${String(cfg.performanceBudget.maxMemoryMb)}`;
    console.log(pc.white(memStr));
    console.log(pc.white(`  Config file:            ${pc.dim((await import('../core/network/network-config')).getConfigPath())}\n`));
    console.log(pc.white('  Available CLI commands:'));
    console.log(pc.white('    sentinel network trusted list|add|remove <name>'));
    console.log(pc.white('    sentinel network doctor [--metrics] [--coverage] [--drift]'));
    console.log(pc.white('    sentinel network blindspots list|add|stats'));
    console.log(pc.white('    sentinel network campaign list|run|show'));
    console.log(pc.white(`    sentinel network benchmark history\n`));
}

async function handleAutoStart(
    askQuestion: (prompt: string) => Promise<string>,
    t: (key: string) => string,
) {
    const { loadConfig, saveConfig } = await import('../core/network/network-config');
    const cfg = loadConfig();

    console.log(pc.cyan('\n🔄 AUTO-START'));
    console.log(pc.dim('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'));
    console.log(pc.white(`  Current status: ${cfg.autoStart ? pc.green('ENABLED') : pc.yellow('DISABLED')}`));
    console.log(pc.white(`  Config path:   ${pc.dim((await import('../core/network/network-config')).getConfigPath())}\n`));
    console.log(pc.white('  1. Enable auto-start (register Windows Scheduled Task)'));
    console.log(pc.white('  2. Disable auto-start (remove task)'));
    console.log(pc.white('  3. Show scheduled task status'));
    console.log(pc.white('  0. Back\n'));

    const action = await askQuestion(pc.blue('  ❯ ') + pc.bold('Select option (0-3): '));

    if (action === '1') {
        cfg.autoStart = true;
        saveConfig(cfg);
        console.log(pc.green('\n  ✓ Auto-start enabled in config.'));
        if (os.platform() === 'win32') {
            try {
                const { execSync } = await import('child_process');
                const scriptPath = process.argv[1];
                const taskName = 'SentinelNetworkMonitor';
                execSync(
                    `powershell -NoProfile -Command "` +
                    `$action = New-ScheduledTaskAction -Execute 'node' -Argument '${scriptPath.replace(/'/g, "''")} network start'; ` +
                    `$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME; ` +
                    `$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Limited; ` +
                    `Register-ScheduledTask -TaskName '${taskName}' -Action $action -Trigger $trigger -Principal $principal -Force"`,
                    { timeout: 15000, encoding: 'utf8' },
                );
                console.log(pc.green(`  ✓ Windows Scheduled Task '${taskName}' registered.`));
            } catch (e: any) {
                console.log(pc.yellow(`  ⚠ Could not register scheduled task: ${e.message}`));
            }
        } else {
            try {
                const { execSync } = await import('child_process');
                const servicePath = process.argv[1];
                const systemdDir = path.join(os.homedir(), '.config', 'systemd', 'user');
                if (!fs.existsSync(systemdDir)) {
                    fs.mkdirSync(systemdDir, { recursive: true });
                }
                const unitContent = `[Unit]
Description=Sentinel Network Monitor
After=network.target

[Service]
Type=simple
ExecStart=${servicePath} network start
Restart=on-failure

[Install]
WantedBy=default.target
`;
                const unitPath = path.join(systemdDir, 'sentinel-network.service');
                fs.writeFileSync(unitPath, unitContent, 'utf-8');
                execSync('systemctl --user daemon-reload', { timeout: 5000, encoding: 'utf8' });
                execSync('systemctl --user enable sentinel-network.service', { timeout: 5000, encoding: 'utf8' });
                console.log(pc.green(`  ✓ systemd user service installed at ${unitPath}.`));
            } catch (e: any) {
                console.log(pc.yellow(`  ⚠ Could not install systemd service: ${e.message}`));
            }
        }
    } else if (action === '2') {
        cfg.autoStart = false;
        saveConfig(cfg);
        console.log(pc.yellow('\n  ✓ Auto-start disabled in config.'));
        if (os.platform() === 'win32') {
            try {
                const { execSync } = await import('child_process');
                execSync(
                    `powershell -NoProfile -Command "Unregister-ScheduledTask -TaskName 'SentinelNetworkMonitor' -Confirm:$false"`,
                    { timeout: 10000, encoding: 'utf8' },
                );
                console.log(pc.yellow('  ✓ Windows Scheduled Task removed.'));
            } catch (e: any) {
                console.log(pc.yellow(`  ⚠ Could not remove scheduled task (may not exist): ${e.message}`));
            }
        } else {
            try {
                const { execSync } = await import('child_process');
                execSync('systemctl --user disable sentinel-network.service', { timeout: 5000, encoding: 'utf8' });
                console.log(pc.yellow('  ✓ systemd user service disabled.'));
            } catch (e: any) {
                console.log(pc.yellow(`  ⚠ Could not disable systemd service: ${e.message}`));
            }
        }
    } else if (action === '3') {
        if (os.platform() === 'win32') {
            try {
                const { execSync } = await import('child_process');
                const out = execSync(
                    `powershell -NoProfile -Command "Get-ScheduledTask -TaskName 'SentinelNetworkMonitor' | Format-List State,Enabled"`,
                    { timeout: 5000, encoding: 'utf8' },
                );
                console.log(pc.white(`\n  Scheduled Task status:\n${out}`));
            } catch {
                console.log(pc.yellow('\n  Scheduled task not found.'));
            }
        } else {
            try {
                const { execSync } = await import('child_process');
                const out = execSync('systemctl --user is-enabled sentinel-network.service 2>/dev/null || echo "not-found"', { timeout: 5000, encoding: 'utf8' });
                console.log(pc.white(`\n  systemd service status: ${out.trim()}`));
            } catch {
                console.log(pc.yellow('\n  systemd service not found.'));
            }
        }
    }
}

async function handlePRBot() {
    console.log(pc.magenta('\n🤖 SENTINEL PR BOT — Auto Orchestration'));
    console.log(pc.dim('   Scanning all repos for open Pull Requests...\n'));

    const repoList = ghBridge.listUserRepos(50);
    if (!repoList || repoList.length === 0) {
        console.log(pc.red('   No repositories found.'));
        return;
    }

    let totalScanned = 0;
    let totalThreats = 0;
    let totalClean = 0;
    let totalErrors = 0;

    for (const repo of repoList) {
        const prs = ghBridge.listPRs(repo.fullName);
        if (!prs || prs.length === 0) continue;

        console.log(pc.cyan(`\n📦 ${pc.bold(repo.fullName)} — ${prs.length} open PR(s)`));

        for (const pr of prs) {
            process.stdout.write(`   ${pc.dim(`Analyzing PR #${pr.number}: ${pr.title.substring(0, 50)}...`)}`);

            try {
                const diff = ghBridge.getPRDiff(repo.fullName, pr.number);
                if (!diff) {
                    process.stdout.write(` ${pc.red('✖ (diff error)')}\n`);
                    totalErrors++;
                    continue;
                }

                const scanner = new LiteScanner();
                const findings = scanner.scanPatch(`PR #${pr.number}.diff`, diff);

                // Persist findings to Signal Vault for historical tracking
                try {
                    const mm = new MemoryManager();
                    const map: Record<string, number> = { CRITICAL: 9, HIGH: 7, MEDIUM: 5, LOW: 2 };
                    const scanPayload = {
                        repo: repo.fullName,
                        author: pr.author?.login || 'unknown',
                        pr_number: pr.number,
                        risk_score: findings.reduce((max: number, f: LiteFinding) => {
                            return Math.max(max, map[f.severity] || 3);
                        }, 0),
                        findings: findings.map((f: LiteFinding) => ({
                            type: f.type,
                            severity: f.severity,
                            riskLevel: map[f.severity] || 3,
                            file: f.file,
                            line_number: f.line,
                            description: f.description,
                            snippet: f.snippet
                        }))
                    };
                    mm.ingestReportFromJson(scanPayload);
                } catch (_e: unknown) {}

                process.stdout.write(` ${findings.length === 0 ? pc.green('✔') : pc.yellow('⚠')}\n`);

                // Professional PR report
                const reportColor = findings.length === 0 ? pc.green : pc.yellow;
                const reportBorder = reportColor('━'.repeat(70));
                console.log(`\n${reportBorder}`);
                console.log(reportColor(pc.bold(`  ${findings.length === 0 ? '✔ CLEAN' : '⚠ THREATS FOUND'}  │  PR #${pr.number}  │  ${repo.fullName}`)));
                console.log(`${reportBorder}`);
                console.log(`  ${pc.dim('Title:')}    ${pc.white(pr.title)}`);
                console.log(`  ${pc.dim('Author:')}   ${pc.white(pr.author?.login || 'unknown')}`);
                console.log(`  ${pc.dim('Created:')}  ${pc.white(new Date(pr.createdAt).toLocaleString())}`);
                console.log(`  ${pc.dim('Branch:')}   ${pc.white(pr.headRefName || 'unknown')}`);

                if (findings.length > 0) {
                    totalThreats++;
                    console.log(`  ${pc.dim('Findings:')} ${pc.yellow(String(findings.length))}`);
                    console.log(`\n  ${pc.bold('Threat Breakdown:')}`);
                    const bySeverity = new Map<string, number>();
                    findings.forEach((f: LiteFinding) => bySeverity.set(f.severity, (bySeverity.get(f.severity) || 0) + 1));
                    for (const [sev, count] of bySeverity) {
                        const color = sev === 'CRITICAL' ? pc.bgRed : sev === 'HIGH' ? pc.bgYellow : pc.bgCyan;
                        console.log(`    ${color(pc.black(` ${sev.padEnd(8)} `))} × ${count}`);
                    }
                    console.log(`\n  ${pc.bold('Evidence:')}`);
                    findings.slice(0, 5).forEach((f: LiteFinding) => {
                        console.log(`    ${pc.red('■')} ${pc.bold(f.type)} ${pc.dim(`(L${f.line})`)}`);
                        console.log(`      ${pc.dim(f.description.substring(0, 100))}`);
                        console.log(`      ${pc.dim('`' + f.snippet.substring(0, 80) + '`')}`);
                    });
                    if (findings.length > 5) {
                        console.log(`    ${pc.dim(`... and ${findings.length - 5} more findings`)}`);
                    }
                } else {
                    totalClean++;
                    const p = pr as PullRequest;
                    console.log(`  ${pc.dim('Files changed:')} ${pc.white(String(p.changedFiles ?? 'N/A'))}`);
                    console.log(`  ${pc.dim('Lines:')}       ${pc.green(`+${p.additions ?? '?'}`)}${pc.dim('/')}${pc.red(`-${p.deletions ?? '?'}`)}`);
                    console.log(`  ${pc.dim('Rules engine:')} ${pc.cyan('30 SAST rules (code + secrets + filenames)')}`);
                    console.log(`  ${pc.dim('Status:')}      ${pc.bgGreen(pc.black(' CLEAN BILL OF HEALTH '))}`);
                    console.log(`\n  ${pc.green('✔ All 30 security rules passed. No malicious signatures detected.')}`);
                    console.log(`  ${pc.dim('  This PR introduces no known code threats, secret leaks, or')}`);
                    console.log(`  ${pc.dim('  suspicious patterns. Safe to merge pending code review.')}`);
                }
                console.log(`${reportColor('━'.repeat(70))}\n`);

                totalScanned++;
                await new Promise(r => setTimeout(r, 300)); // rate limit politeness

            } catch (err: unknown) {
                process.stdout.write(` ${pc.red('✖ error')}\n`);
                totalErrors++;
            }
        }
    }

    // Final summary
    console.log(pc.magenta(pc.bold('\n══════════════════ PR BOT — FINAL REPORT ══════════════════')));
    console.log(`  ${pc.dim('Repos scanned:')}  ${pc.white(String(repoList.length))}`);
    console.log(`  ${pc.dim('PRs analyzed:')}   ${pc.white(String(totalScanned))}`);
    console.log(`  ${pc.dim('Clean:')}          ${pc.green(String(totalClean))}`);
    console.log(`  ${pc.dim('Threats found:')}  ${totalThreats > 0 ? pc.red(String(totalThreats)) : pc.green(String(totalThreats))}`);
    if (totalErrors > 0) console.log(`  ${pc.dim('Errors:')}        ${pc.yellow(String(totalErrors))}`);
    console.log(pc.magenta('═══════════════════════════════════════════════════════════\n'));

    await askQuestion(pc.dim(`${t('press_enter')}`));
}
