import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as pc from 'picocolors';
import * as readline from 'readline';

const KEYS_FILE = path.join(os.homedir(), '.sentinel', 'cloud_keys.json');
const LEGACY_TOKEN_FILE = path.join(os.homedir(), '.sentinel', 'cloud-token.txt');

export const DISCLAIMER_TEXT =
  'AVISO DE RESPONSABILIDAD: El usuario es el único responsable del uso de esta herramienta y de las ' +
  'decisiones de seguridad, fusión o despliegue tomadas con base en sus resultados. El desarrollador y ' +
  'los mantenedores no se hacen responsables de daños directos o indirectos, fallas de seguridad, ' +
  'código malicioso o vulnerabilidades no detectadas por Sentinel. Ningún motor de análisis estático o ' +
  'heurístico garantiza la detección del 100% de las amenazas.';

export function maskToken(token: string): string {
  if (!token) return '••••';
  const str = String(token).trim();
  if (str.length <= 8) return '••••' + str.slice(-2);
  const prefix = str.slice(0, 4);
  const suffix = str.slice(-4);
  const maskedMiddle = '•'.repeat(Math.min(16, Math.max(8, str.length - 8)));
  return `${prefix}_${maskedMiddle}_${suffix}`;
}

export interface StoredKey {
  id: string;
  name: string;
  token: string;
  addedAt: string;
}

export function ensureStore(): { keys: StoredKey[] } {
  const dir = path.dirname(KEYS_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  if (!fs.existsSync(KEYS_FILE)) {
    const initialKeys: StoredKey[] = [];
    if (fs.existsSync(LEGACY_TOKEN_FILE)) {
      try {
        const legacy = fs.readFileSync(LEGACY_TOKEN_FILE, 'utf8').trim();
        if (legacy) {
          initialKeys.push({
            id: 'key-1',
            name: 'Clave 1 (Default)',
            token: legacy,
            addedAt: new Date().toISOString()
          });
        }
      } catch (_) {}
    }
    const data = { keys: initialKeys };
    fs.writeFileSync(KEYS_FILE, JSON.stringify(data, null, 2), 'utf8');
    return data;
  }

  try {
    return JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8'));
  } catch {
    return { keys: [] };
  }
}

export function saveStore(data: { keys: StoredKey[] }) {
  const dir = path.dirname(KEYS_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(KEYS_FILE, JSON.stringify(data, null, 2), 'utf8');
}

export function listKeys() {
  const store = ensureStore();
  return (store.keys || []).map((k, idx) => ({
    index: idx + 1,
    id: k.id,
    name: k.name || `Clave ${idx + 1}`,
    maskedToken: maskToken(k.token),
    token: k.token,
    addedAt: k.addedAt || null
  }));
}

export function getKey(indexOrId: number | string): StoredKey | null {
  const store = ensureStore();
  const keys = store.keys || [];
  if (typeof indexOrId === 'number') {
    const idx = indexOrId - 1;
    return (idx >= 0 && idx < keys.length) ? keys[idx] : null;
  }
  return keys.find(k => k.id === indexOrId || k.name === indexOrId) || null;
}

export function addKey(token: string, name?: string) {
  if (!token || token.trim().length < 6) {
    throw new Error('El token ingresado es inválido.');
  }
  const clean = token.trim();
  const store = ensureStore();
  const nextNum = (store.keys || []).length + 1;
  const newKey: StoredKey = {
    id: `key-${Date.now()}`,
    name: name && name.trim() ? name.trim() : `Clave ${nextNum}`,
    token: clean,
    addedAt: new Date().toISOString()
  };
  store.keys = store.keys || [];
  store.keys.push(newKey);
  saveStore(store);

  if (store.keys.length === 1) {
    try { fs.writeFileSync(LEGACY_TOKEN_FILE, clean, 'utf8'); } catch (_) {}
  }

  return newKey;
}

export function revokeKey(idOrIndex: string | number) {
  const store = ensureStore();
  const keys = store.keys || [];
  let removed: StoredKey | null = null;

  if (typeof idOrIndex === 'number') {
    const idx = idOrIndex - 1;
    if (idx >= 0 && idx < keys.length) removed = keys.splice(idx, 1)[0];
  } else {
    const idx = keys.findIndex(k => k.id === idOrIndex || k.name === idOrIndex);
    if (idx !== -1) removed = keys.splice(idx, 1)[0];
  }

  if (!removed) throw new Error('Clave no encontrada.');

  saveStore(store);
  if (fs.existsSync(LEGACY_TOKEN_FILE)) {
    try {
      if (store.keys.length > 0) fs.writeFileSync(LEGACY_TOKEN_FILE, store.keys[0].token, 'utf8');
      else fs.unlinkSync(LEGACY_TOKEN_FILE);
    } catch (_) {}
  }
  return removed;
}

export async function promptKeysInteractive() {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const ask = (q: string): Promise<string> => new Promise(res => rl.question(q, a => res(a.trim())));

  try {
    while (true) {
      console.log('\n' + pc.cyan('──────────────────────────────────────────────────────────'));
      console.log(pc.bold('🔑 GESTIÓN DE CLAVES DE SENTINEL CLOUD (CLI)'));
      console.log(pc.dim(`⚖ ${DISCLAIMER_TEXT}`));
      console.log(pc.cyan('──────────────────────────────────────────────────────────'));

      const keys = listKeys();
      if (keys.length === 0) {
        console.log(pc.yellow('No hay claves de Sentinel Cloud almacenadas en esta máquina.'));
      } else {
        console.log(pc.bold('Claves almacenadas en este equipo (censuradas):'));
        keys.forEach(k => {
          console.log(`  [${k.index}] ${pc.white(k.name.padEnd(22))}: ${pc.cyan(k.maskedToken)}`);
        });
      }

      console.log('\nOpciones:');
      console.log('  1) Añadir nueva clave Cloud');
      console.log('  2) Revocar / Eliminar clave de la máquina');
      console.log('  3) Salir');

      const choice = await ask('\nSelecciona [1-3]: ');
      if (choice === '1') {
        const token = await ask('\nPega el API Token de Sentinel Cloud: ');
        if (!token) {
          console.log(pc.red('Operación cancelada. Token vacío.'));
          continue;
        }
        const name = await ask('Nombre identificador opcional (ej: Clave Prod): ');
        try {
          const added = addKey(token, name);
          console.log(pc.green(`✔ Clave "${added.name}" guardada con éxito: ${maskToken(added.token)}`));
        } catch (err: any) {
          console.log(pc.red(`Error: ${err.message}`));
        }
      } else if (choice === '2') {
        if (keys.length === 0) {
          console.log(pc.yellow('No hay claves para revocar.'));
          continue;
        }
        const idxStr = await ask(`Número de clave a revocar [1-${keys.length}]: `);
        const idx = parseInt(idxStr, 10);
        if (isNaN(idx) || idx < 1 || idx > keys.length) {
          console.log(pc.red('Selección inválida.'));
          continue;
        }
        console.log(pc.yellow('\n⚠ ADVERTENCIA DE REVOCACIÓN:'));
        console.log(pc.yellow('  Revocar una clave desde este menú SOLO la elimina de tu máquina local.'));
        console.log(pc.yellow('  Para invalidarla permanentemente, debes revocarla desde Sentinel Cloud.\n'));
        const conf = (await ask(`¿Seguro que deseas eliminar la Clave ${idx}? [y/N]: `)).toLowerCase();
        if (conf === 'y' || conf === 'yes') {
          try {
            const removed = revokeKey(idx);
            console.log(pc.green(`✔ ${removed.name} eliminada de la máquina.`));
          } catch (err: any) {
            console.log(pc.red(`Error: ${err.message}`));
          }
        }
      } else {
        break;
      }
    }
  } finally {
    rl.close();
  }
}
