import type { Writable } from 'stream';

export type PRProgressState = 'PENDING' | 'RUNNING' | 'COMPLETE' | 'FAILED' | 'NOT_RUN';
export interface PRProgressEvent { stage: string; state: PRProgressState; detail?: string; }

const LABELS: Record<string, string> = {
  PR: 'Metadatos del pull request',
  DIFF: 'Diff del pull request',
  MANIFEST: 'Manifiesto del commit propuesto',
  AUTH: 'Acceso a Sentinel Cloud',
  ENGINE: 'Motor de análisis',
  RESULT: 'Veredicto y evidencia',
};
const ICONS: Record<PRProgressState, string> = { PENDING: 'WAIT', RUNNING: 'RUN', COMPLETE: 'OK', FAILED: 'FAIL', NOT_RUN: 'SKIP' };

function clean(value: string): string {
  return value.replace(/[\u0000-\u001f\u007f\u001b]/g, ' ').replace(/\s+/g, ' ').slice(0, 120);
}

export class PRProgressMap {
  private readonly stream: Writable & { isTTY?: boolean };
  private readonly color: boolean;
  private readonly states = new Map<string, { state: PRProgressState; detail: string }>();
  private drawn = false;
  private closed = false;
  private frame = 0;
  private timer: NodeJS.Timeout | null = null;

  constructor(private readonly engine: 'lite' | 'cloud', private readonly prNumber: number, stream: Writable & { isTTY?: boolean } = process.stderr) {
    this.stream = stream;
    this.color = process.env.NO_COLOR == null && !!this.stream.isTTY && process.env.TERM !== 'dumb';
    const stages = engine === 'lite' ? ['PR', 'DIFF', 'ENGINE', 'RESULT'] : ['PR', 'MANIFEST', 'AUTH', 'ENGINE', 'RESULT'];
    for (const stage of stages) this.states.set(stage, { state: 'PENDING', detail: '' });
  }

  update(event: PRProgressEvent): void {
    if (this.closed || !this.states.has(event.stage)) return;
    const item = this.states.get(event.stage)!;
    item.state = event.state;
    item.detail = clean(event.detail || '');
    if (event.state === 'RUNNING' && !this.timer && this.stream.isTTY) {
      this.timer = setInterval(() => { this.frame++; this.draw(); }, 100);
    }
    if (event.state !== 'RUNNING' && this.timer) { clearInterval(this.timer); this.timer = null; }
    this.draw(event.stage);
  }

  finish(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    if (this.stream.isTTY) {
      if (this.drawn) this.stream.write('\n');
    } else this.draw();
    this.closed = true;
  }

  private draw(changedStage?: string): void {
    if (this.closed) return;
    const rows = ['Sentinel CLI | PR #' + this.prNumber + ' | ' + (this.engine === 'cloud' ? 'Sentinel Cloud' : 'Sentinel Lite') + ' | mapa de análisis'];
    for (const [stage, item] of this.states) {
      const icon = item.state === 'RUNNING' ? 'RUN ' + ['|', '/', '-', '\\'][this.frame % 4] : ICONS[item.state];
      let painted = icon;
      if (this.color) {
        const code = item.state === 'FAILED' ? 31 : item.state === 'COMPLETE' ? 32 : item.state === 'RUNNING' ? 36 : 90;
        painted = '\u001b[' + code + 'm' + icon + '\u001b[0m';
      }
      rows.push('  [' + painted + '] ' + LABELS[stage] + ': ' + item.state + (item.detail ? ' — ' + item.detail : ''));
    }
    if (this.engine === 'cloud') rows.push('  i El endpoint devuelve un resultado agregado; no publica eventos internos de sus analizadores.');
    if (!this.stream.isTTY && changedStage) {
      const rowIndex = ['PR', 'DIFF', 'MANIFEST', 'AUTH', 'ENGINE', 'RESULT'].indexOf(changedStage);
      if (rowIndex >= 0) this.stream.write(rows[rowIndex + 1] + '\n');
    } else if (!this.stream.isTTY) this.stream.write(rows.join('\n') + '\n');
    else {
      if (this.drawn) this.stream.write('\u001b[' + rows.length + 'A\u001b[J');
      this.stream.write(rows.join('\n') + '\n');
    }
    this.drawn = true;
  }
}
