import { describe, expect, it } from 'vitest';
import { Writable } from 'stream';
import { PRProgressMap } from './pr_progress';

class Capture extends Writable {
  public isTTY = false;
  public data = '';
  _write(chunk: Buffer, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    this.data += chunk.toString();
    callback();
  }
}

describe('PR progress map', () => {
  it('shows actual stage states and cloud API scope without ANSI in pipes', () => {
    const stream = new Capture();
    const map = new PRProgressMap('cloud', 17, stream);
    map.update({ stage: 'MANIFEST', state: 'COMPLETE', detail: 'package.json loaded' });
    map.update({ stage: 'ENGINE', state: 'RUNNING', detail: 'remote request' });
    map.finish();
    expect(stream.data).toContain('PR #17');
    expect(stream.data).toContain('Manifiesto del commit propuesto: COMPLETE');
    expect(stream.data).toContain('remote request');
    expect(stream.data).toContain('no publica eventos internos');
    expect(stream.data).not.toContain('\u001b[');
  });

  it('renders the lite path without claiming a cloud analysis', () => {
    const stream = new Capture();
    const map = new PRProgressMap('lite', 5, stream);
    map.update({ stage: 'DIFF', state: 'COMPLETE', detail: '100 bytes' });
    map.finish();
    expect(stream.data).toContain('Sentinel Lite');
    expect(stream.data).toContain('Diff del pull request: COMPLETE');
    expect(stream.data).not.toContain('no publica eventos internos');
  });

  it('adds terminal colors only when stderr is an interactive TTY and NO_COLOR is unset', () => {
    const previousNoColor = process.env.NO_COLOR;
    const previousTerm = process.env.TERM;
    delete process.env.NO_COLOR;
    process.env.TERM = 'xterm';
    try {
      const stream = new Capture();
      stream.isTTY = true;
      const map = new PRProgressMap('lite', 2, stream);
      map.update({ stage: 'PR', state: 'COMPLETE', detail: 'head pinned' });
      map.finish();
      expect(stream.data).toContain('\u001b[32m');
    } finally {
      if (previousNoColor === undefined) delete process.env.NO_COLOR;
      else process.env.NO_COLOR = previousNoColor;
      if (previousTerm === undefined) delete process.env.TERM;
      else process.env.TERM = previousTerm;
    }
  });
});
