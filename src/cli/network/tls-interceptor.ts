'use strict';

import * as net from 'net';
import { NetworkFlow, generateId } from '../../core/network/types';

export class TlsInterceptor {
  private server: net.Server | null = null;
  private port: number;
  private onFlow: ((flow: NetworkFlow) => void) | null = null;
  private sessionId: string = '';

  constructor(port = 9090) {
    this.port = port;
  }

  start(sessionId: string, callback: (flow: NetworkFlow) => void): void {
    this.sessionId = sessionId;
    this.onFlow = callback;

    this.server = net.createServer((clientSocket) => {
      clientSocket.once('data', (data: Buffer) => {
        const sni = this.extractSni(data);

        if (this.onFlow) {
          const flow: NetworkFlow = {
            id: generateId(),
            sessionId: this.sessionId,
            timestamp: new Date(),
            protocol: 'TLS',
            sourceAddr: clientSocket.remoteAddress || '127.0.0.1',
            sourcePort: clientSocket.remotePort || 0,
            destAddr: sni || 'unknown',
            destPort: 443,
            hostname: sni || undefined,
            sni: sni || undefined,
            tlsVersion: 'TLSv1.3',
            bytesSent: 0,
            bytesReceived: 0,
            durationMs: 0,
          };
          this.onFlow(flow);
        }

        clientSocket.end();
      });
    });

    this.server.listen(this.port, '127.0.0.1');
  }

  private extractSni(data: Buffer): string | null {
    try {
      const len = data.length;
      if (len < 50) return null;

      let pos = 0;
      if (data[pos] !== 0x16) return null;
      pos += 1;

      if (pos + 2 > len) return null;
      const tlsLen = data.readUInt16BE(pos);
      pos += 2;
      if (pos + tlsLen > len) return null;

      if (data[pos] !== 0x01) return null;
      pos += 1;

      pos += 3;
      if (pos + 2 > len) return null;
      const sessLen = data.readUInt16BE(pos);
      pos += 2 + sessLen;

      if (pos + 2 > len) return null;
      const cipherLen = data.readUInt16BE(pos);
      pos += 2 + cipherLen;

      if (pos + 1 > len) return null;
      const compLen = data[pos];
      pos += 1 + compLen;

      if (pos + 2 > len) return null;
      const extLen = data.readUInt16BE(pos);
      pos += 2;
      const extEnd = pos + extLen;

      while (pos + 4 <= extEnd) {
        const extType = data.readUInt16BE(pos);
        const extDataLen = data.readUInt16BE(pos + 2);
        pos += 4;
        if (extType === 0x00 && pos + 2 <= extEnd) {
          const sniListLen = data.readUInt16BE(pos);
          pos += 2;
          if (pos + 1 <= extEnd) {
            const sniEntryType = data[pos];
            pos += 1;
            if (sniEntryType === 0x00 && pos + 2 <= extEnd) {
              const sniNameLen = data.readUInt16BE(pos);
              pos += 2;
              if (pos + sniNameLen <= extEnd) {
                return data.toString('utf8', pos, pos + sniNameLen);
              }
            }
          }
        }
        pos += extDataLen;
      }
    } catch {
    }
    return null;
  }

  stop(): void {
    if (this.server) {
      this.server.close();
      this.server = null;
    }
  }
}
