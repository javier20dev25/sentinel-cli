'use strict';

import * as http from 'http';
import * as https from 'https';
import * as net from 'net';
import * as tls from 'tls';
import * as url from 'url';
import { NetworkFlow, generateId } from '../../core/network/types';

export class HttpInterceptor {
  private proxy: http.Server | null = null;
  private port: number;
  private onFlow: ((flow: NetworkFlow) => void) | null = null;
  private sessionId: string = '';
  private captureBody: boolean;

  constructor(port = 8089, captureBody = false) {
    this.port = port;
    this.captureBody = captureBody;
  }

  getProxyUrl(): string {
    return `http://127.0.0.1:${this.port}`;
  }

  start(sessionId: string, callback: (flow: NetworkFlow) => void): void {
    this.sessionId = sessionId;
    this.onFlow = callback;

    this.proxy = http.createServer((req, res) => {
      const startTime = Date.now();
      const chunks: Buffer[] = [];
      let totalSize = 0;

      req.on('data', (chunk: Buffer) => {
        chunks.push(chunk);
        totalSize += chunk.length;
      });

      req.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8').substring(0, 500);
        const flow: NetworkFlow = {
          id: generateId(),
          sessionId: this.sessionId,
          timestamp: new Date(),
          protocol: 'HTTP',
          sourceAddr: req.socket.remoteAddress || '127.0.0.1',
          sourcePort: req.socket.remotePort || 0,
          destAddr: req.headers.host || 'unknown',
          destPort: 80,
          hostname: req.headers.host,
          method: req.method,
          path: req.url,
          contentType: req.headers['content-type'],
          bytesSent: totalSize,
          bytesReceived: 0,
          durationMs: Date.now() - startTime,
          headers: req.headers as Record<string, string>,
          bodyPreview: this.captureBody ? body : undefined,
        };

        if (this.onFlow) this.onFlow(flow);

        const options = url.parse(req.url || '');
        const proxyReq = http.request({
          hostname: options.hostname,
          port: options.port || 80,
          path: options.path,
          method: req.method,
          headers: req.headers,
        }, (proxyRes) => {
          res.writeHead(proxyRes.statusCode || 200, proxyRes.headers);
          proxyRes.pipe(res);
        });
        proxyReq.write(Buffer.concat(chunks));
        proxyReq.end();
      });
    });

    this.proxy.on('connect', (req, clientSocket: net.Socket, head) => {
      const [hostname, portStr] = (req.url || ':443').split(':');
      const port = parseInt(portStr, 10) || 443;

      const serverSocket = net.connect(port, hostname, () => {
        clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        serverSocket.write(head);
        serverSocket.pipe(clientSocket);
        clientSocket.pipe(serverSocket);
      });

      const flow: NetworkFlow = {
        id: generateId(),
        sessionId: this.sessionId,
        timestamp: new Date(),
        protocol: 'TLS',
        sourceAddr: clientSocket.remoteAddress || '127.0.0.1',
        sourcePort: clientSocket.remotePort || 0,
        destAddr: hostname,
        destPort: port,
        hostname,
        sni: hostname,
        bytesSent: 0,
        bytesReceived: 0,
        durationMs: 0,
      };
      if (this.onFlow) this.onFlow(flow);
    });

    this.proxy.listen(this.port, '127.0.0.1');
  }

  stop(): void {
    if (this.proxy) {
      this.proxy.close();
      this.proxy = null;
    }
  }
}
