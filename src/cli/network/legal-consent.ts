'use strict';

import * as readline from 'readline';
import { AuditDatabase } from './database';

export const LEGAL_NOTICE = `
╔══════════════════════════════════════════════════════════════╗
║              SENTINEL NETWORK AUDITOR                       ║
║       AI Agent Behavior & Repository Exfiltration Detection ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  This module monitors system activity to detect whether      ║
║  AI coding agents are exfiltrating your repository.          ║
║                                                              ║
║  WHAT THIS MODULE DOES:                                      ║
║  ✔ Monitors running processes for AI agent detection         ║
║  ✔ Observes file access patterns (especially .git/)          ║
║  ✔ Detects git bundle/archive/pack commands                   ║
║  ✔ Observes DNS lookups to AI/cloud endpoints                ║
║  ✔ Inspects TLS connections (SNI, certificates)              ║
║  ✔ Intercepts HTTP/HTTPS traffic (requires certificate)      ║
║  ✔ Detects large data uploads and suspicious patterns         ║
║                                                              ║
║  WHAT THIS MODULE DOES NOT DO:                               ║
║  ✗ Does NOT send any data to the cloud                       ║
║  ✗ Does NOT block or modify your network traffic             ║
║  ✗ Does NOT store full file contents                         ║
║  ✗ Does NOT modify system certificates                       ║
║  ✗ Does NOT inject code into running processes               ║
║                                                              ║
║  DATA STORAGE:                                               ║
║  All data is stored LOCALLY in: ~/.sentinel/network-audit.db ║
║  No telemetry, no cloud backups, no external transmission.   ║
║                                                              ║
║  PERMISSIONS REQUIRED:                                       ║
║  • Process listing (ps/Get-Process) — user-level             ║
║  • File system watching — user-level                         ║
║  • DNS resolution observation — user-level                   ║
║  • TLS/HTTP interception — may require admin/elevation       ║
║                                                              ║
║  By accepting, you consent to local monitoring of your       ║
║  system's processes, file access, and network connections.   ║
║  You may stop the audit at any time.                         ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
`;

export async function requestConsent(db: AuditDatabase): Promise<boolean> {
  const existing = db.getConsent();
  if (existing && existing.accepted) {
    return true;
  }

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  console.log(LEGAL_NOTICE);

  const accepted = await new Promise<boolean>((resolve) => {
    rl.question('\nDo you accept these terms and start the audit? (y/N): ', (answer) => {
      rl.close();
      const val = answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes';
      if (!val) {
        console.log('\nConsent not given. Network Auditor will not start.');
      }
      resolve(val);
    });
  });

  db.setConsent(accepted ? 1 : 0);
  return accepted;
}
