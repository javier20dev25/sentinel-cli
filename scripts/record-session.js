'use strict';

/**
 * Usage: node scripts/record-session.js <profileId> <duration_sec> [work_cmd]
 *
 * Records a session with the given profile.
 * If work_cmd is provided, it's run in a background PowerShell job during recording.
 * Otherwise just does a silent recording with no parallel workload.
 *
 * Examples:
 *   node scripts/record-session.js git-clone 30 "git clone --depth 1 https://github.com/expressjs/express.git C:\\tmp\\test"
 *   node scripts/record-session.js git-clone 30
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const profileId = process.argv[2];
const durationSec = parseInt(process.argv[3], 10);
const workCmd = process.argv.slice(4).join(' ');

if (!profileId || !durationSec) {
  console.error('Usage: node scripts/record-session.js <profileId> <duration_sec> [work_cmd]');
  process.exit(1);
}

const recordedDir = path.join(process.cwd(), 'replay-corpus', 'recorded');
fs.mkdirSync(recordedDir, { recursive: true });

console.log(`Profile: ${profileId}`);
console.log(`Duration: ${durationSec}s`);
if (workCmd) console.log(`Work: ${workCmd}`);
console.log(`Output: ${recordedDir}`);

// Run recorder via spawn (avoids ETIMEDOUT bugs with execSync on Windows)
function runRecorder() {
  return new Promise((resolve, reject) => {
    const proc = spawn('node', [
      'dist/cli/main.js', 'network', 'record', String(durationSec), '--profile', profileId
    ], {
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
      timeout: (durationSec + 60) * 1000,
    });

    let stdout = '';
    proc.stdout.on('data', (d) => { stdout += d.toString(); process.stdout.write(d); });
    proc.stderr.on('data', (d) => { process.stderr.write(d); });

    const timeoutId = setTimeout(() => {
      proc.kill('SIGTERM');
      // If output already contains a session save path, treat as success
      if (stdout.includes('Session saved:') || stdout.includes('Session recorded')) {
        resolve({ stdout, timedOut: true });
      } else {
        reject(new Error('Recorder timed out with no session output'));
      }
    }, (durationSec + 60) * 1000);

    proc.on('exit', (code) => {
      clearTimeout(timeoutId);
      if (code === 0 || stdout.includes('Session saved:') || stdout.includes('Session recorded')) {
        resolve({ stdout, timedOut: false });
      } else {
        reject(new Error(`Recorder exited with code ${code}`));
      }
    });

    proc.on('error', (err) => {
      clearTimeout(timeoutId);
      reject(err);
    });
  });
}

// Launch work in background
if (workCmd) {
  console.log(`Starting work: ${workCmd}`);
  const tmpDir = require('os').tmpdir();
  const isPowershellCmdlet = /(Select-String|Get-ChildItem|Set-Content|Get-Content|Write-Output|Start-Sleep|Get-Process)\b/i.test(workCmd);

  if (isPowershellCmdlet) {
    // PowerShell cmdlets: write to temp script, run with powershell -File
    const tmpFile = path.join(tmpDir, `work-${profileId}-${Date.now()}.ps1`);
    const psContent = 'Set-Location "' + process.cwd() + '"\n' + workCmd
      .replace(/&&/g, '\n')
      .replace(/^cd\s+/im, '# ')
      .replace(/\bcd\s+/gi, 'Set-Location ');
    fs.writeFileSync(tmpFile, psContent, 'utf-8');
    const workProc = spawn('powershell', [
      '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', tmpFile,
    ], { stdio: ['ignore', 'inherit', 'pipe'], windowsHide: true, cwd: process.cwd() });
    workProc.stderr.on('data', (d) => {
      const msg = d.toString();
      if (msg.trim()) process.stderr.write('[ps-work-stderr] ' + msg);
    });
    workProc.on('error', (e) => process.stderr.write('[ps-work-error] ' + e.message + '\n'));
    workProc.on('exit', () => {
      try { fs.unlinkSync(tmpFile); } catch {}
    });
    workProc.on('error', () => {
      try { fs.unlinkSync(tmpFile); } catch {}
    });
  } else {
    // Native command — run directly via cmd.exe with stderr captured for diagnostics
    const workProc = spawn('cmd.exe', ['/c', workCmd], {
      stdio: ['ignore', 'inherit', 'pipe'], windowsHide: true, cwd: process.cwd(),
    });
    workProc.stderr.on('data', (d) => {
      const msg = d.toString();
      if (msg.trim()) process.stderr.write('[work-stderr] ' + msg);
    });
    workProc.on('error', (e) => process.stderr.write('[work-error] ' + e.message + '\n'));
  }
}

// Run recorder
runRecorder().then(({ stdout, timedOut }) => {
  if (timedOut) console.log('\n(Recorder timed out but session was saved)');

  // Show session files
  const files = fs.readdirSync(recordedDir).filter(f => f.endsWith('.json') && f.includes(profileId));
  if (files.length > 0) {
    console.log(`\nSession files matching "${profileId}":`);
    for (const f of files.slice(-3)) {
      const stat = fs.statSync(path.join(recordedDir, f));
      console.log(`  ${f} (${(stat.size / 1024).toFixed(1)} KB)`);
    }
  }
  console.log('\nSession recorded successfully.');
}).catch(err => {
  console.error('FAILED:', err.message);
  process.exit(1);
});
