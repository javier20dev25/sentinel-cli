import { execFileSync } from 'child_process';
import { runPrAudit } from './pr-audit';

interface WorkflowOptions {
  repo?: string;
  prNumber?: number;
  owner?: string;
  comment?: boolean;
  checkRun?: boolean;
}

function runGh(args: string[]): string {
  try {
    return execFileSync('gh', args, {
      timeout: 30000,
      encoding: 'utf-8',
      maxBuffer: 50 * 1024 * 1024,
      windowsHide: true,
    }).trim();
  } catch (e: any) {
    return e.stdout?.trim() || e.stderr?.trim() || e.message;
  }
}

export async function prReview(opts: WorkflowOptions): Promise<void> {
  if (!opts.repo || !opts.prNumber) {
    console.error('Error: --repo and --pr are required for pr-review');
    process.exit(1);
  }

  const author = runGh(['pr', 'view', String(opts.prNumber), '--repo', opts.repo, '--json', 'author', '--jq', '.author.login']) || 'unknown';

  const result = await runPrAudit({
    repo: opts.repo,
    prNumber: opts.prNumber,
    author,
    comment: opts.comment,
    checkRun: opts.checkRun,
  });

  console.log(JSON.stringify(result, null, 2));

  if (result.verdict.decision === 'BLOCK') {
    process.exit(1);
  }
}

export async function fullAudit(opts: WorkflowOptions): Promise<void> {
  const repos: string[] = [];

  if (opts.repo) {
    repos.push(opts.repo);
    console.log(`Scanning repository: ${opts.repo}\n`);
  } else {
    const owner = opts.owner || 'javier20dev25';
    const reposRaw = runGh(['repo', 'list', owner, '--limit', '50', '--json', 'nameWithOwner']);

    try {
      const parsed = JSON.parse(reposRaw);
      for (const r of parsed) {
        repos.push(r.nameWithOwner);
      }
    } catch {
      console.error('Failed to parse repo list');
      process.exit(1);
    }

    console.log(`Found ${repos.length} repositories. Scanning for open PRs...\n`);
  }

  let totalPRs = 0;
  let totalBlock = 0;
  let totalReview = 0;
  let totalPass = 0;
  const results: { repo: string; pr: number; verdict: string }[] = [];

  for (const repo of repos) {
    const prsRaw = runGh(['pr', 'list', '--repo', repo, '--state', 'open', '--json', 'number,title,author', '--limit', '20']);
    let prs: { number: number; title: string; author: { login: string } }[] = [];

    try {
      prs = JSON.parse(prsRaw);
    } catch {
      continue;
    }

    if (prs.length === 0) continue;

    console.log(`  ${repo} — ${prs.length} PR(s)`);

    for (const pr of prs) {
      totalPRs++;

      const result = await runPrAudit({
        repo,
        prNumber: pr.number,
        author: pr.author?.login || 'unknown',
        comment: opts.comment,
        checkRun: opts.checkRun,
      });

      results.push({ repo, pr: pr.number, verdict: `${result.verdict.decision} [${result.verdict.band}]` });

      if (result.verdict.decision === 'BLOCK') totalBlock++;
      else if (result.verdict.decision === 'REVIEW') totalReview++;
      else totalPass++;
    }
  }

  console.log(`\n====== FULL AUDIT SUMMARY ======`);
  console.log(`Total PRs scanned: ${totalPRs}`);
  console.log(`  BLOCK:  ${totalBlock}`);
  console.log(`  REVIEW: ${totalReview}`);
  console.log(`  PASS:   ${totalPass}`);
  console.log(`================================\n`);

  for (const r of results) {
    console.log(`  ${r.repo} #${r.pr} → ${r.verdict}`);
  }
}
