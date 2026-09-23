import * as pc from 'picocolors';
import type { RemoteScanResult } from './cloud_client';

/**
 * Terminal renderers for stored pulse results. `json` is the machine
 * consumption contract (industry standard raw result); `table` and `donut`
 * are human views of the same data.
 */

export type ResultsFormat = 'table' | 'donut' | 'json';

export const RESULTS_FORMATS: ReadonlyArray<ResultsFormat> = ['table', 'donut', 'json'];

export function isResultsFormat(value: string): value is ResultsFormat {
    return (RESULTS_FORMATS as ReadonlyArray<string>).includes(value);
}

function severityStyle(severity: string): string {
    const key = String(severity).toLowerCase();
    if (key === 'critical') return pc.red(severity);
    if (key === 'high') return pc.magenta(severity);
    if (key === 'medium') return pc.yellow(severity);
    if (key === 'warning') return pc.white(severity);
    return pc.gray(severity);
}

function shortId(jobId: string): string {
    return jobId.length > 12 ? jobId.slice(0, 12) : jobId;
}

export function renderResultsSummary(results: RemoteScanResult[]): string {
    if (results.length === 0) {
        return 'No pulse results stored yet. Run "sentinel pulse-scan <path>" to store one.';
    }
    const lines: string[] = [`Pulse results (${results.length}):`];
    lines.push(`  ${pc.gray('JOB')}${' '.repeat(9)}  VERDICT     RISK     FINDINGS  SCANNED`);
    for (const r of results) {
        const scannedAt = new Date(r.scannedAt ?? 0);
        const date = Number.isNaN(scannedAt.getTime())
            ? 'unknown'
            : scannedAt.toISOString().slice(0, 19).replace('T', ' ');
        lines.push(
            `  ${pc.cyan(shortId(r.jobId ?? 'pulse').padEnd(14))}  ${String(r.verdict).padEnd(10)}  ${String(r.risk).padEnd(8)}  ${String(r.findings.length).padStart(3).padEnd(8)}  ${date}`,
        );
    }
    return lines.join('\n');
}

export function renderResultTable(r: RemoteScanResult): string {
    const lines: string[] = [];
    lines.push(`Job: ${pc.cyan(r.jobId ?? 'pulse')}`);
    lines.push(`Scanned: ${r.scannedAt ?? 'unknown'}`);
    lines.push(
        `${pc.white('Verdict')}: ${String(r.verdict)} · ${pc.white('Risk')}: ${String(r.risk)} (score ${r.riskScore}) · ${pc.white('Confidence')}: ${r.confidence}`,
    );
    if (typeof r.summary === 'string' && r.summary.length > 0) {
        lines.push(`Summary: ${r.summary}`);
    }
    if (r.findings.length === 0) {
        lines.push('Findings: none.');
        return lines.join('\n');
    }
    lines.push(`Findings (${r.findings.length}):`);
    lines.push(`  ${pc.gray('SEVERITY')}  ${pc.gray('TYPE')}${' '.repeat(Math.max(0, 30 - 'TYPE'.length))}  ${pc.gray('DETAIL')}`);
    for (const f of r.findings) {
        const sev = severityStyle(String(f.severity).toUpperCase().padEnd(8));
        const type = String(f.type ?? '')
            .slice(0, 30)
            .padEnd(30);
        const title = f.title ?? f.message ?? '';
        lines.push(`  ${sev}  ${type}  ${title}`);
    }
    for (const explanation of r.explanation ?? []) {
        lines.push(`${pc.gray('·')} ${explanation}`);
    }
    return lines.join('\n');
}

export function renderSeverityDonut(r: RemoteScanResult): string {
    const order: ReadonlyArray<'critical' | 'high' | 'medium' | 'warning' | 'info'> = [
        'critical',
        'high',
        'medium',
        'warning',
        'info',
    ];
    const counts = order.map((sev) => ({
        sev,
        count: r.findings.filter((f) => String(f.severity).toLowerCase() === sev).length,
    }));
    const total = counts.reduce((acc, c) => acc + c.count, 0);
    const lines: string[] = [];
    lines.push(`Findings distribution (${total} total):`);
    if (total === 0) {
        lines.push('  (none)');
        return lines.join('\n');
    }
    const width = 24;
    const populated = counts.filter((c) => c.count > 0);
    const barWidth = Math.max(1, width);
    for (const c of populated) {
        const blocks = Math.max(1, Math.round((c.count / total) * barWidth));
        const bar = pc.green('█').repeat(blocks) + pc.gray('░').repeat(barWidth - blocks);
        const pct = Math.round((c.count / total) * 100);
        lines.push(`  ${severityStyle(c.sev.padEnd(9))} ${bar} ${String(c.count).padStart(3)} (${pct}%)`);
    }
    const composite = populated.reduce(
        (acc, c) => acc + Math.round((c.count / total) * 40),
        0,
    );
    lines.push(
        `  ${pc.gray('stacked')}  ${Array(Math.min(40, composite))
            .fill('█')
            .join('')}${Array(Math.max(0, 40 - Math.min(40, composite)))
            .fill('░')
            .join('')} ${String(total).padStart(3)}`,
    );
    return lines.join('\n');
}

export function renderStoredPulseResult(result: RemoteScanResult, format: ResultsFormat): string {
    switch (format) {
        case 'json':
            return JSON.stringify(result, null, 2);
        case 'donut':
            return renderSeverityDonut(result);
        default:
            return renderResultTable(result);
    }
}