"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.renderPdfHtml = renderPdfHtml;
function esc(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function severityColor(sev) {
    switch (sev) {
        case 'CRITICAL': return '#dc2626';
        case 'HIGH': return '#ea580c';
        case 'MEDIUM': return '#ca8a04';
        default: return '#6b7280';
    }
}
function severityBg(sev) {
    switch (sev) {
        case 'CRITICAL': return '#fef2f2';
        case 'HIGH': return '#fff7ed';
        case 'MEDIUM': return '#fefce8';
        default: return '#f9fafb';
    }
}
function renderPdfHtml(packs, agency) {
    const verdictColor = agency.verdict === 'BLOCK' ? '#dc2626' : agency.verdict === 'REVIEW' ? '#ea580c' : '#16a34a';
    const blastColor = severityColor(agency.blastRadius);
    let packsHtml = '';
    for (const pack of packs) {
        const badgeColor = severityColor(pack.severity);
        const bgColor = severityBg(pack.severity);
        const confPct = Math.round(pack.confidence * 100);
        const evidenceRows = pack.evidenceItems.map(item => {
            const itemColor = severityColor(item.severity);
            return `<tr>
        <td style="padding:6px 8px;border-bottom:1px solid #e5e7eb;font-weight:600;color:${itemColor}">${esc(item.subcode)}</td>
        <td style="padding:6px 8px;border-bottom:1px solid #e5e7eb">${esc(item.file)}</td>
        <td style="padding:6px 8px;border-bottom:1px solid #e5e7eb;text-align:center">${item.line}</td>
        <td style="padding:6px 8px;border-bottom:1px solid #e5e7eb;text-align:center"><span style="background:${bgColor};color:${itemColor};padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:600">${item.severity}</span></td>
        <td style="padding:6px 8px;border-bottom:1px solid #e5e7eb;text-align:center">${item.riskScore}</td>
      </tr>`;
        }).join('\n');
        const remediationItems = pack.remediationSteps.map(r => `<li style="margin:4px 0;color:#374151">${esc(r)}</li>`).join('\n');
        const assetItems = pack.affectedAssets.map(a => `<li style="margin:2px 0;color:#6b7280;font-size:0.9em">${esc(a)}</li>`).join('\n');
        packsHtml += `<div class="pack">
      <div class="pack-header" style="border-left:4px solid ${badgeColor};background:${bgColor};padding:12px 16px;margin-bottom:12px">
        <h2 style="margin:0;font-size:1.1em;color:#111827">${esc(pack.title)}</h2>
        <div style="margin-top:4px;font-size:0.85em;color:#4b5563">
          <span style="display:inline-block;background:${badgeColor};color:#fff;padding:2px 10px;border-radius:4px;font-weight:600;margin-right:8px">${pack.severity}</span>
          Score: ${pack.score}/100 &middot; Confidence: ${confPct}% &middot; Chain: ${pack.chainLength} step(s) &middot; Assets: ${pack.affectedAssets.length}
        </div>
      </div>

      <p style="margin:0 0 8px 0;color:#374151;line-height:1.6"><strong>Narrative:</strong> ${esc(pack.narrative)}</p>
      <p style="margin:0 0 12px 0;color:#374151;line-height:1.6"><strong>Impact:</strong> ${esc(pack.impact)}</p>

      <h3 style="font-size:0.95em;color:#111827;margin:12px 0 6px 0">Evidence Chain</h3>
      <table style="width:100%;border-collapse:collapse;font-size:0.85em;margin-bottom:12px">
        <thead>
          <tr style="background:#f3f4f6">
            <th style="padding:8px;text-align:left;border-bottom:2px solid #d1d5db">Subcode</th>
            <th style="padding:8px;text-align:left;border-bottom:2px solid #d1d5db">File</th>
            <th style="padding:8px;text-align:center;border-bottom:2px solid #d1d5db">Line</th>
            <th style="padding:8px;text-align:center;border-bottom:2px solid #d1d5db">Severity</th>
            <th style="padding:8px;text-align:center;border-bottom:2px solid #d1d5db">Score</th>
          </tr>
        </thead>
        <tbody>
          ${evidenceRows}
        </tbody>
      </table>

      ${remediationItems ? `<h3 style="font-size:0.95em;color:#111827;margin:12px 0 6px 0">Remediation</h3><ul style="margin:0 0 12px 0;padding-left:20px">${remediationItems}</ul>` : ''}

      ${assetItems ? `<h3 style="font-size:0.95em;color:#111827;margin:12px 0 6px 0">Affected Assets</h3><ul style="margin:0 0 0 0;padding-left:20px">${assetItems}</ul>` : ''}
    </div>`;
    }
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Sentinel Executive Evidence Report</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Georgia', 'Times New Roman', serif; color: #111827; background: #fff; padding: 40px; line-height: 1.5; }
  .container { max-width: 900px; margin: 0 auto; }
  h1 { font-size: 1.6em; margin-bottom: 4px; }
  .subtitle { font-size: 0.9em; color: #6b7280; margin-bottom: 20px; }
  .summary-grid { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 28px; }
  .summary-card { flex: 1; min-width: 140px; background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; padding: 14px 16px; text-align: center; }
  .summary-card .label { font-size: 0.75em; text-transform: uppercase; letter-spacing: 0.05em; color: #6b7280; }
  .summary-card .value { font-size: 1.5em; font-weight: 700; margin-top: 4px; }
  .pack { margin-bottom: 24px; page-break-inside: avoid; }
  table { page-break-inside: avoid; }
  tr { page-break-inside: avoid; }
  hr { border: none; border-top: 1px solid #e5e7eb; margin: 20px 0; }
  .footer { text-align: center; font-size: 0.75em; color: #9ca3af; margin-top: 32px; padding-top: 16px; border-top: 1px solid #e5e7eb; }
  @media print { body { padding: 20px; } .pack { page-break-inside: avoid; } }
</style>
</head>
<body>
<div class="container">
  <h1>Sentinel Executive Evidence Report</h1>
  <div class="subtitle">Generated ${new Date().toISOString().split('T')[0]} &middot; Sentinel CLI v4.0</div>

  <div class="summary-grid">
    <div class="summary-card">
      <div class="label">Agency Score</div>
      <div class="value" style="color:${verdictColor}">${agency.agencyScore}/100</div>
    </div>
    <div class="summary-card">
      <div class="label">Verdict</div>
      <div class="value" style="color:${verdictColor}">${agency.verdict}</div>
    </div>
    <div class="summary-card">
      <div class="label">Blast Radius</div>
      <div class="value" style="color:${blastColor}">${agency.blastRadius}</div>
    </div>
    <div class="summary-card">
      <div class="label">Total Findings</div>
      <div class="value">${agency.totalFindings}</div>
    </div>
    <div class="summary-card">
      <div class="label">Critical</div>
      <div class="value" style="color:#dc2626">${agency.criticalCount}</div>
    </div>
    <div class="summary-card">
      <div class="label">High</div>
      <div class="value" style="color:#ea580c">${agency.highCount}</div>
    </div>
  </div>

  <hr>

  <h2 style="font-size:1.2em;margin-bottom:16px;color:#111827">Attack Scenario Evidence Packs (${packs.length})</h2>

  ${packsHtml || '<p style="color:#6b7280">No evidence packs generated.</p>'}

  <div class="footer">Sentinel Security Intelligence &mdash; Report printed from CLI</div>
</div>
</body>
</html>`;
}
