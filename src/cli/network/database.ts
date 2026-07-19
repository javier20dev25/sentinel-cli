'use strict';

import Database from 'better-sqlite3';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';

export class AuditDatabase {
  private db: Database.Database;

  constructor(dbPath?: string) {
    const resolved = dbPath || path.join(os.homedir(), '.sentinel', 'network-audit.db');
    const dir = path.dirname(resolved);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    this.db = new Database(resolved);
    this.db.pragma('journal_mode = WAL');
    this.migrate();
  }

  private migrate(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        start_time TEXT NOT NULL,
        end_time TEXT,
        status TEXT NOT NULL DEFAULT 'running',
        config_json TEXT
      );

      CREATE TABLE IF NOT EXISTS flows (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        protocol TEXT NOT NULL,
        source_addr TEXT,
        source_port INTEGER,
        dest_addr TEXT,
        dest_port INTEGER,
        hostname TEXT,
        sni TEXT,
        tls_version TEXT,
        bytes_sent INTEGER DEFAULT 0,
        bytes_received INTEGER DEFAULT 0,
        duration_ms INTEGER DEFAULT 0,
        method TEXT,
        path TEXT,
        content_type TEXT,
        status_code INTEGER,
        headers_json TEXT,
        body_preview TEXT,
        dns_query TEXT,
        dns_response_json TEXT,
        FOREIGN KEY (session_id) REFERENCES sessions(id)
      );

      CREATE TABLE IF NOT EXISTS processes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        pid INTEGER,
        name TEXT,
        command_line TEXT,
        parent_pid INTEGER,
        parent_name TEXT,
        username TEXT,
        risk_indicators_json TEXT,
        FOREIGN KEY (session_id) REFERENCES sessions(id)
      );

      CREATE TABLE IF NOT EXISTS file_accesses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        file_path TEXT,
        process_name TEXT,
        pid INTEGER,
        operation TEXT,
        bytes_read INTEGER,
        FOREIGN KEY (session_id) REFERENCES sessions(id)
      );

      CREATE TABLE IF NOT EXISTS git_commands (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        pid INTEGER,
        process_name TEXT,
        command_line TEXT,
        action TEXT,
        repository TEXT,
        FOREIGN KEY (session_id) REFERENCES sessions(id)
      );

      CREATE TABLE IF NOT EXISTS behaviors (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        type TEXT NOT NULL,
        confidence REAL DEFAULT 0,
        source TEXT,
        evidence_json TEXT,
        artifacts_json TEXT,
        FOREIGN KEY (session_id) REFERENCES sessions(id)
      );

      CREATE TABLE IF NOT EXISTS evidence (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        type TEXT NOT NULL,
        title TEXT,
        description TEXT,
        data_json TEXT,
        severity TEXT DEFAULT 'info',
        flow_id TEXT,
        behavior_id TEXT,
        FOREIGN KEY (session_id) REFERENCES sessions(id)
      );

      CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        severity TEXT NOT NULL,
        title TEXT,
        description TEXT,
        evidence_json TEXT,
        acknowledged INTEGER DEFAULT 0,
        FOREIGN KEY (session_id) REFERENCES sessions(id)
      );

      CREATE TABLE IF NOT EXISTS legal_consent (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT,
        accepted INTEGER NOT NULL DEFAULT 0,
        accepted_at TEXT,
        version TEXT DEFAULT '1.0'
      );

      CREATE TABLE IF NOT EXISTS trusted_agents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        executable TEXT,
        added_at TEXT DEFAULT (datetime('now'))
      );

      CREATE TABLE IF NOT EXISTS verdicts (
        session_id TEXT PRIMARY KEY,
        risk_score INTEGER,
        risk_level TEXT,
        verdict_summary TEXT,
        dna_json TEXT,
        generated_at TEXT,
        FOREIGN KEY (session_id) REFERENCES sessions(id)
      );

      CREATE TABLE IF NOT EXISTS evidence_chains (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        name TEXT NOT NULL,
        confidence REAL DEFAULT 0,
        steps_json TEXT,
        summary TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (session_id) REFERENCES sessions(id)
      );

      CREATE TABLE IF NOT EXISTS anti_evasion_signals (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        type TEXT NOT NULL,
        score INTEGER DEFAULT 0,
        confidence REAL DEFAULT 0,
        evidence_json TEXT,
        details_json TEXT,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (session_id) REFERENCES sessions(id)
      );

      CREATE TABLE IF NOT EXISTS canary_events (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        type TEXT NOT NULL,
        canary_name TEXT,
        confidence REAL DEFAULT 0,
        process_name TEXT,
        pid INTEGER,
        detail TEXT,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (session_id) REFERENCES sessions(id)
      );

      CREATE INDEX IF NOT EXISTS idx_flows_session ON flows(session_id);
      CREATE INDEX IF NOT EXISTS idx_behaviors_session ON behaviors(session_id);
      CREATE INDEX IF NOT EXISTS idx_evidence_session ON evidence(session_id);
      CREATE INDEX IF NOT EXISTS idx_alerts_session ON alerts(session_id);
      CREATE INDEX IF NOT EXISTS idx_chains_session ON evidence_chains(session_id);
      CREATE INDEX IF NOT EXISTS idx_signals_session ON anti_evasion_signals(session_id);
      CREATE TABLE IF NOT EXISTS blind_spots (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT,
        how_it_happened TEXT,
        sensor_failed TEXT,
        expected_behavior TEXT,
        actual_observation TEXT,
        impact TEXT,
        severity TEXT NOT NULL DEFAULT 'medium',
        status TEXT NOT NULL DEFAULT 'open',
        session_id TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        resolved_at TEXT,
        resolution TEXT,
        FOREIGN KEY (session_id) REFERENCES sessions(id)
      );

      CREATE INDEX IF NOT EXISTS idx_blindspots_status ON blind_spots(status);
      CREATE INDEX IF NOT EXISTS idx_blindspots_severity ON blind_spots(severity);
      CREATE INDEX IF NOT EXISTS idx_blindspots_sensor ON blind_spots(sensor_failed);

      CREATE TABLE IF NOT EXISTS campaign_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        campaign_id TEXT NOT NULL,
        scenario_id TEXT NOT NULL,
        scenario_name TEXT NOT NULL,
        passed INTEGER NOT NULL DEFAULT 0,
        risk_level TEXT,
        risk_score INTEGER DEFAULT 0,
        confidence_score REAL DEFAULT 0,
        coverage_score REAL DEFAULT 0,
        behaviors_json TEXT,
        expected_json TEXT,
        missing_json TEXT,
        unexpected_json TEXT,
        errors_json TEXT,
        details_json TEXT,
        duration_ms INTEGER DEFAULT 0,
        ran_at TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_campaign_id ON campaign_results(campaign_id);
      CREATE INDEX IF NOT EXISTS idx_campaign_passed ON campaign_results(passed);
      CREATE INDEX IF NOT EXISTS idx_canary_session ON canary_events(session_id);
    `);
  }

  createSession(
    id: string, config: Record<string, unknown>
  ): void {
    const stmt = this.db.prepare(
      'INSERT INTO sessions (id, start_time, status, config_json) VALUES (?, ?, ?, ?)'
    );
    stmt.run(id, new Date().toISOString(), 'running', JSON.stringify(config));
  }

  endSession(id: string): void {
    this.db.prepare(
      'UPDATE sessions SET end_time = ?, status = ? WHERE id = ?'
    ).run(new Date().toISOString(), 'stopped', id);
  }

  insertFlow(data: Record<string, unknown>): void {
    this.db.prepare(`
      INSERT INTO flows (id, session_id, timestamp, protocol, source_addr, source_port,
        dest_addr, dest_port, hostname, sni, tls_version, bytes_sent, bytes_received,
        duration_ms, method, path, content_type, status_code, headers_json, body_preview,
        dns_query, dns_response_json)
      VALUES (@id, @session_id, @timestamp, @protocol, @source_addr, @source_port,
        @dest_addr, @dest_port, @hostname, @sni, @tls_version, @bytes_sent, @bytes_received,
        @duration_ms, @method, @path, @content_type, @status_code, @headers_json, @body_preview,
        @dns_query, @dns_response_json)
    `).run(data);
  }

  insertProcess(data: Record<string, unknown>): void {
    this.db.prepare(`
      INSERT INTO processes (session_id, timestamp, pid, name, command_line,
        parent_pid, parent_name, username, risk_indicators_json)
      VALUES (@session_id, @timestamp, @pid, @name, @command_line,
        @parent_pid, @parent_name, @username, @risk_indicators_json)
    `).run(data);
  }

  insertFileAccess(data: Record<string, unknown>): void {
    this.db.prepare(`
      INSERT INTO file_accesses (session_id, timestamp, file_path, process_name,
        pid, operation, bytes_read)
      VALUES (@session_id, @timestamp, @file_path, @process_name,
        @pid, @operation, @bytes_read)
    `).run(data);
  }

  insertGitCommand(data: Record<string, unknown>): void {
    this.db.prepare(`
      INSERT INTO git_commands (session_id, timestamp, pid, process_name,
        command_line, action, repository)
      VALUES (@session_id, @timestamp, @pid, @process_name,
        @command_line, @action, @repository)
    `).run(data);
  }

  insertBehavior(data: Record<string, unknown>): void {
    this.db.prepare(`
      INSERT INTO behaviors (id, session_id, timestamp, type, confidence,
        source, evidence_json, artifacts_json)
      VALUES (@id, @session_id, @timestamp, @type, @confidence,
        @source, @evidence_json, @artifacts_json)
    `).run(data);
  }

  insertEvidence(data: Record<string, unknown>): void {
    this.db.prepare(`
      INSERT INTO evidence (id, session_id, timestamp, type, title, description,
        data_json, severity, flow_id, behavior_id)
      VALUES (@id, @session_id, @timestamp, @type, @title, @description,
        @data_json, @severity, @flow_id, @behavior_id)
    `).run(data);
  }

  insertAlert(data: Record<string, unknown>): void {
    this.db.prepare(`
      INSERT INTO alerts (session_id, timestamp, severity, title, description, evidence_json)
      VALUES (@session_id, @timestamp, @severity, @title, @description, @evidence_json)
    `).run(data);
  }

  getConsent(): { accepted: number; version?: string } | null {
    const row = this.db.prepare(
      'SELECT accepted, version FROM legal_consent ORDER BY id DESC LIMIT 1'
    ).get() as { accepted: number; version?: string } | undefined;
    return row || null;
  }

  setConsent(accepted: number): void {
    this.db.prepare(
      'INSERT INTO legal_consent (accepted, accepted_at, version) VALUES (?, ?, ?)'
    ).run(accepted, new Date().toISOString(), '1.0');
  }

  getSessions(limit = 10): Array<Record<string, unknown>> {
    return this.db.prepare(
      'SELECT * FROM sessions ORDER BY start_time DESC LIMIT ?'
    ).all(limit) as Array<Record<string, unknown>>;
  }

  getSessionFlows(sessionId: string): Array<Record<string, unknown>> {
    return this.db.prepare(
      'SELECT * FROM flows WHERE session_id = ? ORDER BY timestamp ASC'
    ).all(sessionId) as Array<Record<string, unknown>>;
  }

  getSessionBehaviors(sessionId: string): Array<Record<string, unknown>> {
    return this.db.prepare(
      'SELECT * FROM behaviors WHERE session_id = ? ORDER BY timestamp ASC'
    ).all(sessionId) as Array<Record<string, unknown>>;
  }

  getSessionEvidence(sessionId: string): Array<Record<string, unknown>> {
    return this.db.prepare(
      'SELECT * FROM evidence WHERE session_id = ? ORDER BY timestamp ASC'
    ).all(sessionId) as Array<Record<string, unknown>>;
  }

  getSessionVerdict(sessionId: string): Record<string, unknown> | null {
    const row = this.db.prepare(
      'SELECT * FROM verdicts WHERE session_id = ?'
    ).get(sessionId) as Record<string, unknown> | undefined;
    return row || null;
  }

  saveVerdict(data: Record<string, unknown>): void {
    this.db.prepare(`
      INSERT OR REPLACE INTO verdicts (session_id, risk_score, risk_level,
        verdict_summary, dna_json, generated_at)
      VALUES (@session_id, @risk_score, @risk_level,
        @verdict_summary, @dna_json, @generated_at)
    `).run(data);
  }

  getAlerts(sessionId: string, severity?: string): Array<Record<string, unknown>> {
    if (severity) {
      return this.db.prepare(
        'SELECT * FROM alerts WHERE session_id = ? AND severity = ? ORDER BY timestamp DESC'
      ).all(sessionId, severity) as Array<Record<string, unknown>>;
    }
    return this.db.prepare(
      'SELECT * FROM alerts WHERE session_id = ? ORDER BY timestamp DESC'
    ).all(sessionId) as Array<Record<string, unknown>>;
  }

  getTrustedAgents(): Array<Record<string, unknown>> {
    return this.db.prepare(
      'SELECT * FROM trusted_agents ORDER BY name ASC'
    ).all() as Array<Record<string, unknown>>;
  }

  addTrustedAgent(name: string, executable?: string): void {
    this.db.prepare(
      'INSERT OR IGNORE INTO trusted_agents (name, executable) VALUES (?, ?)'
    ).run(name, executable || null);
  }

  removeTrustedAgent(name: string): void {
    this.db.prepare(
      'DELETE FROM trusted_agents WHERE name = ?'
    ).run(name);
  }

  insertEvidenceChain(data: Record<string, unknown>): void {
    this.db.prepare(`
      INSERT OR REPLACE INTO evidence_chains (id, session_id, name, confidence, steps_json, summary)
      VALUES (@id, @session_id, @name, @confidence, @steps_json, @summary)
    `).run(data);
  }

  insertAntiEvasionSignal(data: Record<string, unknown>): void {
    this.db.prepare(`
      INSERT INTO anti_evasion_signals (id, session_id, type, score, confidence, evidence_json, details_json, timestamp)
      VALUES (@id, @session_id, @type, @score, @confidence, @evidence_json, @details_json, @timestamp)
    `).run(data);
  }

  insertCanaryEvent(data: Record<string, unknown>): void {
    this.db.prepare(`
      INSERT INTO canary_events (id, session_id, type, canary_name, confidence, process_name, pid, detail, timestamp)
      VALUES (@id, @session_id, @type, @canary_name, @confidence, @process_name, @pid, @detail, @timestamp)
    `).run(data);
  }

  getSessionChains(sessionId: string): Array<Record<string, unknown>> {
    return this.db.prepare(
      'SELECT * FROM evidence_chains WHERE session_id = ?'
    ).all(sessionId) as Array<Record<string, unknown>>;
  }

  getSessionSignals(sessionId: string): Array<Record<string, unknown>> {
    return this.db.prepare(
      'SELECT * FROM anti_evasion_signals WHERE session_id = ? ORDER BY timestamp DESC'
    ).all(sessionId) as Array<Record<string, unknown>>;
  }

  getSessionCanaryEvents(sessionId: string): Array<Record<string, unknown>> {
    return this.db.prepare(
      'SELECT * FROM canary_events WHERE session_id = ? ORDER BY timestamp DESC'
    ).all(sessionId) as Array<Record<string, unknown>>;
  }

  insertBlindSpot(data: Record<string, unknown>): void {
    this.db.prepare(`
      INSERT INTO blind_spots (id, title, description, how_it_happened, sensor_failed,
        expected_behavior, actual_observation, impact, severity, status, session_id,
        created_at, updated_at, resolved_at, resolution)
      VALUES (@id, @title, @description, @how_it_happened, @sensor_failed,
        @expected_behavior, @actual_observation, @impact, @severity, @status, @session_id,
        @created_at, @updated_at, @resolved_at, @resolution)
    `).run(data);
  }

  getBlindSpots(
    status?: string, severity?: string, sensor?: string, limit = 50
  ): Array<Record<string, unknown>> {
    let sql = 'SELECT * FROM blind_spots WHERE 1=1';
    const params: unknown[] = [];
    if (status) { sql += ' AND status = ?'; params.push(status); }
    if (severity) { sql += ' AND severity = ?'; params.push(severity); }
    if (sensor) { sql += ' AND sensor_failed = ?'; params.push(sensor); }
    sql += ' ORDER BY created_at DESC LIMIT ?';
    params.push(limit);
    return this.db.prepare(sql).all(...params) as Array<Record<string, unknown>>;
  }

  updateBlindSpotStatus(id: string, status: string, resolution?: string): void {
    if (status === 'resolved' && resolution) {
      this.db.prepare(
        'UPDATE blind_spots SET status = ?, resolution = ?, resolved_at = ?, updated_at = ? WHERE id = ?'
      ).run(status, resolution, new Date().toISOString(), new Date().toISOString(), id);
    } else {
      this.db.prepare(
        'UPDATE blind_spots SET status = ?, updated_at = ? WHERE id = ?'
      ).run(status, new Date().toISOString(), id);
    }
  }

  deleteBlindSpot(id: string): void {
    this.db.prepare('DELETE FROM blind_spots WHERE id = ?').run(id);
  }

  getBlindSpotStats(): Record<string, unknown> {
    const total = (this.db.prepare('SELECT COUNT(*) as c FROM blind_spots').get() as { c: number }).c;
    const open = (this.db.prepare("SELECT COUNT(*) as c FROM blind_spots WHERE status = 'open'").get() as { c: number }).c;
    const resolved = (this.db.prepare("SELECT COUNT(*) as c FROM blind_spots WHERE status = 'resolved'").get() as { c: number }).c;
    const bySeverity = this.db.prepare(
      'SELECT severity, COUNT(*) as count FROM blind_spots GROUP BY severity ORDER BY count DESC'
    ).all() as Array<{ severity: string; count: number }>;
    const bySensor = this.db.prepare(
      'SELECT sensor_failed, COUNT(*) as count FROM blind_spots WHERE sensor_failed IS NOT NULL GROUP BY sensor_failed ORDER BY count DESC'
    ).all() as Array<{ sensor_failed: string; count: number }>;
    return { total, open, resolved, bySeverity, bySensor };
  }

  insertCampaignResult(data: Record<string, unknown>): void {
    this.db.prepare(`
      INSERT OR REPLACE INTO campaign_results
        (campaign_id, scenario_id, scenario_name, passed, risk_level, risk_score,
         confidence_score, coverage_score, behaviors_json, expected_json,
         missing_json, unexpected_json, errors_json, details_json, duration_ms, ran_at)
      VALUES (@campaign_id, @scenario_id, @scenario_name, @passed, @risk_level, @risk_score,
        @confidence_score, @coverage_score, @behaviors_json, @expected_json,
        @missing_json, @unexpected_json, @errors_json, @details_json, @duration_ms, @ran_at)
    `).run(data);
  }

  getCampaignResults(campaignId: string): Array<Record<string, unknown>> {
    return this.db.prepare(
      'SELECT * FROM campaign_results WHERE campaign_id = ? ORDER BY ran_at ASC'
    ).all(campaignId) as Array<Record<string, unknown>>;
  }

  getCampaignSummaries(limit = 10): Array<Record<string, unknown>> {
    return this.db.prepare(`
      SELECT campaign_id,
        COUNT(*) as total,
        SUM(CASE WHEN passed = 1 THEN 1 ELSE 0 END) as passed,
        ROUND(AVG(risk_score), 1) as avg_risk,
        ROUND(AVG(coverage_score), 1) as avg_coverage,
        MAX(ran_at) as last_run
      FROM campaign_results
      GROUP BY campaign_id
      ORDER BY last_run DESC
      LIMIT ?
    `).all(limit) as Array<Record<string, unknown>>;
  }

  deleteCampaign(campaignId: string): void {
    this.db.prepare('DELETE FROM campaign_results WHERE campaign_id = ?').run(campaignId);
  }

  close(): void {
    this.db.close();
  }
}
