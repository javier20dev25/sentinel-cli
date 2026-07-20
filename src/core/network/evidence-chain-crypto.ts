import { createHash } from 'crypto';
import { Evidence, generateId } from './types';

export interface EvidenceRecord {
  index: number;
  timestamp: string;
  evidenceId: string;
  evidenceType: string;
  summary: string;
  previousHash: string | null;
  hash: string;
}

export interface EvidenceChainVerification {
  totalRecords: number;
  chainValid: boolean;
  firstHash: string;
  lastHash: string;
  tamperedIndices: number[];
  verifiedAt: string;
}

function computeRecordHash(
  index: number,
  timestamp: string,
  evidenceId: string,
  evidenceType: string,
  summary: string,
  previousHash: string | null,
): string {
  const payload = [
    String(index),
    timestamp,
    evidenceId,
    evidenceType,
    summary,
    previousHash ?? '',
  ].join('|');
  return createHash('sha256').update(payload, 'utf-8').digest('hex');
}

export function buildEvidenceChain(evidenceList: Evidence[]): EvidenceRecord[] {
  const sorted = [...evidenceList].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime(),
  );

  const records: EvidenceRecord[] = [];
  let previousHash: string | null = null;

  for (let i = 0; i < sorted.length; i++) {
    const ev = sorted[i];
    const timestamp = ev.timestamp instanceof Date
      ? ev.timestamp.toISOString()
      : new Date(ev.timestamp).toISOString();
    const summary = `[${ev.severity}] ${ev.title}`;

    const hash = computeRecordHash(i, timestamp, ev.id, ev.type, summary, previousHash);

    records.push({
      index: i,
      timestamp,
      evidenceId: ev.id,
      evidenceType: ev.type,
      summary,
      previousHash,
      hash,
    });

    previousHash = hash;
  }

  return records;
}

export function verifyEvidenceChain(records: EvidenceRecord[]): EvidenceChainVerification {
  const tamperedIndices: number[] = [];
  let previousHash: string | null = null;

  for (let i = 0; i < records.length; i++) {
    const rec = records[i];
    const expectedHash = computeRecordHash(
      rec.index,
      rec.timestamp,
      rec.evidenceId,
      rec.evidenceType,
      rec.summary,
      previousHash,
    );

    if (expectedHash !== rec.hash) {
      tamperedIndices.push(i);
    }

    if (rec.previousHash !== previousHash) {
      tamperedIndices.push(i);
    }

    previousHash = rec.hash;
  }

  return {
    totalRecords: records.length,
    chainValid: tamperedIndices.length === 0,
    firstHash: records.length > 0 ? records[0].hash : '',
    lastHash: records.length > 0 ? records[records.length - 1].hash : '',
    tamperedIndices,
    verifiedAt: new Date().toISOString(),
  };
}
