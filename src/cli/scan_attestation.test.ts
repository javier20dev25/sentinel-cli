import { describe, it, expect } from 'vitest';
import {
    canonicalize,
    signScanAttestation,
    verifyScanAttestation,
    findingSha,
    AttestationInput,
} from './intelligence/scan_attestation';

const KEY = 'test-key-0123456789abcdef0123456789abcdef';

const INPUT: AttestationInput = {
    pkg: 'keyv@6.0.0',
    name: 'keyv',
    version: '6.0.0',
    verdict: 'MALICIOUS',
    fileCount: 12,
    findingCount: 3,
    criticalCount: 2,
    highCount: 1,
    findingShas: ['a'.repeat(64), 'b'.repeat(64), 'c'.repeat(64)].sort(),
    sizeBytes: 30_000,
};

describe('scan attestation', () => {
    it('is deterministic for the same input, key and timestamp', () => {
        const a = signScanAttestation(INPUT, KEY, 1_700_000_000_000);
        const b = signScanAttestation(INPUT, KEY, 1_700_000_000_000);
        expect(a.signature).toBe(b.signature);
        expect(a.signature.length).toBe(64);
    });

    it('signs differently at different timestamps', () => {
        const a = signScanAttestation(INPUT, KEY, 1_700_000_000_000);
        const b = signScanAttestation(INPUT, KEY, 1_700_000_000_001);
        expect(a.signature).not.toBe(b.signature);
    });

    it('verifies a valid attestation', () => {
        const att = signScanAttestation(INPUT, KEY);
        expect(verifyScanAttestation(att, KEY)).toBe(true);
    });

    it('rejects tampered verdict', () => {
        const att = signScanAttestation(INPUT, KEY);
        const tampered = { ...att, input: { ...att.input, verdict: 'SAFE' as const } };
        expect(verifyScanAttestation(tampered, KEY)).toBe(false);
    });

    it('rejects a tampered finding count', () => {
        const att = signScanAttestation(INPUT, KEY);
        const tampered = { ...att, input: { ...att.input, findingCount: 0 } };
        expect(verifyScanAttestation(tampered, KEY)).toBe(false);
    });

    it('rejects an added finding digest', () => {
        const att = signScanAttestation(INPUT, KEY);
        const tampered = {
            ...att,
            input: { ...att.input, findingShas: [...att.input.findingShas, 'd'.repeat(64)] },
        };
        expect(verifyScanAttestation(tampered, KEY)).toBe(false);
    });

    it('rejects signatures made with a different key', () => {
        const att = signScanAttestation(INPUT, KEY);
        expect(verifyScanAttestation(att, 'other-key-0123456789abcdef')).toBe(false);
    });

    it('rejects malformed attestations', () => {
        expect(verifyScanAttestation({} as never, KEY)).toBe(false);
        expect(verifyScanAttestation(null as never, KEY)).toBe(false);
    });

    it('canonicalize is independent of key order', () => {
        expect(canonicalize({ a: 1, b: { c: [1, 2] } }))
            .toBe(canonicalize({ b: { c: [1, 2] }, a: 1 }));
        expect(canonicalize({ a: 1 })).toBe(JSON.stringify({ a: 1 }));
    });

    it('findingSha is deterministic and content-sensitive', () => {
        expect(findingSha('X', 'CRITICAL', 'f.js')).toBe(findingSha('X', 'CRITICAL', 'f.js'));
        expect(findingSha('X', 'CRITICAL', 'f.js')).not.toBe(findingSha('X', 'HIGH', 'f.js'));
    });
});
