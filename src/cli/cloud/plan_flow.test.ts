import { describe, it, expect, vi } from 'vitest';
import { isSafePlanUrl, resolvePlanLandingUrl, offerPlanLanding } from './plan_flow';

describe('plan_flow isSafePlanUrl', () => {
    it('accepts https URLs', () => {
        expect(isSafePlanUrl('https://sentinel.example.com/#pricing')).toBe(true);
        expect(isSafePlanUrl('https://127.0.0.1')).toBe(true);
    });

    it('accepts http only to loopback hosts (local dev)', () => {
        expect(isSafePlanUrl('http://localhost:8787/#pricing')).toBe(true);
        expect(isSafePlanUrl('http://127.0.0.1:8787')).toBe(true);
    });

    it('rejects http to non-loopback, other schemes and garbage', () => {
        expect(isSafePlanUrl('http://cloud.example.com')).toBe(false);
        expect(isSafePlanUrl('javascript:alert(1)')).toBe(false);
        expect(isSafePlanUrl('not-a-url')).toBe(false);
    });
});

describe('plan_flow resolvePlanLandingUrl', () => {
    it('falls back to baseUrl + /#pricing when no landingUrl is advertised', () => {
        expect(resolvePlanLandingUrl('https://sentinel.example.com/', null)).toBe(
            'https://sentinel.example.com/#pricing'
        );
        expect(resolvePlanLandingUrl('https://sentinel.example.com', undefined)).toBe(
            'https://sentinel.example.com/#pricing'
        );
    });

    it('prefers the server landingUrl when it is safe to open', () => {
        expect(resolvePlanLandingUrl('https://api.example.com', 'https://sentinel.example.com/plans')).toBe(
            'https://sentinel.example.com/plans'
        );
    });

    it('ignores an unsafe landingUrl and falls back', () => {
        expect(resolvePlanLandingUrl('https://api.example.com', 'http://evil.example.com')).toBe(
            'https://api.example.com/#pricing'
        );
    });
});

describe('plan_flow offerPlanLanding', () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    it('interactive: prompts for ENTER, then opens the URL', async () => {
        const open = vi.fn(() => true);
        const prompt = vi.fn(async () => undefined);
        const result = await offerPlanLanding('https://sentinel.example.com/#pricing', {
            open,
            prompt,
            isTTY: true,
        });
        expect(result).toBe('opened');
        expect(prompt).toHaveBeenCalledWith(expect.stringContaining('ENTER'));
        expect(open).toHaveBeenCalledWith('https://sentinel.example.com/#pricing');
    });

    it('non-interactive: never blocks, never opens, prints the URL', async () => {
        const open = vi.fn(() => true);
        const prompt = vi.fn(async () => undefined);
        const result = await offerPlanLanding('https://sentinel.example.com/#pricing', {
            open,
            prompt,
            isTTY: false,
        });
        expect(result).toBe('shown');
        expect(prompt).not.toHaveBeenCalled();
        expect(open).not.toHaveBeenCalled();
        expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('https://sentinel.example.com/#pricing'));
    });
});