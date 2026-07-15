/**
 * Sentinel Typosquatting Detector (v5.0)
 *
 * Detects typosquatting attacks against popular npm packages
 * using Levenshtein distance and homoglyph character substitution.
 */
export interface TyposquatResult {
    isSuspicious: boolean;
    matches: TyposquatMatch[];
}
export interface TyposquatMatch {
    target: string;
    distance: number;
    homoglyphs: string[];
}
export declare class TyposquatDetector {
    private popularSet;
    constructor();
    /**
     * Check a package name for typosquatting against popular packages.
     */
    check(name: string): TyposquatResult;
    /**
     * Levenshtein distance between two strings.
     */
    private levenshtein;
    /**
     * Find homoglyph characters between two strings.
     */
    private findHomoglyphs;
}
