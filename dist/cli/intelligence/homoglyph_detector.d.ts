export interface HomoglyphMatch {
    packageName: string;
    target: string;
    distance: number;
    homoglyphs: string[];
    severity: 'LOW' | 'MEDIUM' | 'HIGH';
}
export interface HomoglyphResult {
    packageName: string;
    isSuspicious: boolean;
    matches: HomoglyphMatch[];
    confidence: number;
}
export declare function detectHomoglyph(packageName: string, topPackages?: string[]): HomoglyphResult;
