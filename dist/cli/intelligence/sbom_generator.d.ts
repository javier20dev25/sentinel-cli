import { LockfileEntry } from './lockfile_parser';
export interface SbomComponent {
    type: string;
    name: string;
    version: string;
    purl: string;
    properties?: {
        name: string;
        value: string;
    }[];
}
export interface SbomResult {
    format: string;
    bomFormat: string;
    specVersion: string;
    serialNumber: string;
    version: number;
    metadata: any;
    components: SbomComponent[];
}
export declare class SbomGenerator {
    private parser;
    constructor();
    generate(lockfilePath: string): SbomResult;
    generateFromEntries(entries: LockfileEntry[], format: string): SbomResult;
    toCycloneDx(entries: LockfileEntry[]): SbomResult;
    toPurl(name: string, version: string): string;
    private generateSerial;
}
export interface CveReference {
    id: string;
    severity: string;
    score: number;
    summary: string;
    affectedVersions: string;
    fixedIn?: string;
}
export declare function enrichSbomWithCves(sbom: any, osvResults: any[] | null | undefined): any;
