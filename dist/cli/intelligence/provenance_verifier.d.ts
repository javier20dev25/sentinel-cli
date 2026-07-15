export interface ProvenanceAttestation {
    type: string;
    issuer: string;
    subject: string;
    predicateType: string;
    timestamp: string;
    slsaLevel?: string;
}
export interface ProvenanceResult {
    packageName: string;
    version: string;
    verified: boolean;
    attestations: ProvenanceAttestation[];
    error?: string;
}
export declare class ProvenanceVerifier {
    checkCommandAvailable(): boolean;
    verify(packageName: string, version?: string): Promise<ProvenanceResult>;
}
