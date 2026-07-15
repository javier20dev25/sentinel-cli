export interface VaultRecordScan {
    id: string;
    repo: string;
    pr: number;
    author: string;
    score: number;
    band: string;
}
export interface VaultSignal {
    repo: string;
    author: string;
    signal_type: string;
    weight: number;
    file_path: string;
    source_scan: string;
}
export interface Vault {
    recordScan(scan: VaultRecordScan): void;
    recordSignal(signal: VaultSignal): void;
    getCorrelations(author: string, currentSignals: string[]): unknown[];
}
