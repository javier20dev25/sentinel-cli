/**
 * Sentinel Baseline Manager (v1.0)
 *
 * Creates and compares system snapshots to detect "Drift".
 */
export declare class BaselineManager {
    private baselineDir;
    constructor();
    /**
     * Creates a snapshot of the current environment.
     */
    createBaseline(name: string): void;
    /**
     * Compares current state with a saved baseline.
     */
    diffBaseline(name: string): void;
}
