export declare function listDetectedAgents(): {
    name: string;
    detected: boolean;
}[];
export declare function runInstall(targetAgents?: string[]): {
    results: {
        agent: string;
        installed: string[];
        errors: string[];
    }[];
};
export declare function installSkillsCommand(args: string[]): void;
