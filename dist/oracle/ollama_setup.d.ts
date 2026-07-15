export interface OllamaStatus {
    installed: boolean;
    running: boolean;
    models: string[];
    hasModel: boolean;
    targetModel: string;
}
/** Check if Ollama is installed by looking for the binary */
export declare function isOllamaInstalled(): boolean;
/** Check if Ollama API is reachable */
export declare function isOllamaRunning(): Promise<boolean>;
/** Start Ollama serve in background */
export declare function startOllama(): Promise<boolean>;
/** List installed models from Ollama API */
export declare function listModels(): Promise<string[]>;
/** Pull a model using Ollama CLI */
export declare function pullModel(model: string): Promise<boolean>;
/** Check full Ollama status */
export declare function checkOllamaStatus(targetModel?: string): Promise<OllamaStatus>;
/**
 * Full auto-setup: ensure Ollama is installed, running, and has the target model.
 * Returns true if everything is ready.
 */
export declare function ensureOllamaReady(targetModel?: string): Promise<boolean>;
