type AnimationSet = 'bars' | 'dots' | 'wave' | 'pulse';
export declare class LiveIndicator {
    private frame;
    private colorCycle;
    private interval;
    private message;
    private running;
    private anim;
    private timestamp;
    start(message: string, anim?: AnimationSet): void;
    update(message: string): void;
    stop(): void;
    private tick;
    section(name: string): void;
}
export {};
