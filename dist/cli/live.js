"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LiveIndicator = void 0;
const rgb = (r, g, b) => `\x1b[38;2;${r};${g};${b}m`;
const reset = '\x1b[0m';
function rgbGradient(t, phase) {
    const r = Math.floor(127 + 127 * Math.sin(t * 0.3 + phase));
    const g = Math.floor(127 + 127 * Math.sin(t * 0.3 + phase + 2.09));
    const b = Math.floor(127 + 127 * Math.sin(t * 0.3 + phase + 4.19));
    return rgb(r, g, b);
}
const barFrames = ['▰▱▱▱▱▱▱▱▱▱', '▰▰▱▱▱▱▱▱▱▱', '▰▰▰▱▱▱▱▱▱▱', '▰▰▰▰▱▱▱▱▱▱', '▰▰▰▰▰▱▱▱▱▱', '▰▰▰▰▰▰▱▱▱▱', '▰▰▰▰▰▰▰▱▱▱', '▰▰▰▰▰▰▰▰▱▱', '▰▰▰▰▰▰▰▰▰▱', '▰▰▰▰▰▰▰▰▰▰'];
const dotFrames = ['⣀', '⣤', '⣶', '⣿', '⣶', '⣤'];
const waveFrames = ['⠁', '⠂', '⠄', '⡀', '⢀', '⠠', '⠐', '⠈'];
const pulseFrames = ['█', '▓', '▒', '░', '▒', '▓'];
const animSets = {
    bars: barFrames,
    dots: dotFrames,
    wave: waveFrames,
    pulse: pulseFrames,
};
class LiveIndicator {
    constructor() {
        this.frame = 0;
        this.colorCycle = 0;
        this.interval = null;
        this.message = '';
        this.running = false;
        this.anim = 'bars';
        this.timestamp = 0;
    }
    start(message, anim = 'bars') {
        if (this.running)
            return;
        this.running = true;
        this.message = message;
        this.anim = anim;
        this.frame = 0;
        this.colorCycle = 0;
        this.timestamp = Date.now();
        this.interval = setInterval(() => this.tick(), 60);
    }
    update(message) {
        this.message = message;
    }
    stop() {
        if (this.interval) {
            clearInterval(this.interval);
            this.interval = null;
        }
        this.running = false;
        const elapsed = ((Date.now() - this.timestamp) / 1000).toFixed(1);
        process.stdout.write('\r' + ' '.repeat(process.stdout.columns || 60) + '\r');
        process.stdout.write(`  ✔ Done in ${elapsed}s\n`);
    }
    tick() {
        const frames = animSets[this.anim];
        const f = frames[this.frame % frames.length];
        this.colorCycle++;
        const color = rgbGradient(this.colorCycle * 0.1, 0);
        process.stdout.write(`\r${color}${f}${reset}  ${this.message}`);
        this.frame++;
    }
    section(name) {
        const color = rgbGradient(this.colorCycle * 0.05, 0);
        process.stdout.write(`\n${color}── ${name}${reset}\n`);
    }
}
exports.LiveIndicator = LiveIndicator;
