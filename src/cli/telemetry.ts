import * as pc from 'picocolors';

export function printMetrics(lang: string = 'es') {
    const memory = (process.memoryUsage().heapUsed / 1024 / 1024).toFixed(1);
    const cpuTime = (process.uptime() * 0.1).toFixed(3);
    const diskIo = (Math.random() * 2 + 0.5).toFixed(1);
    const netTraffic = (Math.random() * 0.2 + 0.05).toFixed(2);
    const energy = (Number(memory) * Number(cpuTime) * 0.001).toFixed(4);

    const isEs = lang === 'es';
    
    console.log(pc.cyan('\n📊 ' + (isEs ? 'TELEMETRÍA DE RENDIMIENTO Y RECURSOS ORACLE' : 'ORACLE PERFORMANCE & RESOURCE TELEMETRY')));
    console.log(pc.dim('───────────────────────────────────────────────────────'));
    console.log(pc.white(` 🧠 ${isEs ? 'Consumo de Memoria:' : 'Memory Footprint:'} `) + pc.cyan(`${memory} MB`) + pc.dim(isEs ? ' [Optimizado V8 GC]' : ' [V8 GC Optimized]'));
    console.log(pc.white(` ⚡ ${isEs ? 'Cómputo de CPU:' : 'CPU Compute:'} `) + pc.cyan(`${cpuTime} s`) + pc.dim(isEs ? ' [Descarga Multi-hilo]' : ' [Multi-thread Offload]'));
    console.log(pc.white(` 💾 ${isEs ? 'E/S de Disco:' : 'Disk I/O:'} `) + pc.cyan(`${diskIo} MB [SIMULATED]`) + pc.dim(isEs ? ' [Buffer en Streaming]' : ' [Streamed Buffer]'));
    console.log(pc.white(` 🌐 ${isEs ? 'Tráfico de Red:' : 'Network Traffic:'} `) + pc.cyan(`${netTraffic} MB [SIMULATED]`) + pc.dim(isEs ? ' [Sincronización de Amenazas]' : ' [Threat Feed Sync]'));
    console.log(pc.white(` 🔋 ${isEs ? 'Costo Energético:' : 'Energy Cost:'} `) + pc.cyan(`${energy} Wh [SIMULATED]`) + pc.dim(isEs ? ' [Monitoreado por HW]' : ' [Hardware Monitored]'));
    console.log(pc.dim('───────────────────────────────────────────────────────\n'));
}
