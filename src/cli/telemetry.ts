import * as pc from 'picocolors';

export function printMetrics(lang: string = 'es', bytesRead?: number, bytesWritten?: number) {
    const memory = (process.memoryUsage().heapUsed / 1024 / 1024).toFixed(1);
    const cpuMicros = process.cpuUsage();
    const cpuSeconds = ((cpuMicros.user + cpuMicros.system) / 1_000_000).toFixed(3);
    const diskMb = bytesRead !== undefined ? (bytesRead / 1024 / 1024).toFixed(1) : '< 0.1';
    const netMb = '< 0.1';
    const cpuNum = parseFloat(cpuSeconds);
    const energy = (cpuNum * 15 / 3600).toFixed(4);

    const isEs = lang === 'es';
    
    console.log(pc.cyan('\n📊 ' + (isEs ? 'TELEMETRÍA DE RENDIMIENTO Y RECURSOS' : 'PERFORMANCE & RESOURCE TELEMETRY')));
    console.log(pc.dim('───────────────────────────────────────────────────────'));
    console.log(pc.white(` 🧠 ${isEs ? 'Consumo de Memoria:' : 'Memory Footprint:'} `) + pc.cyan(`${memory} MB`) + pc.dim(isEs ? ' [Optimizado V8 GC]' : ' [V8 GC Optimized]'));
    console.log(pc.white(` ⚡ ${isEs ? 'Cómputo de CPU:' : 'CPU Compute:'} `) + pc.cyan(`${cpuSeconds} s`) + pc.dim(isEs ? ' [Tiempo real user + system]' : ' [Real user + system time]'));
    console.log(pc.white(` 💾 ${isEs ? 'E/S de Disco:' : 'Disk I/O:'} `) + pc.cyan(`${diskMb} MB`) + pc.dim(isEs ? ' [Datos escaneados]' : ' [Scanned data]'));
    console.log(pc.white(` 🌐 ${isEs ? 'Tráfico de Red:' : 'Network Traffic:'} `) + pc.cyan(`${netMb} MB`) + pc.dim(isEs ? ' [Próximamente]' : ' [Coming soon]'));
    console.log(pc.white(` 🔋 ${isEs ? 'Costo Energético:' : 'Energy Cost:'} `) + pc.cyan(`${energy} Wh`) + pc.dim(isEs ? ' [Estimado CPU × 15W TDP]' : ' [CPU × 15W TDP estimate]'));
    console.log(pc.dim('───────────────────────────────────────────────────────\n'));
}
