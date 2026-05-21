"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.printMetrics = printMetrics;
const pc = __importStar(require("picocolors"));
function printMetrics(lang = 'es', bytesRead, bytesWritten) {
    const memory = (process.memoryUsage().heapUsed / 1024 / 1024).toFixed(1);
    const cpuMicros = process.cpuUsage();
    const cpuSeconds = ((cpuMicros.user + cpuMicros.system) / 1000000).toFixed(3);
    const diskMb = bytesRead !== undefined ? (bytesRead / 1024 / 1024).toFixed(1) : '< 0.1';
    const netMb = '< 0.1';
    const cpuNum = parseFloat(cpuSeconds);
    const energy = (cpuNum * 15 / 3600).toFixed(4);
    const isEs = lang === 'es';
    console.log(pc.cyan('\n📊 ' + (isEs ? 'TELEMETRÍA DE RENDIMIENTO Y RECURSOS ORACLE' : 'ORACLE PERFORMANCE & RESOURCE TELEMETRY')));
    console.log(pc.dim('───────────────────────────────────────────────────────'));
    console.log(pc.white(` 🧠 ${isEs ? 'Consumo de Memoria:' : 'Memory Footprint:'} `) + pc.cyan(`${memory} MB`) + pc.dim(isEs ? ' [Optimizado V8 GC]' : ' [V8 GC Optimized]'));
    console.log(pc.white(` ⚡ ${isEs ? 'Cómputo de CPU:' : 'CPU Compute:'} `) + pc.cyan(`${cpuSeconds} s`) + pc.dim(isEs ? ' [Tiempo real user + system]' : ' [Real user + system time]'));
    console.log(pc.white(` 💾 ${isEs ? 'E/S de Disco:' : 'Disk I/O:'} `) + pc.cyan(`${diskMb} MB`) + pc.dim(isEs ? ' [Datos escaneados]' : ' [Scanned data]'));
    console.log(pc.white(` 🌐 ${isEs ? 'Tráfico de Red:' : 'Network Traffic:'} `) + pc.cyan(`${netMb} MB`) + pc.dim(isEs ? ' [Próximamente]' : ' [Coming soon]'));
    console.log(pc.white(` 🔋 ${isEs ? 'Costo Energético:' : 'Energy Cost:'} `) + pc.cyan(`${energy} Wh`) + pc.dim(isEs ? ' [Estimado CPU × 15W TDP]' : ' [CPU × 15W TDP estimate]'));
    console.log(pc.dim('───────────────────────────────────────────────────────\n'));
}
