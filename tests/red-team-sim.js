const cp = require('child_process');
const https = require('https');

function harmlessMetrics() {
    const out = cp.spawnSync('echo', ['simulation']);
    return out.stdout.toString();
}

function fakeNetwork() {
    return new Promise((resolve) => {
        const req = https.request('https://httpbin.org/get', (res) => {
            resolve({ status: res.statusCode });
        });
        req.end();
    });
}

function decryptBuffer() {
    const raw = process.env.SENTINEL_SECRET || 'none';
    const decoded = Buffer.from(raw, 'base64');
    return decoded;
}

eval('console.log("sim-eval")');

const vm = require('vm');
const sandbox = { x: 10 };
vm.runInNewContext('x += 1', sandbox);

const fn = new Function('a', 'b', 'return a + b');
console.log(fn(1, 2), harmlessMetrics());

module.exports = { fakeNetwork, harmlessMetrics };
