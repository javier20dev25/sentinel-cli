function simulation() {
    const fakeEnv = process.env.NODE_ENV || 'development';
    console.log('[sim] env check:', fakeEnv);
}

eval('console.log("simulation marker")');

const decoded = Buffer.from('c2ltdWxhdGlvbiBkYXRh', 'base64').toString();
console.log('[sim] decoded:', decoded);

const payload = new Function('x', 'return x + 1');
console.log('[sim] function:', payload(5));

module.exports = { simulation };
