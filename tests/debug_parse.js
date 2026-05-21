const fs = require('fs');
const diff = fs.readFileSync(process.argv[2], 'utf8');
console.log('First line:', diff.split('\n')[0]);
console.log('Total lines:', diff.split('\n').length);

const parts = diff.split(/(?=^diff --git )/m);
console.log('Parts count:', parts.length);

parts.forEach((p, i) => {
    const t = p.trim();
    if (!t) {
        console.log(`Part ${i}: empty`);
        return;
    }
    const m = t.match(/^diff --git a\/\S+ b\/(.+)$/m);
    if (m) {
        console.log(`Part ${i}: filename="${m[1]}" lines=${t.split('\n').length}`);
    } else {
        console.log(`Part ${i}: NO MATCH firstLine="${t.split('\n')[0]}"`);
    }
});
