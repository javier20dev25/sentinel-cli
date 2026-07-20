const express = require('express')
const app = express()
const port = process.env.PORT || 3000

app.get('/', function(req, res) {
  res.json({ status: 'ok', message: 'Hello world' })
})

app.get('/health', function(req, res) {
  res.status(200).end()
})

app.listen(port, function() {
  console.log('Server running on port ' + port)
})

module.exports = app
