var http = require('http')
var https = require('https')
var autocert = require('./')

var challenges = {}

http.createServer((req, res) => {
  console.log(req.method + ' ' + req.url)
  console.log('headers:', req.headers)

  var proof = challenges[req.url]
  console.log('proof:', proof)

  if (proof) {
    res.end(proof)
  } else {
    res.statusCode = 404
    res.end('not found')
  }
}).listen(8080)

https.createServer(autocert.tlsOpts({
  url: 'https://acme-staging.api.letsencrypt.org',
  email: 'info@example.com',
  challenges,
}), (req, res) => {
  res.end('secure af')
}).listen(4430)
