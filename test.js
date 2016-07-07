var fs = require('fs')
var http = require('http')
var https = require('https')
var autocert = require('./')

http.createServer((req, res) => {
  fs.createReadStream(__dirname + req.url)
    .pipe(res)
}).listen(8080)

https.createServer(autocert({
  email: 'info@example.com',
  storage: __dirname,
  challenges: __dirname,
}), (req, res) => {
  res.end('secure af')
}).listen(4430)
