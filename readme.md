# autocert
Get a TLS options object that will automagically certify your domains.

## Why
Obligatory [Let's Encrypt](https://letsencrypt.org/) thingy.

## How
[letiny](https://github.com/anatolsommer/letiny)

## Example
```javascript
var fs = require('fs')
var http = require('http')
var https = require('https')
var autocert = require('autocert')

http.createServer((req, res) => {
  if (req.url.indexOf('/.well-known/') === 0) {
    fs.createReadStream(__dirname + req.url)
      .pipe(res)
  } else {
    res.statusCode = 301
    res.setHeader('location', 'https://mydomain.org')
    res.end()
  }
}).listen(80)

https.createServer(autocert({
  email: 'webmaster@mydomain.org',
  storage: '/etc/pki/autocert',
  challenges: __dirname,
}), (req, res) => {
  res.end('secure af')
}).listen(443)
```

## License
MIT
