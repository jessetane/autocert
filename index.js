var fs = require('fs')
var tls = require('tls')
var letiny = require('letiny')

var maxCertificateAge = 75 * 24 * 60 * 60 * 1000 // 75 days
var letsEncryptUrl = 'https://acme-v01.api.letsencrypt.org'
// var letsEncryptUrl = 'https://acme-staging.api.letsencrypt.org'

var now = new Date().getTime()
setInterval(() => {
  now = new Date().getTime()
}, 60 * 1000).unref()

module.exports = function (opts) {
  var email = opts.email
  var storage = opts.storage
  var challenges = opts.challenges
  if (!email || !storage || !challenges) {
    throw new Error('missing a required option')
  }
  var certificates = {}
  var queue = null
  return {
    SNICallback: (name, cb) => {
      var certificate = certificates[name]
      if (!certificate || now - certificate.date > maxCertificateAge) {
        createContext(name, cb)
      } else {
        cb(null, certificate.context)
      }
    }
  }

  function createContext (name, _cb) {
    if (queue) {
      queue[queue.length] = _cb
      return
    } else {
      queue = [ _cb ]
    }
    tryFileSystem(name, (err, certificate) => {
      if (err) return cb(err)
      if (certificate) return cb(null, certificate)
      tryLetsencrypt(name, cb)
    })
    function cb (err, certificate) {
      var context = null
      if (!err) {
        certificates[name] = certificate
        certificate.context = context = new tls.createSecureContext({
          key: certificate.key,
          cert: certificate.cert,
        })
      }
      var cbs = queue
      queue = null
      cbs.forEach(_cb => {
        _cb.call(null, err, context)
      })
    }
  }

  function tryFileSystem (name, cb) {
    var filename = storage + '/' + name + '.json'
    fs.readFile(filename, 'utf8', (err, data) => {
      if (err && err.code !== 'ENOENT') return cb(err)
      if (!data) return cb()
      try {
        var certificate = JSON.parse(data)
      } catch (err) {
        return cb(err)
      }
      if (!certificate.key || !certificate.cert || isNaN(certificate.date)) {
        cb()
      } else if (now - certificate.date > maxCertificateAge) {
        cb()
      } else {
        cb(null, certificate)
      }
    })
  }

  function tryLetsencrypt (name, cb) {
    letiny.getCert({
      url: letsEncryptUrl,
      domains: [ name ],
      email: email,
      webroot: challenges,
      agreeTerms: true,
    }, (err, cert, key, caCert) => {
      if (err) return cb(err)
      certificate = {
        key: key,
        cert: cert + '\n' + caCert,
        date: new Date().getTime(),
      }
      var filename = storage + '/' + name + '.json'
      fs.writeFile(filename, JSON.stringify(certificate), err => {
        if (err) return cb(err)
        fs.chmod(filename, '600', err => {
          if (err) return cb(err)
          cb(null, certificate)
        })
      })
    })
  }
}
