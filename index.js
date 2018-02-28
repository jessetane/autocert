'use strict';

var tls = require('tls')
var letiny = require('letiny')

var now = new Date().getTime()
setInterval(() => {
  now = new Date().getTime()
}, 60 * 1000).unref()

class AutoCert {
  constructor (opts) {
    this.email = opts.email
    this.url = opts.url || 'https://acme-v01.api.letsencrypt.org'
    this.maxAge = opts.maxAge || 75 * 24 * 60 * 60 * 1000 // 75 days
    this.challenges = opts.challenges || {}
    this.credentials = opts.credentials || {}
    this.cache = opts.cache === undefined ? {} : opts.cache
    this.queue = {}
  }

  certify (name, cb) {
    var queue = this.queue
    var q = queue[name]
    if (q && q.length) {
      q[q.length] = cb
      return
    } else {
      q = queue[name] = [ cb ]
    }
    this._tryLookup(name, (err, credential) => {
      if (err) return cbwrap(err)
      if (credential) return cbwrap(null, credential)
      this._tryLetsencrypt(name, cbwrap)
    })
    var cache = this.cache
    function cbwrap (err, credential) {
      var context = null
      if (!err && credential) {
        context = cache && cache[name]
        if (!context) {
          context = new tls.createSecureContext({
            key: credential.key,
            cert: credential.cert,
          })
          if (cache) {
            cache[name] = context
          }
        }
      }
      queue[name] = null
      q.forEach(cb => {
        cb.call(null, err, context)
      })
    }
  }

  getCredential (name, cb) {
    cb(null, this.credentials[name])
  }

  setCredential (name, credential, cb) {
    this.credentials[name] = credential
    cb()
  }

  setChallenge (key, value, cb) {
    this.challenges[key] = value
    cb()
  }

  _tryLookup (name, cb) {
    this.getCredential(name, (err, credential) => {
      if (err) return cb(err)
      if (!credential) return cb()
      if (!credential.key || !credential.cert || isNaN(credential.date)) {
        cb()
      } else if (now - credential.date > this.maxAge) {
        cb()
      } else {
        cb(null, credential)
      }
    })
  }

  _tryLetsencrypt (name, cb) {
    this.getCredential(this.email, (err, accountKey) => {
      if (err) return cb(err)
      letiny.getCert({
        url: this.url,
        email: this.email,
        accountKey,
        domains: [ name ],
        agreeTerms: true,
        challenge: (name, path, data, cb) => {
          this.setChallenge(path, data, cb)
        }
      }, (err, cert, key, caCert, _accountKey) => {
        if (err) return cb(err)
        var credential = {
          key: key,
          cert: cert + '\n' + caCert,
          date: new Date().getTime(),
        }
        if (!accountKey) {
          this.setCredential(this.email, _accountKey, err => {
            if (err) return cb(err)
            setCredential.call(this)
          })
        } else {
          setCredential.call(this)
        }
        function setCredential () {
          this.setCredential(name, credential, err => {
            if (err) return cb(err)
            cb(null, credential)
          })
        }
      })
    })
  }
}

AutoCert.tlsOpts = function (opts) {
  var autocert = new AutoCert(opts)
  return {
    SNICallback: autocert.certify.bind(autocert)
  }
}

module.exports = AutoCert
