'use strict';

var tls = require('tls')
var acme = require('acme-client')

var now = new Date().getTime()
setInterval(() => {
  now = new Date().getTime()
}, 60 * 1000).unref()

class AutoCert {
  constructor (opts) {
    this.email = opts.email
    this.url = opts.url || 'https://acme-v02.api.letsencrypt.org/directory'
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
    if (value) {
      this.challenges[key] = value
    } else {
      delete this.challenges[key]
    }
    if (cb) cb()
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
      if (!accountKey) return cb(new Error('Account creation not yet supported'))
      var client = new acme.Client({
        directoryUrl: this.url,
        accountKey,
      })
      var self = this
      async function go () {
        var [key, csr] = await acme.forge.createCsr({
          commonName: name
        })
        async function challengeCreateFn (authz, challenge, keyAuthorization) {
          if (challenge.type === 'http-01') {
            var path = `/.well-known/acme-challenge/${challenge.token}`
            self.setChallenge(path, keyAuthorization)
          } else {
            throw new Error('unknown challenge type', challenge.type)
          }
        }
        async function challengeRemoveFn (authz, challenge) {
          if (challenge.type === 'http-01') {
            var path = `/.well-known/acme-challenge/${challenge.token}`
            self.setChallenge(path, null)
          } else {
            throw new Error('unknown challenge type', challenge.type)
          }
        }
        var cert = await client.auto({
          csr,
          email: self.email,
          termsOfServiceAgreed: true,
          challengeCreateFn,
          challengeRemoveFn
        })
        var credential = {
          key: key.toString(),
          cert: cert.toString(),
          date: new Date().getTime(),
        }
        return new Promise((res, rej) => {
          self.setCredential(name, credential, err => {
            if (err) return rej(err)
            res(credential)
          })
        })
      }
      go().then(credential => {
        cb(null, credential)
      }).catch(cb)
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
