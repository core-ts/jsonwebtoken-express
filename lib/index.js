"use strict"
Object.defineProperty(exports, "__esModule", { value: true })
var jsonwebtoken_1 = require("jsonwebtoken")
var TokenVerifier = (function () {
  function TokenVerifier(account, token, secret, expiresIn, remember, rememberSecret) {
    this.account = account
    this.token = token
    this.secret = secret
    this.expiresIn = expiresIn
    this.remember = remember
    this.rememberSecret = rememberSecret
    this.verify = this.verify.bind(this)
  }
  TokenVerifier.prototype.verify = function (req, res, next) {
    var _this = this
    var token
    var remember
    if (req.cookies) {
      token = req.cookies[this.token]
      remember = req.cookies[this.remember]
    }
    if (!token) {
      if (!remember) {
        next()
      } else {
        jsonwebtoken_1.verify(remember, this.rememberSecret, function (err2, decoded2) {
          if (err2) {
            next()
          } else {
            removeJWTFields(decoded2)
            var newToken = jsonwebtoken_1.sign(decoded2, _this.secret, { expiresIn: _this.expiresIn })
            res.cookie(_this.token, newToken, { httpOnly: true, secure: true, sameSite: "lax", maxAge: _this.expiresIn })
            res.locals[_this.account] = decoded2
            res.locals.userId = decoded2.id
            if (decoded2.username) {
              res.locals.username = decoded2.username
            }
            next()
          }
        })
      }
    } else {
      jsonwebtoken_1.verify(token, this.secret, function (err, decoded) {
        if (err) {
          if (!remember) {
            next()
          } else {
            jsonwebtoken_1.verify(remember, _this.rememberSecret, function (err2, decoded2) {
              if (err2) {
                next()
              } else {
                removeJWTFields(decoded2)
                var newToken = jsonwebtoken_1.sign(decoded2, _this.secret, { expiresIn: _this.expiresIn })
                res.cookie(_this.token, newToken, { httpOnly: true, secure: true, sameSite: "lax", maxAge: _this.expiresIn })
                res.locals[_this.account] = decoded2
                res.locals.userId = decoded2.id
                if (decoded2.username) {
                  res.locals.username = decoded2.username
                }
                next()
              }
            })
          }
        } else {
          res.locals[_this.account] = decoded
          res.locals.userId = decoded.id
          if (decoded.username) {
            res.locals.username = decoded.username
          }
          next()
        }
      })
    }
  }
  return TokenVerifier
})()
exports.TokenVerifier = TokenVerifier
function removeJWTFields(obj) {
  delete obj.iat
  delete obj.exp
}
