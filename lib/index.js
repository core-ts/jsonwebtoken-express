"use strict"
Object.defineProperty(exports, "__esModule", { value: true })
var jsonwebtoken_1 = require("jsonwebtoken")
var TokenVerifier = /** @class */ (function () {
  function TokenVerifier(account, userId, payloadId, token, secret, expiresIn, remember, rememberSecret, username, payloadUsername) {
    this.account = account
    this.userId = userId
    this.payloadId = payloadId
    this.token = token
    this.secret = secret
    this.expiresIn = expiresIn
    this.remember = remember
    this.rememberSecret = rememberSecret
    this.username = username ? username : "username"
    this.payloadUsername = payloadUsername ? payloadUsername : "username"
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
            res.locals[_this.userId] = decoded2[_this.payloadId]
            if (decoded2[_this.username]) {
              res.locals[_this.username] = decoded2[_this.payloadUsername]
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
                res.locals[_this.userId] = decoded2[_this.payloadId]
                if (decoded2[_this.username]) {
                  res.locals[_this.username] = decoded2[_this.payloadUsername]
                }
                next()
              }
            })
          }
        } else {
          removeJWTFields(decoded)
          res.locals[_this.account] = decoded
          res.locals[_this.userId] = decoded[_this.payloadId]
          if (decoded[_this.username]) {
            res.locals[_this.username] = decoded[_this.payloadUsername]
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
exports.removeJWTFields = removeJWTFields
