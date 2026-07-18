import { JsonWebTokenError, sign, TokenExpiredError, verify } from "jsonwebtoken";
export class TokenVerifier {
  constructor(account, userId, payloadId, accessToken, accessSecret, expiresIn, sameSite, rememberToken, rememberSecret, username, payloadUsername) {
    this.account = account;
    this.userId = userId;
    this.payloadId = payloadId;
    this.accessToken = accessToken;
    this.accessSecret = accessSecret;
    this.expiresIn = expiresIn;
    this.sameSite = sameSite;
    this.rememberToken = rememberToken;
    this.rememberSecret = rememberSecret;
    this.username = username ? username : "username";
    this.payloadUsername = payloadUsername ? payloadUsername : "username";
    this.verify = this.verify.bind(this);
  }
  verify(req, res, next) {
    let accessToken;
    let rememberToken;
    if (req.cookies) {
      accessToken = req.cookies[this.accessToken];
      rememberToken = req.cookies[this.rememberToken];
    }
    if (!accessToken) {
      if (!rememberToken) {
        next();
      }
      else {
        verify(rememberToken, this.rememberSecret, (err2, decoded2) => {
          if (err2) {
            next();
          }
          else {
            removeJWTFields(decoded2);
            const newToken = sign(decoded2, this.accessSecret, { expiresIn: this.expiresIn });
            res.cookie(this.accessToken, newToken, { httpOnly: true, secure: true, sameSite: this.sameSite, maxAge: this.expiresIn });
            res.locals[this.account] = decoded2;
            res.locals[this.userId] = decoded2[this.payloadId];
            if (decoded2[this.username]) {
              res.locals[this.username] = decoded2[this.payloadUsername];
            }
            next();
          }
        });
      }
    }
    else {
      verify(accessToken, this.accessSecret, (err, decoded) => {
        if (err) {
          if (!rememberToken) {
            next();
          }
          else {
            verify(rememberToken, this.rememberSecret, (err2, decoded2) => {
              if (err2) {
                next();
              }
              else {
                removeJWTFields(decoded2);
                const newToken = sign(decoded2, this.accessSecret, { expiresIn: this.expiresIn });
                res.cookie(this.accessToken, newToken, { httpOnly: true, secure: true, sameSite: this.sameSite, maxAge: this.expiresIn });
                res.locals[this.account] = decoded2;
                res.locals[this.userId] = decoded2[this.payloadId];
                if (decoded2[this.username]) {
                  res.locals[this.username] = decoded2[this.payloadUsername];
                }
                next();
              }
            });
          }
        }
        else {
          removeJWTFields(decoded);
          res.locals[this.account] = decoded;
          res.locals[this.userId] = decoded[this.payloadId];
          if (decoded[this.username]) {
            res.locals[this.username] = decoded[this.payloadUsername];
          }
          next();
        }
      });
    }
  }
}
export function removeJWTFields(obj) {
  delete obj.iat;
  delete obj.exp;
}
export class AuthenticationVerifier {
  constructor(account, userId, payloadId, accessToken, accessSecret, expiresIn, sameSite, rememberToken, rememberSecret, log, username, payloadUsername) {
    this.account = account;
    this.userId = userId;
    this.payloadId = payloadId;
    this.accessToken = accessToken;
    this.accessSecret = accessSecret;
    this.expiresIn = expiresIn;
    this.sameSite = sameSite;
    this.rememberToken = rememberToken;
    this.rememberSecret = rememberSecret;
    this.log = log;
    this.username = username ? username : "username";
    this.payloadUsername = payloadUsername ? payloadUsername : "username";
    this.verify = this.verify.bind(this);
  }
  verify(req, res, next) {
    let accessToken;
    let rememberToken;
    if (req.cookies) {
      accessToken = req.cookies[this.accessToken];
      rememberToken = req.cookies[this.rememberToken];
    }
    if (!accessToken) {
      if (!rememberToken) {
        res.status(401).end(`${this.accessToken} is required in cookies`);
      }
      else {
        verify(rememberToken, this.rememberSecret, (err2, decoded2) => {
          if (err2) {
            next();
          }
          else {
            removeJWTFields(decoded2);
            const newToken = sign(decoded2, this.accessSecret, { expiresIn: this.expiresIn });
            res.cookie(this.accessToken, newToken, { httpOnly: true, secure: true, sameSite: this.sameSite, maxAge: this.expiresIn });
            res.locals[this.account] = decoded2;
            res.locals[this.userId] = decoded2[this.payloadId];
            if (decoded2[this.username]) {
              res.locals[this.username] = decoded2[this.payloadUsername];
            }
            next();
          }
        });
      }
    }
    else {
      verify(accessToken, this.accessSecret, (err, decoded) => {
        if (err) {
          if (!rememberToken) {
            if (err instanceof TokenExpiredError) {
              res.status(401).end("the remember token is expired");
            }
            else if (err instanceof JsonWebTokenError) {
              res.status(401).end("invalid remember token");
            }
            else {
              if (this.log) {
                this.log("Internal Server Error " + toString(err));
              }
              res.status(500).end("Internal Server Error");
            }
          }
          else {
            verify(rememberToken, this.rememberSecret, (err2, decoded2) => {
              if (err2) {
                if (err2 instanceof TokenExpiredError) {
                  res.status(401).end(`${this.accessToken} is required in cookies`);
                }
                else if (err2 instanceof JsonWebTokenError) {
                  res.status(401).end("invalid remember token");
                }
                else {
                  if (this.log) {
                    this.log("Internal Server Error " + toString(err2));
                  }
                  res.status(500).end("Internal Server Error");
                }
              }
              else {
                removeJWTFields(decoded2);
                const newToken = sign(decoded2, this.accessSecret, { expiresIn: this.expiresIn });
                res.cookie(this.accessToken, newToken, { httpOnly: true, secure: true, sameSite: this.sameSite, maxAge: this.expiresIn });
                res.locals[this.account] = decoded2;
                res.locals[this.userId] = decoded2[this.payloadId];
                if (decoded2[this.username]) {
                  res.locals[this.username] = decoded2[this.payloadUsername];
                }
                next();
              }
            });
          }
        }
        else {
          removeJWTFields(decoded);
          res.locals[this.account] = decoded;
          res.locals[this.userId] = decoded[this.payloadId];
          if (decoded[this.username]) {
            res.locals[this.username] = decoded[this.payloadUsername];
          }
          next();
        }
      });
    }
  }
}
export function toString(v) {
  return typeof v === "string" ? v : JSON.stringify(v);
}
