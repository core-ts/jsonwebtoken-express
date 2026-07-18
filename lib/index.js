import { JsonWebTokenError, sign, TokenExpiredError, verify } from "jsonwebtoken";
export class TokenVerifier {
  constructor(account, userId, payloadId, accessToken, accessSecret, username, payloadUsername) {
    this.account = account;
    this.userId = userId;
    this.payloadId = payloadId;
    this.accessToken = accessToken;
    this.accessSecret = accessSecret;
    this.username = username ? username : "username";
    this.payloadUsername = payloadUsername ? payloadUsername : "username";
    this.verify = this.verify.bind(this);
  }
  verify(req, res, next) {
    let accessToken;
    if (req.cookies) {
      accessToken = req.cookies[this.accessToken];
    }
    if (!accessToken) {
      next();
    }
    else {
      verify(accessToken, this.accessSecret, (err, decoded) => {
        if (err) {
          next();
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
  constructor(account, userId, payloadId, accessToken, accessSecret, log, username, payloadUsername) {
    this.account = account;
    this.userId = userId;
    this.payloadId = payloadId;
    this.accessToken = accessToken;
    this.accessSecret = accessSecret;
    this.log = log;
    this.username = username ? username : "username";
    this.payloadUsername = payloadUsername ? payloadUsername : "username";
    this.verify = this.verify.bind(this);
  }
  verify(req, res, next) {
    let accessToken = undefined;
    if (req.cookies) {
      accessToken = req.cookies[this.accessToken];
    }
    if (!accessToken) {
      res.status(401).end(`${this.accessToken} is required in cookies`);
    }
    else {
      verify(accessToken, this.accessSecret, (err, decoded) => {
        if (err) {
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
export class TokenController {
  constructor(accessToken, accessSecret, expiresIn, sameSite, rememberToken, rememberSecret, log) {
    this.accessToken = accessToken;
    this.accessSecret = accessSecret;
    this.expiresIn = expiresIn;
    this.sameSite = sameSite;
    this.rememberToken = rememberToken;
    this.rememberSecret = rememberSecret;
    this.log = log;
    this.refresh = this.refresh.bind(this);
  }
  refresh(req, res) {
    let rememberToken = undefined;
    if (req.cookies) {
      rememberToken = req.cookies[this.rememberToken];
    }
    if (!rememberToken) {
      res.status(401).end("the remember token does not exist");
    }
    else {
      verify(rememberToken, this.rememberSecret, (err, decoded) => {
        if (err) {
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
          removeJWTFields(decoded);
          const newToken = sign(decoded, this.accessSecret, { expiresIn: this.expiresIn });
          res.cookie(this.accessToken, newToken, { httpOnly: true, secure: true, sameSite: this.sameSite, maxAge: this.expiresIn });
          res.status(200).end("refresh token successfully");
        }
      });
    }
  }
}
export const TokenHandler = TokenController;
export function toString(v) {
  return typeof v === "string" ? v : JSON.stringify(v);
}
