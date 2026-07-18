import { NextFunction, Request, Response } from "express"
import { JsonWebTokenError, sign, TokenExpiredError, verify } from "jsonwebtoken"

export class TokenVerifier {
  protected username: string
  protected payloadUsername: string
  constructor(
      protected account: string,
      protected userId: string,
      protected payloadId: string,
      protected accessToken: string,
      protected accessSecret: string,
      protected expiresIn: number,
      protected sameSite: "lax" | "strict" | "none",
      protected rememberToken: string,
      protected rememberSecret: string,
      username?: string,
      payloadUsername?: string,
  ) {
    this.username = username ? username : "username"
    this.payloadUsername = payloadUsername ? payloadUsername : "username"
    this.verify = this.verify.bind(this)
  }

  verify(req: Request, res: Response, next: NextFunction) {
    let accessToken: string | undefined
    let rememberToken: string | undefined
    if (req.cookies) {
      accessToken = req.cookies[this.accessToken]
      rememberToken = req.cookies[this.rememberToken]
    }
    if (!accessToken) {
      if (!rememberToken) {
        next()
      } else {
        verify(rememberToken, this.rememberSecret, (err2: any, decoded2: any) => {
          if (err2) {
            next()
          } else {
            removeJWTFields(decoded2)
            const newToken = sign(decoded2, this.accessSecret, { expiresIn: this.expiresIn })
            res.cookie(this.accessToken, newToken, { httpOnly: true, secure: true, sameSite: this.sameSite, maxAge: this.expiresIn })
            res.locals[this.account] = decoded2
            res.locals[this.userId] = decoded2[this.payloadId]
            if (decoded2[this.username]) {
              res.locals[this.username] = decoded2[this.payloadUsername]
            }
            next()
          }
        })
      }
    } else {
      verify(accessToken, this.accessSecret, (err: any, decoded: any) => {
        if (err) {
          if (!rememberToken) {
            next()
          } else {
            verify(rememberToken, this.rememberSecret, (err2: any, decoded2: any) => {
              if (err2) {
                next()
              } else {
                removeJWTFields(decoded2)
                const newToken = sign(decoded2, this.accessSecret, { expiresIn: this.expiresIn })
                res.cookie(this.accessToken, newToken, { httpOnly: true, secure: true, sameSite: this.sameSite, maxAge: this.expiresIn })
                res.locals[this.account] = decoded2
                res.locals[this.userId] = decoded2[this.payloadId]
                if (decoded2[this.username]) {
                  res.locals[this.username] = decoded2[this.payloadUsername]
                }
                next()
              }
            })
          }
        } else {
          removeJWTFields(decoded)
          res.locals[this.account] = decoded
          res.locals[this.userId] = decoded[this.payloadId]
          if (decoded[this.username]) {
            res.locals[this.username] = decoded[this.payloadUsername]
          }
          next()
        }
      })
    }
  }
}
export function removeJWTFields(obj: any) {
  delete obj.iat
  delete obj.exp
}

export class AuthenticationVerifier {
  protected username: string
  protected payloadUsername: string
  constructor(
      protected account: string,
      protected userId: string,
      protected payloadId: string,
      protected accessToken: string,
      protected accessSecret: string,
      protected expiresIn: number,
      protected sameSite: "lax" | "strict" | "none",
      protected rememberToken: string,
      protected rememberSecret: string,
      protected log: (msg: string) => void,
      username?: string,
      payloadUsername?: string,
  ) {
    this.username = username ? username : "username"
    this.payloadUsername = payloadUsername ? payloadUsername : "username"
    this.verify = this.verify.bind(this)
  }

  verify(req: Request, res: Response, next: NextFunction) {
    let accessToken: string | undefined
    let rememberToken: string | undefined
    if (req.cookies) {
      accessToken = req.cookies[this.accessToken]
      rememberToken = req.cookies[this.rememberToken]
    }
    if (!accessToken) {
      if (!rememberToken) {
        res.status(401).end(`${this.accessToken} is required in cookies`)
      } else {
        verify(rememberToken, this.rememberSecret, (err2: any, decoded2: any) => {
          if (err2) {
            next()
          } else {
            removeJWTFields(decoded2)
            const newToken = sign(decoded2, this.accessSecret, { expiresIn: this.expiresIn })
            res.cookie(this.accessToken, newToken, { httpOnly: true, secure: true, sameSite: this.sameSite, maxAge: this.expiresIn })
            res.locals[this.account] = decoded2
            res.locals[this.userId] = decoded2[this.payloadId]
            if (decoded2[this.username]) {
              res.locals[this.username] = decoded2[this.payloadUsername]
            }
            next()
          }
        })
      }
    } else {
      verify(accessToken, this.accessSecret, (err: any, decoded: any) => {
        if (err) {
          if (!rememberToken) {
            if (err instanceof TokenExpiredError) {
              res.status(401).end("the remember token is expired")
            } else if (err instanceof JsonWebTokenError) {
              res.status(401).end("invalid remember token")
            } else {
              if (this.log) {
                this.log("Internal Server Error " + toString(err))
              }
              res.status(500).end("Internal Server Error")
            }
          } else {
            verify(rememberToken, this.rememberSecret, (err2: any, decoded2: any) => {
              if (err2) {
                if (err2 instanceof TokenExpiredError) {
                  res.status(401).end(`${this.accessToken} is required in cookies`)
                } else if (err2 instanceof JsonWebTokenError) {
                  res.status(401).end("invalid remember token")
                } else {
                  if (this.log) {
                    this.log("Internal Server Error " + toString(err2))
                  }
                  res.status(500).end("Internal Server Error")
                }
              } else {
                removeJWTFields(decoded2)
                const newToken = sign(decoded2, this.accessSecret, { expiresIn: this.expiresIn })
                res.cookie(this.accessToken, newToken, { httpOnly: true, secure: true, sameSite: this.sameSite, maxAge: this.expiresIn })
                res.locals[this.account] = decoded2
                res.locals[this.userId] = decoded2[this.payloadId]
                if (decoded2[this.username]) {
                  res.locals[this.username] = decoded2[this.payloadUsername]
                }
                next()
              }
            })
          }
        } else {
          removeJWTFields(decoded)
          res.locals[this.account] = decoded
          res.locals[this.userId] = decoded[this.payloadId]
          if (decoded[this.username]) {
            res.locals[this.username] = decoded[this.payloadUsername]
          }
          next()
        }
      })
    }
  }
}

export function toString(v: any): string {
  return typeof v === "string" ? v : JSON.stringify(v)
}
