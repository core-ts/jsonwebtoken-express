import { NextFunction, Request, Response } from "express"
import { sign, verify } from "jsonwebtoken"

export class TokenVerifier {
  protected username: string
  protected payloadUsername: string
  constructor(
    protected account: string,
    protected userId: string,
    protected payloadId: string,
    protected token: string,
    protected secret: string,
    protected expiresIn: number,
    protected remember: string,
    protected rememberSecret: string,
    username?: string,
    payloadUsername?: string,
  ) {
    this.username = username ? username : "username"
    this.payloadUsername = payloadUsername ? payloadUsername : "username"
    this.verify = this.verify.bind(this)
  }

  verify(req: Request, res: Response, next: NextFunction) {
    let token: string | undefined
    let remember: string | undefined
    if (req.cookies) {
      token = req.cookies[this.token]
      remember = req.cookies[this.remember]
    }
    if (!token) {
      if (!remember) {
        next()
      } else {
        verify(remember, this.rememberSecret, (err2: any, decoded2: any) => {
          if (err2) {
            next()
          } else {
            removeJWTFields(decoded2)
            const newToken = sign(decoded2, this.secret, { expiresIn: this.expiresIn })
            res.cookie(this.token, newToken, { httpOnly: true, secure: true, sameSite: "lax", maxAge: this.expiresIn })
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
      verify(token, this.secret, (err: any, decoded: any) => {
        if (err) {
          if (!remember) {
            next()
          } else {
            verify(remember, this.rememberSecret, (err2: any, decoded2: any) => {
              if (err2) {
                next()
              } else {
                removeJWTFields(decoded2)
                const newToken = sign(decoded2, this.secret, { expiresIn: this.expiresIn })
                res.cookie(this.token, newToken, { httpOnly: true, secure: true, sameSite: "lax", maxAge: this.expiresIn })
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
