import { NextFunction, Request, Response } from "express"
import { sign, verify } from "jsonwebtoken"

export class TokenVerifier {
  constructor(
    private account: string,
    private token: string,
    private secret: string,
    private expiresIn: number,
    private remember: string,
    private rememberSecret: string,
  ) {
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
            res.locals.userId = decoded2.id
            if (decoded2.username) {
              res.locals.username = decoded2.username
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
                res.locals.userId = decoded2.id
                if (decoded2.username) {
                  res.locals.username = decoded2.username
                }
                next()
              }
            })
          }
        } else {
          res.locals[this.account] = decoded
          res.locals.userId = decoded.id
          if (decoded.username) {
            res.locals.username = decoded.username
          }
          next()
        }
      })
    }
  }
}

function removeJWTFields(obj: any) {
  delete obj.iat
  delete obj.exp
}
