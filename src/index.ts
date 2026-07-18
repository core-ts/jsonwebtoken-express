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
    username?: string,
    payloadUsername?: string,
  ) {
    this.username = username ? username : "username"
    this.payloadUsername = payloadUsername ? payloadUsername : "username"
    this.verify = this.verify.bind(this)
  }

  verify(req: Request, res: Response, next: NextFunction) {
    let accessToken: string | undefined
    if (req.cookies) {
      accessToken = req.cookies[this.accessToken]
    }
    if (!accessToken) {
      next()
    } else {
      verify(accessToken, this.accessSecret, (err: any, decoded: any) => {
        if (err) {
          next()
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
    protected log: (msg: string) => void,
    username?: string,
    payloadUsername?: string,
  ) {
    this.username = username ? username : "username"
    this.payloadUsername = payloadUsername ? payloadUsername : "username"
    this.verify = this.verify.bind(this)
  }

  verify(req: Request, res: Response, next: NextFunction) {
    let accessToken: string | undefined = undefined
    if (req.cookies) {
      accessToken = req.cookies[this.accessToken]
    }
    if (!accessToken) {
      res.status(401).end(`${this.accessToken} is required in cookies`)
    } else {
      verify(accessToken, this.accessSecret, (err: any, decoded: any) => {
        if (err) {
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

export class TokenController {
  constructor(
    protected accessToken: string,
    protected accessSecret: string,
    protected expiresIn: number,
    protected sameSite: "lax" | "strict" | "none",
    protected rememberToken: string,
    protected rememberSecret: string,
    protected log: (msg: string) => void,
  ) {
    this.refresh = this.refresh.bind(this)
  }
  refresh(req: Request, res: Response) {
    let rememberToken: string | undefined = undefined
    if (req.cookies) {
      rememberToken = req.cookies[this.rememberToken]
    }
    if (!rememberToken) {
      res.status(401).end("the remember token does not exist")
    } else {
      verify(rememberToken, this.rememberSecret, (err: any, decoded: any) => {
        if (err) {
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
          removeJWTFields(decoded)
          const newToken = sign(decoded, this.accessSecret, { expiresIn: this.expiresIn })
          res.cookie(this.accessToken, newToken, { httpOnly: true, secure: true, sameSite: this.sameSite, maxAge: this.expiresIn })
          res.status(200).end("refresh token successfully")
        }
      })
    }
  }
}
export const TokenHandler = TokenController

export function toString(v: any): string {
  return typeof v === "string" ? v : JSON.stringify(v)
}
