# jsonwebtoken-express

Express middleware for JWT authentication with automatic access token renewal.

`jsonwebtoken-express` is built on top of **Express** and **jsonwebtoken** to simplify server-side authentication. It verifies JWT access tokens, automatically renews expired access tokens using a remember token, and exposes the authenticated user through `res.locals`.

Unlike full authentication frameworks, `jsonwebtoken-express` focuses only on the **HTTP layer**. Authentication business logic belongs to libraries such as **authen-service**, while this library is responsible for JWT verification, cookie handling, and Express integration.

---

## Features

- 🔐 JWT authentication middleware
- 🍪 HTTP-only cookie support
- 🔄 Automatic access token renewal
- 🧠 Remember token support
- 🚀 Designed for Server-Side Rendering (SSR)
- 🔌 Built on Express
- 🛡 Secure cookie defaults
- ⚙️ Configurable cookie and payload field names
- 📝 Stores authenticated user in `res.locals`
- 🎯 Lightweight and framework-focused

---

## Installation

```bash
npm install jsonwebtoken-express
```

or

```bash
yarn add jsonwebtoken-express
```

---

## Philosophy

`jsonwebtoken-express` intentionally handles only HTTP concerns.

```
    HTTP Request
         │
         ▼
    JWT Cookie
         │
         ▼
 jsonwebtoken-express
         │
         ▼
  Authenticated User
         │
         ▼
     Controller
```

Authentication policies such as:

- Password verification
- Account lockout
- Password expiration
- Two-factor authentication
- Privilege loading

should be implemented by **authen-service** or another authentication domain library.

---

## Architecture

```
   Express Request
         │
         ▼
 jsonwebtoken-express
   (JWT + Cookies)
         │
         ▼
   authen-service
(Authentication Domain)
         │
         ▼
    Application
         │
         ▼
      Database
```

This separation follows Clean Architecture by keeping transport concerns separate from authentication business logic.

---

## Examples
- [backoffice](https://github.com/content-system/backoffice): A SSR backoffice for a CMS (user, role, audit-log, category, content, job)
- [admin](https://github.com/fintech-product/admin): A SSR backoffice for a common fintech product (user, role, audit-log, currency, country, locale)

## Quick Start

```typescript
import express from "express";
import cookieParser from "cookie-parser";
import { TokenVerifier } from "jsonwebtoken-express";

const app = express();

app.use(cookieParser());

const verifier = new TokenVerifier(
    "account",
    "userId",
    "id",
    "access_token",
    process.env.JWT_SECRET!,
    900,
    "remember_token",
    process.env.REMEMBER_SECRET!
);

app.use(verifier.verify);

app.get("/profile", (req, res) => {
    if (!res.locals.account) {
        return res.status(401).send("Unauthorized");
    }

    res.json(res.locals.account);
});
```

---

## Authentication Flow

```
Request
   │
   ▼
Access Token
   │
   ▼
Valid?
   ├── Yes
   │    │
   │    ▼
   │  User Available
   │
   └── No
       │
       ▼
 Remember Token
       │
       ▼
     Valid?
       ├── No
       │
       │  Continue as Guest
       │
       └── Yes
            │
            ▼
 Generate New Access Token
            │
            ▼
      Update Cookie
            │
            ▼
     Continue Request
```

---

## Automatic Token Renewal

When an access token expires:

1. Verify the remember token.
2. Generate a new access token.
3. Store it in an HTTP-only cookie.
4. Continue processing the request.

No additional middleware is required.

---

## Middleware Result

After successful verification, the middleware populates `res.locals`:

```typescript
res.locals.account
res.locals.userId
res.locals.username
```

Example:

```typescript
app.get("/me", (req, res) => {
    console.log(res.locals.account);
    res.json(res.locals.account);
});
```

---

## Constructor

```typescript
new TokenVerifier(
    account,
    userId,
    payloadId,
    token,
    secret,
    expiresIn,
    remember,
    rememberSecret,
    username?,
    payloadUsername?
)
```

| Parameter | Description |
|-----------|-------------|
| `account` | Property name used to store the authenticated account in `res.locals` |
| `userId` | Property name used to store the authenticated user ID |
| `payloadId` | JWT payload field containing the user ID |
| `token` | Access token cookie name |
| `secret` | Secret used to verify access tokens |
| `expiresIn` | Lifetime of newly generated access tokens |
| `remember` | Remember token cookie name |
| `rememberSecret` | Secret used to verify remember tokens |
| `username` | Optional property name stored in `res.locals` |
| `payloadUsername` | Username field inside the JWT payload |

---

## Secure Cookie Defaults

New access tokens are stored with secure defaults:

```typescript
{
    httpOnly: true,
    secure: true,
    sameSite: "lax"
}
```

These defaults help mitigate XSS attacks while remaining compatible with most web applications.

---

## Server-Side Rendering (SSR)

`jsonwebtoken-express` is primarily designed for **Server-Side Rendering** applications.

Typical request flow:

```
     Browser
        │
        ▼
   HTTP Cookies
        │
        ▼
 Express Middleware
        │
        ▼
 JWT Verification
        │
        ▼
 Authenticated User
        │
        ▼
Server-Side Rendering
```

The server always receives an authenticated user before rendering pages.

---

## Integration with authen-service

`jsonwebtoken-express` complements **authen-service**.

| authen-service | jsonwebtoken-express |
|----------------|----------------------|
| Password verification | JWT verification |
| Account lockout | Cookie handling |
| Password expiration | Middleware |
| Two-factor authentication | Automatic token renewal |
| Privilege loading | Populate `res.locals` |
| Authentication policies | Express integration |

Together they provide a clean separation between business authentication and HTTP infrastructure.

---

## Security

The library provides:

- JWT verification
- HTTP-only cookies
- Secure cookies
- SameSite protection
- Automatic access token renewal

The library intentionally **does not** implement:

- Username/password authentication
- Account management
- OAuth / OpenID Connect
- Authorization
- Refresh token persistence
- Session management

These concerns belong to the authentication domain or application layer.

---

## Use Cases

`jsonwebtoken-express` is ideal for:

- Express applications
- Server-Side Rendering (SSR)
- Traditional MVC applications
- Cookie-based JWT authentication
- Enterprise web applications

---

## Related Packages

### authen-service

A framework-independent authentication domain library providing:

- Password authentication
- Account lockout
- Password expiration
- Two-factor authentication
- Privilege loading
- Authentication policies

### security-express

Express authorization middleware for protecting routes after authentication.

---

## Design Principles

- Separation of concerns
- Clean Architecture
- Framework-independent authentication
- HTTP adapter pattern
- Dependency inversion
- Cookie-based authentication
- Minimal API surface

---

## License

MIT License.