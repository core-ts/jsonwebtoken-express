# jsonwebtoken-express

Express middleware for JWT authentication with automatic access token refresh using remember tokens.

Unlike low-level JWT libraries, **jsonwebtoken-express** provides ready-to-use Express middleware that:

- Verifies access tokens
- Supports optional authentication
- Protects authenticated routes
- Automatically refreshes expired access tokens using remember tokens
- Stores authenticated user information in `res.locals`
- Uses secure HTTP-only cookies

## Features

- ✔ Optional authentication middleware
- ✔ Required authentication middleware
- ✔ Automatic access token renewal
- ✔ Remember Me support
- ✔ HTTP-only secure cookies
- ✔ Configurable cookie names
- ✔ Configurable payload field mapping
- ✔ Stores authenticated account in `res.locals`
- ✔ TypeScript support
- ✔ Lightweight with minimal dependencies

---

## Installation

```bash
npm install jsonwebtoken-express
```

---

## Requirements

This library expects:

- Express
- cookie-parser
- jsonwebtoken

```bash
npm install express cookie-parser jsonwebtoken
```

---

## Quick Start

```ts
import express from "express"
import cookieParser from "cookie-parser"
import { TokenVerifier } from "jsonwebtoken-express"

const app = express()

app.use(cookieParser())

app.use(new TokenVerifier(
    "account",
    "userId",
    "id",
    "accessToken",
    "ACCESS_SECRET",
    1000 * 60 * 15,
    "lax",
    "rememberToken",
    "REMEMBER_SECRET"
).verify)
```

---

# Middleware

The library provides two middleware classes.

| Middleware | Authentication Required |
|------------|-------------------------|
| TokenVerifier | No |
| AuthenticationVerifier | Yes |

---

# TokenVerifier

`TokenVerifier` performs optional authentication.

Behavior:

- Valid access token → user is authenticated.
- Expired access token + valid remember token → generates a new access token.
- No tokens → request continues anonymously.
- Invalid tokens → request continues anonymously.

Example:

```ts
app.use(new TokenVerifier(
    "account",
    "userId",
    "id",
    "accessToken",
    process.env.ACCESS_SECRET!,
    1000 * 60 * 15,
    "lax",
    "rememberToken",
    process.env.REMEMBER_SECRET!
).verify)
```

This middleware is useful for:

- Public APIs
- Home pages
- Product pages
- Optional login

---

# AuthenticationVerifier

`AuthenticationVerifier` requires authentication.

Behavior:

- Valid access token → continue.
- Expired access token + valid remember token → automatically issues a new access token.
- Missing tokens → HTTP 401.
- Invalid tokens → HTTP 401.
- Unexpected errors → HTTP 500.

Example:

```ts
app.get(
    "/profile",
    new AuthenticationVerifier(
        "account",
        "userId",
        "id",
        "accessToken",
        process.env.ACCESS_SECRET!,
        1000 * 60 * 15,
        "lax",
        "rememberToken",
        process.env.REMEMBER_SECRET!,
        console.error
    ).verify,
    (req, res) => {
        res.json(res.locals.account)
    }
)
```

---

# Automatic Token Refresh

One of the primary features of this library is automatic access token renewal.

```
Request
      │
      ▼
Access Token
      │
      ├── Valid
      │      │
      │      ▼
      │   Continue
      │
      └── Expired
             │
             ▼
      Remember Token
             │
      ├── Valid
      │      │
      │      ▼
      │ Generate New Access Token
      │      │
      │      ▼
      │ Continue Request
      │
      └── Invalid
             │
             ▼
          401 Unauthorized
```

The user stays logged in without manually signing in again.

---

# res.locals

After successful authentication, the middleware stores the authenticated user inside `res.locals`.

Example:

```ts
res.locals.account
res.locals.userId
```

You can access these values from any subsequent middleware or route handler.

---

# Payload Mapping

Your JWT payload does not have to match the property names used inside Express.

For example:

JWT

```json
{
    "id": 123,
    "email": "john@example.com"
}
```

Middleware

```ts
new AuthenticationVerifier(
    "account",
    "userId",
    "id",
    "accessToken",
    ACCESS_SECRET,
    900000,
    "lax",
    "rememberToken",
    REMEMBER_SECRET,
    console.error,
    "email",
    "email"
)
```

Result:

```ts
res.locals.account
res.locals.userId
res.locals.email
```

---

# Cookie Options

The generated access token is stored as an HTTP-only cookie.

```ts
{
    httpOnly: true,
    secure: true,
    sameSite: "lax"
}
```

The cookie lifetime is determined by the configured expiration time.

---

# Error Responses

AuthenticationVerifier returns standard HTTP responses.

| Status | Description |
|---------|-------------|
| 401 | Missing access token |
| 401 | Invalid remember token |
| 401 | Remember token expired |
| 500 | Unexpected internal error |

---

# API

## TokenVerifier

```ts
new TokenVerifier(
    account,
    userId,
    payloadId,
    accessToken,
    accessSecret,
    expiresIn,
    sameSite,
    rememberToken,
    rememberSecret,
    username?,
    payloadUsername?
)
```

---

## AuthenticationVerifier

```ts
new AuthenticationVerifier(
    account,
    userId,
    payloadId,
    accessToken,
    accessSecret,
    expiresIn,
    sameSite,
    rememberToken,
    rememberSecret,
    log,
    username?,
    payloadUsername?
)
```

---

# Example

```ts
app.get(
    "/me",
    authentication.verify,
    (req, res) => {
        res.json({
            user: res.locals.account
        })
    }
)
```

---

# Use Cases

- REST APIs
- Express applications
- Server-side rendered applications
- Admin dashboards
- Internal business systems
- Authentication middleware
- Cookie-based JWT authentication

---

# License

MIT




# jsonwebtoken-express

Express middleware for JWT authentication with automatic access token renewal.

`jsonwebtoken-express` is a lightweight Express middleware built on top of **Express** and **jsonwebtoken**. It verifies JWT access tokens stored in HTTP cookies, automatically renews expired access tokens using a remember token, and exposes the authenticated account through `res.locals`.

The library is designed primarily for **Server-Side Rendering (SSR)** applications where authentication is performed before rendering pages.

Unlike complete authentication frameworks, `jsonwebtoken-express` intentionally focuses only on the **HTTP layer**. Authentication policies such as password verification, account lockout, password expiration, and two-factor authentication belong to **authen-service** or another authentication domain library.

---

## Features

- 🔐 JWT authentication middleware
- 🍪 Cookie-based authentication
- 🔄 Automatic access token renewal
- 🧠 Remember token support
- 🚀 Designed for Server-Side Rendering (SSR)
- 🔌 Built for Express
- 🛡 Secure cookie defaults
- ⚙️ Configurable cookie names
- ⚙️ Configurable JWT payload fields
- ⚙️ Configurable SameSite policy
- 📝 Stores authenticated account in `res.locals`
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

`jsonwebtoken-express` handles **HTTP authentication**, not **business authentication**.

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

Business authentication should be delegated to libraries such as **authen-service**.

Examples include:

- Username/password verification
- Password expiration
- Account lockout
- Two-factor authentication
- Privilege loading
- Authentication policies

Keeping these responsibilities separate follows the principles of Clean Architecture.

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

---

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
    process.env.ACCESS_SECRET!,
    15 * 60 * 1000,
    "lax",
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

## Automatic Access Token Renewal

When an access token has expired:

1. Verify the remember token.
2. Generate a new access token.
3. Store the new access token in a secure HTTP-only cookie.
4. Continue processing the request.

No additional refresh endpoint is required for SSR applications.

---

## Middleware Result

After successful verification, the middleware stores the authenticated information in `res.locals`.

```typescript
res.locals.account
res.locals.userId
res.locals.username
```

Example:

```typescript
app.get("/me", (req, res) => {
    res.json({
        account: res.locals.account,
        userId: res.locals.userId,
        username: res.locals.username
    });
});
```

---

## Constructor

```typescript
new TokenVerifier(
    account,
    userId,
    payloadId,
    accessToken,
    accessSecret,
    expiresIn,
    sameSite,
    rememberToken,
    rememberSecret,
    username?,
    payloadUsername?
)
```

| Parameter | Description |
|-----------|-------------|
| `account` | Property name used to store the authenticated account in `res.locals` |
| `userId` | Property name used to store the authenticated user ID |
| `payloadId` | JWT payload field containing the user identifier |
| `accessToken` | Access token cookie name |
| `accessSecret` | Secret used to verify access tokens |
| `expiresIn` | Lifetime of newly generated access tokens |
| `sameSite` | Cookie SameSite policy (`lax`, `strict`, or `none`) |
| `rememberToken` | Remember token cookie name |
| `rememberSecret` | Secret used to verify remember tokens |
| `username` | Optional property name stored in `res.locals` |
| `payloadUsername` | Username field inside the JWT payload |

---

## Cookie Configuration

New access tokens are stored using secure defaults.

```typescript
{
    httpOnly: true,
    secure: true,
    sameSite: "lax"
}
```

The SameSite policy is configurable through the constructor.

---

## Server-Side Rendering (SSR)

`jsonwebtoken-express` is designed primarily for server-side rendered applications.

Typical request lifecycle:

```
      Browser

         ↓

    HTTP Cookies

         ↓

 Express Middleware

         ↓

  JWT Verification

         ↓

Authenticated Account

         ↓

Server-side Rendering
```

The controller or template always receives the authenticated account through `res.locals`.

---

## Integration with authen-service

`jsonwebtoken-express` works naturally with **authen-service**.

| authen-service | jsonwebtoken-express |
|----------------|----------------------|
| Password authentication | JWT verification |
| Account lockout | Cookie handling |
| Password expiration | Middleware |
| Two-factor authentication | Access token renewal |
| Privilege loading | Populate `res.locals` |
| Authentication policies | Express integration |

Together they provide a clean separation between authentication business logic and HTTP infrastructure.

---

## Security

The middleware provides:

- JWT verification
- HTTP-only cookies
- Secure cookies
- Configurable SameSite policy
- Automatic access token renewal

The library intentionally **does not** implement:

- Username/password authentication
- Account management
- Authorization
- OAuth / OpenID Connect
- Session management
- Refresh token persistence

These responsibilities belong to the application layer or **authen-service**.

---

## Use Cases

`jsonwebtoken-express` is well suited for:

- Express applications
- Server-Side Rendering (SSR)
- Traditional MVC applications
- Cookie-based JWT authentication
- Enterprise web applications
- Applications using **authen-service**

---

## Design Principles

- Separation of concerns
- Clean Architecture
- HTTP adapter pattern
- Dependency inversion
- Cookie-based authentication
- Framework-independent authentication domain
- Minimal API surface

---

## Related Packages

### authen-service

Framework-independent authentication domain library providing:

- Password authentication
- Password expiration
- Account lockout
- Two-factor authentication
- Privilege loading
- Authentication policies

### security-express

Express authorization middleware for protecting authenticated routes.

---

# The Big Picture of core-ts ecosystem
### HTTP / Transport Layer
- [jsonwebtoken-express](https://www.npmjs.com/package/jsonwebtoken-express) — verify JWT cookies, renew access tokens, SSR middleware.
- [authentication-express](https://www.npmjs.com/package/authentication-express) — login, refresh, privilege endpoints for React / Angular / Android / iOS clients.
- [security-express](https://www.npmjs.com/package/security-express) — route authorization and request protection.

### Authentication Domain Layer
- [authen-service](https://www.npmjs.com/package/authen-service) — password verification, lockout, expiry, 2FA, access rules, privilege loading.

### Identity / Account Services
- [signup-service](https://www.npmjs.com/package/signup-service) — user registration workflow.
- [password-service](https://www.npmjs.com/package/password-service) — password change / reset logic.

### Persistence Layer
- [sql-core](https://www.npmjs.com/package/sql-core) + [mysql2-core](https://www.npmjs.com/package/mysql2-core) (from a broader ecosystem).

# Spring ecosystem equivalent
### HTTP / Web Security
- SecurityFilterChain
- JWT / OAuth filters
- Remember-me services

### Authentication Core
- AuthenticationManager
- AuthenticationProvider
- PasswordEncoder
- UserDetailsService

### Identity Management
- Custom registration service.
- Password reset service.

### Persistence
- Spring Data / JDBC / JPA repositories

# Direct Mapping with Java Spring

| core-ts ecosystem          | Spring Equivalent |
|----------------------------|-------------------|
| **authen-service**         | AuthenticationProvider + UserDetailsService + Password Policy |
| **password-service**       | Password Reset / Change Service |
| **signup-service**         | Registration Service |
| **authentication-express** | Login Controller + Token Issuance Endpoint |
| **jsonwebtoken-express**   | JWT Authentication Filter + Remember-Me Filter |
| **security-express**       | Authorization Filter / Access Decision Layer |
---

## The Most Important Difference
Spring Security starts from the web framework and moves inward
``` text
HTTP → Filters → Authentication → Domain
```

Your ecosystem starts from the domain and moves outward.
``` text
Domain → authen-service → Express adapters → HTTP
```

That is a fundamentally different architectural philosophy.

## Feature Coverage Comparison

| Capability | core-ts ecosystem | Spring Security |
|------------|:--------------:|:---------------:|
| Username/password authentication | ✅ | ✅ |
| JWT generation | ✅ | ✅ |
| JWT verification | ✅ | ✅ |
| Cookie authentication | ✅ | ✅ |
| SPA authentication | ✅ | ✅ |
| Mobile authentication | ✅ | ✅ |
| Server-Side Rendering (SSR) | ✅ | ✅ |
| Remember token | ✅ | ✅ |
| Access token renewal | ✅ | ✅ |
| Account lockout | ✅ | Custom |
| Password expiration | ✅ | Custom |
| Password reset | ✅ | Custom |
| User registration | ✅ | Custom |
| Two-factor authentication | ✅ | Custom |
| Privilege hierarchy | ✅ | Partial |
| Role-based authorization | ✅ | ✅ |
| Route authorization | ✅ | ✅ |
| OAuth2 / OpenID Connect | ❌ | ✅ |
| LDAP / Active Directory | ❌ | ✅ |
| SAML | ❌ | ✅ |
| Kerberos | ❌ | ✅ |
| X.509 Authentication | ❌ | ✅ |
| CSRF protection | Express middleware | ✅ |
| Session fixation protection | Express middleware | ✅ |
| Method-level authorization (`@PreAuthorize`) | ❌ | ✅ |
| Framework independence | ✅ (Domain libraries) | ❌ |
| Dependency Injection | ✅ | ✅ |
| Clean Architecture | ✅ | Partial |

---

## License

MIT License.
