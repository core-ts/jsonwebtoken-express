# jsonwebtoken-express

A lightweight Express middleware library for JWT authentication using cookies.

Unlike full authentication frameworks, **jsonwebtoken-express** focuses on one job: verifying JWTs and exposing authenticated users through `res.locals`.

It provides:

- Optional authentication middleware
- Required authentication middleware
- Refresh token endpoint
- Cookie-based JWT authentication
- Fully configurable payload mapping

No Passport. No decorators. No unnecessary abstractions.

---

## Features

- ✅ Cookie-based JWT authentication
- ✅ Optional authentication middleware
- ✅ Required authentication middleware
- ✅ Refresh access token using a remember token
- ✅ Stores authenticated user in `res.locals`
- ✅ Configurable payload field names
- ✅ Minimal dependencies
- ✅ TypeScript support

---

## Installation

```bash
npm install jsonwebtoken-express
```

or

```bash
yarn add authen-express
```

---

## Requirements

This library depends on:

- express
- jsonwebtoken
- cookie-parser

Enable cookie parsing before using the middleware.

```typescript
import express from "express";
import cookieParser from "cookie-parser";

const app = express();

app.use(cookieParser());
```

---

## Optional Authentication

`TokenVerifier` attempts to authenticate the current request.

If the access token does not exist or is invalid, the request continues normally.

```typescript
import { TokenVerifier } from "jsonwebtoken-express";

const verifier = new TokenVerifier(
    "account",
    "userId",
    "id",
    "accessToken",
    process.env.ACCESS_SECRET!
);

app.use(verifier.verify);
```

After successful verification:

```typescript
res.locals.account;
res.locals.userId;
```

If no valid access token exists, the request simply continues without authentication.

---

## Required Authentication

`AuthenticationVerifier` requires a valid access token.

```typescript
import { AuthenticationVerifier } from "jsonwebtoken-express";

const auth = new AuthenticationVerifier(
    "account",
    "userId",
    "id",
    "accessToken",
    process.env.ACCESS_SECRET!,
    console.error
);

app.get("/profile", auth.verify, (req, res) => {
    res.json(res.locals.account);
});
```

Possible responses:

| Status | Description |
|--------|-------------|
| 401 | Access token missing |
| 401 | Access token expired |
| 401 | Invalid access token |
| 500 | Internal verification error |

---

## Refresh Access Token

`TokenController` creates a new access token using a valid remember token.

```typescript
import { TokenController } from "jsonwebtoken-express";

const controller = new TokenController(
    "accessToken",
    process.env.ACCESS_SECRET!,
    3600000,
    "lax",
    "rememberToken",
    process.env.REMEMBER_SECRET!,
    console.error
);

app.post("/refresh", controller.refresh);
```

Refresh workflow:

```text
Remember Token Cookie
          │
          ▼
 Verify JWT
          │
          ▼
 Generate New Access Token
          │
          ▼
 Set Access Token Cookie
          │
          ▼
      HTTP 200
```

---

## Accessing the Authenticated User

After successful authentication:

```typescript
res.locals.account;
res.locals.userId;
```

These values remain available throughout the request lifecycle.

---

## Custom Payload Mapping

Suppose your JWT payload is:

```json
{
  "user_id": 123,
  "email": "john@example.com"
}
```

Configure custom payload field names:

```typescript
const verifier = new TokenVerifier(
    "account",
    "userId",
    "user_id",
    "accessToken",
    process.env.ACCESS_SECRET!,
    "email",
    "email"
);
```

Then:

```typescript
res.locals.account;
res.locals.userId;
res.locals.email;
```

---

## API

### TokenVerifier

Optional authentication middleware.

```typescript
new TokenVerifier(
    account,
    userId,
    payloadId,
    accessToken,
    accessSecret,
    username?,
    payloadUsername?
);
```

| Parameter | Description |
|-----------|-------------|
| account | Key used to store the decoded JWT payload in `res.locals` |
| userId | Key used to store the authenticated user's identifier |
| payloadId | Field name inside the JWT payload containing the user ID |
| accessToken | Cookie name containing the access token |
| accessSecret | Secret used to verify the access token |
| username | *(Optional)* Key used in `res.locals` for the username |
| payloadUsername | *(Optional)* Username field inside the JWT payload |

---

### AuthenticationVerifier

Required authentication middleware.

```typescript
new AuthenticationVerifier(
    account,
    userId,
    payloadId,
    accessToken,
    accessSecret,
    logger,
    username?,
    payloadUsername?
);
```

Parameters are identical to `TokenVerifier`, with an additional logger function.

---

### TokenController

Refresh access tokens.

```typescript
new TokenController(
    accessToken,
    accessSecret,
    expiresIn,
    sameSite,
    rememberToken,
    rememberSecret,
    logger
);
```

| Parameter | Description |
|-----------|-------------|
| accessToken | Access token cookie name |
| accessSecret | Secret used to sign access tokens |
| expiresIn | Access token expiration time |
| sameSite | Cookie SameSite policy (`lax`, `strict`, or `none`) |
| rememberToken | Remember token cookie name |
| rememberSecret | Secret used to verify remember tokens |
| logger | Error logging function |


---

## Dependencies

- express
- jsonwebtoken
 
---

## Design Philosophy

This library intentionally stays small and focused.

It **does not** include:

- User management
- Login controllers
- Database integration
- Passport strategies
- OAuth providers
- Session storage

Instead, it provides lightweight middleware that integrates with any authentication system capable of issuing JWTs.

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
- [jsonwebtoken-express](https://www.npmjs.com/package/jsonwebtoken-express) — verify JWT cookies, token refresh endpoint.
- [authentication-express](https://www.npmjs.com/package/authentication-express) — login, privilege endpoints for React / Angular / Android / iOS clients.
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
| **jsonwebtoken-express**   | JWT Authentication Filter |
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

MIT
