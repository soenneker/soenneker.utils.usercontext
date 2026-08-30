[![](https://img.shields.io/nuget/v/Soenneker.Utils.UserContext.svg?style=for-the-badge)](https://www.nuget.org/packages/Soenneker.Utils.UserContext/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.utils.usercontext/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.utils.usercontext/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/Soenneker.Utils.UserContext.svg?style=for-the-badge)](https://www.nuget.org/packages/Soenneker.Utils.UserContext/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.utils.usercontext/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.utils.usercontext/actions/workflows/codeql.yml)

# ![](https://user-images.githubusercontent.com/4441470/224455560-91ed3ee7-f510-4041-a8d2-3fc093025112.png) Soenneker.Utils.UserContext
Scoped access to request identity claims, authorization tokens, API keys, and role checks, with explicit internal-context overrides.

## Installation

```bash
dotnet add package Soenneker.Utils.UserContext
```

## Registration

```csharp
using Soenneker.Utils.UserContext.Registrars;

services.AddUserContextAsScoped();
```

Then inject `IUserContext` wherever you need it.

`IUserContext` is intentionally scoped. It caches resolved values for the lifetime of the scope and assumes one request identity per scope; do not register it as a singleton or reuse a scope across unrelated requests.

## User identity

```csharp
string userId = userContext.GetId();
string? optionalUserId = userContext.GetIdSafe();
string email = userContext.GetEmail();
```

User ID claims are checked in this order:

1. `http://schemas.microsoft.com/identity/claims/objectidentifier`
2. `oid`
3. `ClaimTypes.NameIdentifier`
4. `sub`

`GetId` throws `UnauthorizedException` when no non-empty supported claim is available; `GetIdSafe` returns `null`. `GetEmail` first checks `ClaimTypes.Email`, then the `emails` claim, and throws `UnauthorizedException` when neither contains a value.

Resolved IDs and email addresses are cached. Changing `HttpContextAccessor.HttpContext` afterward does not invalidate them.

## Roles

```csharp
bool canManage = userContext.HasRole("Manager");
bool isBothAdminAndManager = userContext.HasRoles("Admin", "Manager");
bool isAdmin = userContext.IsAdmin();
```

`HasRoles` requires every supplied role; it is not an “any role” check. It returns `false` when there is no current user. With a current user, an empty role array returns `true`. `HasRole` and `HasRoles` delegate matching to the current `ClaimsPrincipal`.

`IsAdmin` checks the `Admin` role once and caches the result. `IsNotAdmin` negates that cached result.

## Authorization token and API key

```csharp
string token = userContext.GetJwt();
string? apiKey = userContext.GetApiKey();
```

`GetJwt` parses the first `Authorization` header value and returns its parameter. It does not require the scheme to be `Bearer`; missing, malformed, or parameterless values throw `UnauthorizedException`. The extracted value is cached without validating the token.

`GetApiKey` reads the `X-Api-Key` header defined by `Soenneker.Constants.Auth`, or returns `null` when unavailable. `SetApiKey` supplies an override for the current context instance; blank overrides throw `ArgumentException`.

## Internal operations

```csharp
userContext.SetInternalContext("service.example");
```

This overrides the cached user ID with `Guid.Empty`, the cached email with `internal@service.example`, and the cached admin result with `true`. It does not create an HTTP principal, add roles, set a JWT, or set an API key, so `HasRole` and `HasRoles` still inspect the request principal.

The internal-context domain is interpolated as supplied and is not validated as a DNS or email domain.
