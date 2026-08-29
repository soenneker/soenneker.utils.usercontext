[![](https://img.shields.io/nuget/v/Soenneker.Utils.UserContext.svg?style=for-the-badge)](https://www.nuget.org/packages/Soenneker.Utils.UserContext/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.utils.usercontext/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.utils.usercontext/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/Soenneker.Utils.UserContext.svg?style=for-the-badge)](https://www.nuget.org/packages/Soenneker.Utils.UserContext/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.utils.usercontext/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.utils.usercontext/actions/workflows/codeql.yml)

# ![](https://user-images.githubusercontent.com/4441470/224455560-91ed3ee7-f510-4041-a8d2-3fc093025112.png) Soenneker.Utils.UserContext
A utility library for retrieving various user information from the request context.

## Installation

```bash
dotnet add package Soenneker.Utils.UserContext
```

## Quick start

```csharp
using Soenneker.Utils.UserContext.Registrars;

services.AddUserContextAsScoped();
```

Then inject `IUserContext` wherever you need it.

## Common operations

- `SetInternalContext()` - Sets an internal context for system or service use.
- `SetApiKey()` - Sets an API key override for the current context instance.
- `GetId()` - Grabs the user id from the current context Throws an auth error if no user id is found.
- `GetIdSafe()` - Grabs the user id from the current context. If it's not found it returns null.
- `GetEmail()` - Retrieves the email address associated with the current instance. Returns a string containing the email address. The value may be empty if no email address is set.
- `GetJwt()` - Grabs the JWT from the current context Throws an auth error if not found.
- `GetApiKey()` - Grabs the header from the current request's context Returns null if the key is not present.
- `HasRoles()` - Determines whether the current principal is assigned any of the specified roles.
- `HasRole()` - Returns whether the current HTTP user's `ClaimsPrincipal` belongs to the requested role; returns `false` when no current user exists.
- `IsAdmin()` - Shorthand for HasUserRole(Admin). Will NOT throw an exception.
- `IsNotAdmin()` - Determines whether the current user does not have administrative privileges.
