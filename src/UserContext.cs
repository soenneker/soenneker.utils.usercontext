using System;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;
using Soenneker.Constants.Auth;
using Soenneker.Exceptions.Suite;
using Soenneker.Utils.UserContext.Abstract;

namespace Soenneker.Utils.UserContext;

// TODO: Tests
///<inheritdoc cref="IUserContext"/>
public class UserContext : IUserContext
{
    public IHttpContextAccessor HttpContextAccessor { get; set; }

    protected string? CachedUserId { private get; set; }
    protected string? CachedUserEmail { private get; set; }
    protected string? CachedJwt { private get; set; }
    protected bool? CachedIsAdmin { private get; set; }

    public UserContext(IHttpContextAccessor httpContextAccessor)
    {
        HttpContextAccessor = httpContextAccessor;
    }

    public virtual void SetInternalContext(string domain)
    {
        CachedUserId = Guid.Empty.ToString();
        CachedUserEmail = $"internal@{domain}";
        CachedIsAdmin = true;
    }

    public string GetId()
    {
        if (CachedUserId != null)
            return CachedUserId;

        Claim? claim = HttpContextAccessor.HttpContext?.User.Claims.FirstOrDefault(c => c.Type == "http://schemas.microsoft.com/identity/claims/objectidentifier");

        if (claim?.Value == null)
            throw new UnauthorizedException();

        CachedUserId = claim.Value;

        return CachedUserId;
    }

    public string? GetIdSafe()
    {
        if (CachedUserId != null)
            return CachedUserId;

        Claim? claim = HttpContextAccessor.HttpContext?.User.Claims.FirstOrDefault(c => c.Type == "http://schemas.microsoft.com/identity/claims/objectidentifier");

        if (claim?.Value == null)
            return null;

        CachedUserId = claim.Value;

        return CachedUserId;
    }

    public string GetEmail()
    {
        if (CachedUserEmail != null)
            return CachedUserEmail;

        // TODO: pretty sure this can return multiple
        Claim? claim = HttpContextAccessor.HttpContext?.User.Claims.FirstOrDefault(c => c.Type == "emails");

        if (claim?.Value == null)
            throw new UnauthorizedException();

        CachedUserEmail = claim.Value;

        return CachedUserEmail;
    }

    public string GetJwt()
    {
        if (CachedJwt != null)
            return CachedJwt;

        IHeaderDictionary? headers = HttpContextAccessor.HttpContext?.Request.Headers;

        if (headers == null)
            throw new UnauthorizedException();

        // TODO: We need to account for multiple values here
        if (!headers.TryGetValue(HeaderNames.Authorization, out StringValues authHeader))
            throw new UnauthorizedException();

        if (AuthenticationHeaderValue.TryParse(authHeader.ToString(), out AuthenticationHeaderValue? headerValue))
        {
            CachedJwt = headerValue.Parameter;
            return CachedJwt!;
        }

        throw new UnauthorizedException();
    }

    public string? GetApiKey()
    {
        if (HttpContextAccessor.HttpContext == null)
            return null;

        bool exists = HttpContextAccessor.HttpContext.Request.Headers.TryGetValue(AuthConstants.XApiKey, out StringValues key);

        if (exists)
            return key.ToString();

        return null;
    }

    public bool HasRoles(params string[] roles)
    {
        HttpContext? context = HttpContextAccessor.HttpContext;

        if (context == null)
            return false;

        bool isInAllRoles = roles.All(context.User.IsInRole);

        return isInAllRoles;
    }

    public bool IsAdmin()
    {
        if (CachedIsAdmin != null)
            return CachedIsAdmin.Value;

        CachedIsAdmin = HasRoles("Admin");

        return CachedIsAdmin.Value;
    }

    public bool IsNotAdmin()
    {
        return !IsAdmin();
    }
}