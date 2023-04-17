using System;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;
using Soenneker.Exceptions.Suite;
using Soenneker.Utils.UserContext.Abstract;

namespace Soenneker.Utils.UserContext;

// TODO: Tests
///<inheritdoc cref="IUserContext"/>
public class UserContext : IUserContext
{
    public IHttpContextAccessor HttpContextAccessor { get; set; }

    // These cached values should only last as long as the request
    private string? _cachedUserId;
    private string? _cachedUserEmail;
    private string? _cachedJwt;
    private bool? _cachedIsAdmin;

    public UserContext(IHttpContextAccessor httpContextAccessor)
    {
        HttpContextAccessor = httpContextAccessor;
    }

    public void SetInternalContext(string domain)
    {
        _cachedUserId = Guid.Empty.ToString();
        _cachedUserEmail = $"internal@{domain}";
        _cachedIsAdmin = true;
    }

    public string GetId()
    {
        if (_cachedUserId != null)
            return _cachedUserId;

        Claim? claim = HttpContextAccessor.HttpContext?.User.Claims.FirstOrDefault(c => c.Type == "http://schemas.microsoft.com/identity/claims/objectidentifier");

        if (claim?.Value == null)
            throw new UnauthorizedException();

        _cachedUserId = claim.Value;

        return _cachedUserId;
    }

    public string? GetIdSafe()
    {
        if (_cachedUserId != null)
            return _cachedUserId;

        Claim? claim = HttpContextAccessor.HttpContext?.User.Claims.FirstOrDefault(c => c.Type == "http://schemas.microsoft.com/identity/claims/objectidentifier");

        if (claim?.Value == null)
            return null;

        _cachedUserId = claim.Value;

        return _cachedUserId;
    }

    public string GetEmail()
    {
        if (_cachedUserEmail != null)
            return _cachedUserEmail;

        // TODO: pretty sure this can return multiple
        Claim? claim = HttpContextAccessor.HttpContext?.User.Claims.FirstOrDefault(c => c.Type == "emails");

        if (claim?.Value == null)
            throw new UnauthorizedException();

        _cachedUserEmail = claim.Value;

        return _cachedUserEmail;
    }

    public string GetJwt()
    {
        if (_cachedJwt != null)
            return _cachedJwt;

        IHeaderDictionary? headers = HttpContextAccessor.HttpContext?.Request.Headers;

        if (headers == null)
            throw new UnauthorizedException();

        // TODO: We need to account for multiple values here
        if (!headers.TryGetValue(HeaderNames.Authorization, out StringValues authHeader))
            throw new UnauthorizedException();

        if (AuthenticationHeaderValue.TryParse(authHeader.ToString(), out AuthenticationHeaderValue? headerValue))
        {
            _cachedJwt = headerValue.Parameter;
            return _cachedJwt!;
        }

        throw new UnauthorizedException();
    }

    public string? GetApiKey()
    {
        if (HttpContextAccessor.HttpContext == null)
            return null;

        bool exists = HttpContextAccessor.HttpContext.Request.Headers.TryGetValue("x-api-key", out StringValues key);

        if (exists)
            return key.ToString();

        return null;
    }

    public bool HasRoles(params string[] roles)
    {
        HttpContext? context = HttpContextAccessor.HttpContext;

        if (context == null)
            return false;

        bool isInAllRoles = roles.All(role => context.User.IsInRole(role));

        return isInAllRoles;
    }

    public bool IsAdmin()
    {
        if (_cachedIsAdmin != null)
            return _cachedIsAdmin.Value;

        _cachedIsAdmin = HasRoles("Admin");

        return _cachedIsAdmin.Value;
    }

    public bool IsNotAdmin()
    {
        return !IsAdmin();
    }
}