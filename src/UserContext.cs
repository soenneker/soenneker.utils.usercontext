using System;
using System.Net.Http.Headers;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Soenneker.Constants.Auth;
using Soenneker.Exceptions.Suite;
using Soenneker.Utils.UserContext.Abstract;
using Soenneker.Extensions.String;

namespace Soenneker.Utils.UserContext;

///<inheritdoc cref="IUserContext"/>
public class UserContext : IUserContext
{
    public IHttpContextAccessor HttpContextAccessor { get; set; }

    private readonly ILogger _logger;

    private string? _cachedUserId;
    private string? _cachedUserEmail;
    private string? _cachedJwt;
    private string? _cachedApiKey;
    private bool? _cachedIsAdmin;

    private const string _idClaim = "http://schemas.microsoft.com/identity/claims/objectidentifier";
    private const string _emailClaim = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";

    public UserContext(IHttpContextAccessor httpContextAccessor, ILogger<UserContext> logger)
    {
        HttpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    public UserContext(IHttpContextAccessor httpContextAccessor, ILogger logger)
    {
        HttpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    /// <summary>
    /// Sets an internal context for system or service use.
    /// </summary>
    public void SetInternalContext(string domain)
    {
        _cachedUserId = Guid.Empty.ToString();
        _cachedUserEmail = $"internal@{domain}";
        _cachedIsAdmin = true;
    }

    /// <summary>
    /// Sets an API key override for the current context instance.
    /// This does not modify the underlying HTTP request headers.
    /// </summary>
    public void SetApiKey(string apiKey)
    {
        if (apiKey.IsNullOrWhiteSpace())
            throw new ArgumentException("API key cannot be null or whitespace.", nameof(apiKey));

        _cachedApiKey = apiKey;
    }

    public string GetId()
    {
        if (_cachedUserId != null)
            return _cachedUserId;

        HttpContext? httpContext = HttpContextAccessor.HttpContext;
        ClaimsPrincipal? user = httpContext?.User;

        if (user == null)
        {
            _logger.LogWarning("HttpContext or User is null in GetId.");
            throw new UnauthorizedException();
        }

        Claim? claim = user.FindFirst(_idClaim);

        if (claim == null || claim.Value.IsNullOrEmpty())
        {
            _logger.LogWarning("User claim for object identifier is missing in GetId.");
            throw new UnauthorizedException();
        }

        _cachedUserId = claim.Value;
        return _cachedUserId;
    }

    public string? GetIdSafe()
    {
        if (_cachedUserId != null)
            return _cachedUserId;

        HttpContext? httpContext = HttpContextAccessor.HttpContext;
        ClaimsPrincipal? user = httpContext?.User;

        Claim? claim = user?.FindFirst(_idClaim);

        if (claim == null || claim.Value.IsNullOrEmpty())
            return null;

        _cachedUserId = claim.Value;
        return _cachedUserId;
    }

    public string GetEmail()
    {
        if (_cachedUserEmail != null)
            return _cachedUserEmail;

        HttpContext? httpContext = HttpContextAccessor.HttpContext;
        ClaimsPrincipal? user = httpContext?.User;

        if (user == null)
        {
            _logger.LogWarning("HttpContext or User is null in GetEmail.");
            throw new UnauthorizedException();
        }

        Claim? claim = user.FindFirst(_emailClaim);

        if (claim == null || claim.Value.IsNullOrEmpty())
        {
            claim = user.FindFirst("emails");

            if (claim == null || claim.Value.IsNullOrEmpty())
            {
                _logger.LogWarning("User claim for emails is missing in GetEmail.");
                throw new UnauthorizedException();
            }
        }

        _cachedUserEmail = claim.Value;
        return _cachedUserEmail;
    }

    public string GetJwt()
    {
        if (_cachedJwt != null)
            return _cachedJwt;

        HttpContext? httpContext = HttpContextAccessor.HttpContext;
        if (httpContext == null)
        {
            _logger.LogWarning("HttpContext is null in GetJwt.");
            throw new UnauthorizedException();
        }

        if (!httpContext.Request.Headers.TryGetValue("Authorization", out StringValues authHeader) || authHeader.Count == 0)
        {
            _logger.LogWarning("Authorization header is missing or empty in GetJwt.");
            throw new UnauthorizedException();
        }

        string? headerValueString = authHeader[0];

        if (AuthenticationHeaderValue.TryParse(headerValueString, out AuthenticationHeaderValue? headerValue) &&
            !headerValue.Parameter.IsNullOrEmpty())
        {
            _cachedJwt = headerValue.Parameter;
            return _cachedJwt;
        }

        _logger.LogWarning("Failed to parse JWT from Authorization header in GetJwt.");
        throw new UnauthorizedException();
    }

    public string? GetApiKey()
    {
        if (_cachedApiKey != null)
            return _cachedApiKey;

        HttpContext? httpContext = HttpContextAccessor.HttpContext;
        if (httpContext == null)
            return null;

        if (httpContext.Request.Headers.TryGetValue(AuthConstants.XApiKey, out StringValues apiKey) && apiKey.Count > 0)
        {
            _cachedApiKey = apiKey[0];
            return _cachedApiKey;
        }

        return null;
    }

    public bool HasRoles(params string[] roles)
    {
        ClaimsPrincipal? user = HttpContextAccessor.HttpContext?.User;

        if (user == null)
            return false;

        for (var i = 0; i < roles.Length; i++)
        {
            if (!user.IsInRole(roles[i]))
                return false;
        }

        return true;
    }

    public bool HasRole(string role)
    {
        ClaimsPrincipal? user = HttpContextAccessor.HttpContext?.User;

        if (user == null)
            return false;

        return user.IsInRole(role);
    }

    public bool IsAdmin()
    {
        if (_cachedIsAdmin.HasValue)
            return _cachedIsAdmin.Value;

        _cachedIsAdmin = HasRoles("Admin");
        return _cachedIsAdmin.Value;
    }

    public bool IsNotAdmin() => !IsAdmin();
}