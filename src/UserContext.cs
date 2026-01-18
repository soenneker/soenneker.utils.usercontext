using System;
using System.Net.Http.Headers;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Soenneker.Constants.Auth;
using Soenneker.Exceptions.Suite;
using Soenneker.Extensions.String;
using Soenneker.Utils.UserContext.Abstract;

namespace Soenneker.Utils.UserContext;

///<inheritdoc cref="IUserContext"/>
public sealed class UserContext : IUserContext
{
    public IHttpContextAccessor HttpContextAccessor { get; set; }

    private readonly ILogger _logger;

    private string? _cachedUserId;
    private string? _cachedUserEmail;
    private string? _cachedJwt;
    private bool? _cachedIsAdmin;

    // Cache "missing" states too, so we don't keep re-walking claims/headers.
    private bool _idResolved;
    private bool _emailResolved;
    private bool _jwtResolved;

    private static readonly string IdClaim = "http://schemas.microsoft.com/identity/claims/objectidentifier";
    private static readonly string EmailClaim = ClaimTypes.Email; // "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
    private const string EmailsFallbackClaim = "emails";

    private const string AuthorizationHeaderName = "Authorization";
    private const string BearerPrefix = "Bearer ";

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
        // 36-char guid string allocation is fine here; it's not hot.
        _cachedUserId = Guid.Empty.ToString();
        _cachedUserEmail = $"internal@{domain}";
        _cachedIsAdmin = true;

        _idResolved = true;
        _emailResolved = true;
    }

    public string GetId()
    {
        string? id = GetIdSafe();

        if (id.HasContent())
            return id!;

        _logger.LogWarning("User claim for object identifier is missing in GetId.");
        throw new UnauthorizedException();
    }

    public string? GetIdSafe()
    {
        if (_idResolved)
            return _cachedUserId;

        _idResolved = true;

        ClaimsPrincipal? user = HttpContextAccessor.HttpContext?.User;
        Claim? claim = user?.FindFirst(IdClaim);

        if (claim == null || claim.Value.IsNullOrEmpty())
            return null;

        _cachedUserId = claim.Value;
        return _cachedUserId;
    }

    public string GetEmail()
    {
        string? email = GetEmailSafe();

        if (email.HasContent())
            return email!;

        _logger.LogWarning("User claim for email is missing in GetEmail.");
        throw new UnauthorizedException();
    }

    public string? GetEmailSafe()
    {
        if (_emailResolved)
            return _cachedUserEmail;

        _emailResolved = true;

        ClaimsPrincipal? user = HttpContextAccessor.HttpContext?.User;

        if (user == null)
            return null;

        Claim? claim = user.FindFirst(EmailClaim);

        if (claim == null || claim.Value.IsNullOrEmpty())
        {
            // Backwards compat: "emails"
            claim = user.FindFirst(EmailsFallbackClaim);

            if (claim == null || claim.Value.IsNullOrEmpty())
                return null;
        }

        _cachedUserEmail = claim.Value;
        return _cachedUserEmail;
    }

    public string GetJwt()
    {
        string? jwt = GetJwtSafe();

        if (jwt.HasContent())
            return jwt!;

        _logger.LogWarning("Authorization header is missing/invalid in GetJwt.");
        throw new UnauthorizedException();
    }

    public string? GetJwtSafe()
    {
        if (_jwtResolved)
            return _cachedJwt;

        _jwtResolved = true;

        HttpContext? httpContext = HttpContextAccessor.HttpContext;
        if (httpContext == null)
            return null;

        if (!httpContext.Request.Headers.TryGetValue(AuthorizationHeaderName, out StringValues authHeader) || authHeader.Count == 0)
            return null;

        string? headerValue = authHeader[0];

        if (headerValue.IsNullOrEmpty())
            return null;

        // Fast path: "Bearer <token>" without AuthenticationHeaderValue allocations
        if (headerValue.StartsWith(BearerPrefix, StringComparison.OrdinalIgnoreCase))
        {
            // Slice after "Bearer "
            string token = headerValue.Substring(BearerPrefix.Length);

            if (!token.IsNullOrEmpty())
            {
                _cachedJwt = token;
                return _cachedJwt;
            }

            return null;
        }

        // Fallback: keep old behavior for non-bearer formats (rare)
        if (AuthenticationHeaderValue.TryParse(headerValue, out AuthenticationHeaderValue? parsed) &&
            !parsed.Parameter.IsNullOrEmpty())
        {
            _cachedJwt = parsed.Parameter;
            return _cachedJwt;
        }

        return null;
    }

    public string? GetApiKey()
    {
        HttpContext? httpContext = HttpContextAccessor.HttpContext;

        if (httpContext == null)
            return null;

        if (httpContext.Request.Headers.TryGetValue(AuthConstants.XApiKey, out StringValues apiKey) && apiKey.Count > 0)
            return apiKey[0];

        return null;
    }

    // Overload avoids params array allocation for the common case.
    public bool HasRole(string role)
    {
        ClaimsPrincipal? user = HttpContextAccessor.HttpContext?.User;
        return user != null && user.IsInRole(role);
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

    public bool IsAdmin()
    {
        if (_cachedIsAdmin.HasValue)
            return _cachedIsAdmin.Value;

        // Avoid params allocation here
        _cachedIsAdmin = HasRole("Admin");
        return _cachedIsAdmin.Value;
    }

    public bool IsNotAdmin() => !IsAdmin();
}