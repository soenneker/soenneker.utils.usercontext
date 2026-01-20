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
public class UserContext : IUserContext
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
    private const string OidClaim = "oid";
    private const string SubjectClaim = "sub";

    private const string AuthorizationHeaderName = "Authorization";

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

        ClaimsPrincipal? user = HttpContextAccessor.HttpContext?.User;

        // If we run before auth middleware (or outside an HTTP request), don't cache "missing".
        // This lets subsequent calls later in the pipeline resolve successfully.
        if (user?.Identity?.IsAuthenticated != true)
            return null;

        Claim? claim =
            user.FindFirst(IdClaim) ??
            user.FindFirst(OidClaim) ??
            user.FindFirst(ClaimTypes.NameIdentifier) ??
            user.FindFirst(SubjectClaim);

        if (claim == null || claim.Value.IsNullOrEmpty())
        {
            // User is authenticated but the identifier claim is genuinely missing; cache the miss.
            _idResolved = true;
            return null;
        }

        _cachedUserId = claim.Value;
        _idResolved = true;
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

        ClaimsPrincipal? user = HttpContextAccessor.HttpContext?.User;

        // if we're not authenticated yet / no context, don't cache a miss.
        if (user?.Identity?.IsAuthenticated != true)
            return null;

        Claim? claim = user.FindFirst(EmailClaim);

        if (claim == null || claim.Value.IsNullOrEmpty())
        {
            claim = user.FindFirst(EmailsFallbackClaim);

            if (claim == null || claim.Value.IsNullOrEmpty())
            {
                // Authenticated, but genuinely missing -> cache miss.
                _emailResolved = true;
                return null;
            }
        }

        _cachedUserEmail = claim.Value;
        _emailResolved = true;
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

        HttpContext? httpContext = HttpContextAccessor.HttpContext;

        // If no context yet, don't cache a miss.
        if (httpContext == null)
            return null;

        if (!httpContext.Request.Headers.TryGetValue(AuthorizationHeaderName, out StringValues authHeader) || authHeader.Count == 0)
            return null; // don't cache a miss

        string? headerValue = authHeader[0];

        if (headerValue.IsNullOrEmpty())
        {
            // Header exists but empty -> cache miss (this is a real miss for this request)
            _jwtResolved = true;
            return null;
        }

        // More tolerant bearer parsing than StartsWith("Bearer ")
        // Handles: "Bearer    token", "bearer token", leading/trailing whitespace.
        ReadOnlySpan<char> s = headerValue.AsSpan().Trim();

        if (s.Length >= 6 && s[..6].Equals("Bearer".AsSpan(), StringComparison.OrdinalIgnoreCase))
        {
            s = s[6..].TrimStart(); // skip scheme, then whitespace

            if (!s.IsEmpty)
            {
                _cachedJwt = new string(s); // allocation, but same as returning substring
                _jwtResolved = true;
                return _cachedJwt;
            }

            _jwtResolved = true;
            return null;
        }

        // Fallback for odd formats
        if (AuthenticationHeaderValue.TryParse(headerValue, out AuthenticationHeaderValue? parsed) &&
            !parsed.Parameter.IsNullOrEmpty())
        {
            _cachedJwt = parsed.Parameter;
            _jwtResolved = true;
            return _cachedJwt;
        }

        // Header present but invalid -> cache miss (real miss for this request)
        _jwtResolved = true;
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