using System.Diagnostics.Contracts;
using Microsoft.AspNetCore.Http;
using Soenneker.Exceptions.Suite;

namespace Soenneker.Utils.UserContext.Abstract;

/// <summary>
/// Always Scoped IoC. <para/>
/// It's possible no claims exist on the user; like if this is an API call
/// </summary>
public interface IUserContext
{
    /// <summary>
    /// For unit test access
    /// </summary>
    IHttpContextAccessor HttpContextAccessor { get; set; }

    void SetInternalContext(string domain);

    /// <summary>
    /// Grabs the user id from the current context
    /// Throws an auth error if no user id is found
    /// </summary>
    /// <exception cref="UnauthorizedException"></exception>
    [Pure]
    string GetId();

    /// <summary>
    /// Grabs the user id from the current context. If it's not found it returns null.
    /// </summary>
    [Pure]
    string? GetIdSafe();

    [Pure]
    string GetEmail();

    /// <summary>
    /// Grabs the JWT from the current context
    /// Throws an auth error if not found
    /// </summary>
    /// <exception cref="UnauthorizedException"></exception>
    [Pure]
    string GetJwt();

    [Pure]
    bool HasRoles(params string[] roles);

    /// <summary>
    /// Shorthand for HasUserRole(Admin). Will NOT throw an exception.
    /// </summary>
    [Pure]
    bool IsAdmin();

    [Pure]
    bool IsNotAdmin();

    /// <summary>
    /// Grabs the header from the current request's context
    /// </summary>
    /// <returns>null if the key is not present</returns>
    [Pure]
    string? GetApiKey();
}