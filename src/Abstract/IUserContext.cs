using System.Diagnostics.Contracts;
using Microsoft.AspNetCore.Http;
using Soenneker.Exceptions.Suite;

namespace Soenneker.Utils.UserContext.Abstract;

/// <summary>
/// A utility library for retrieving various user information from the request context <para/>
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

    /// <summary>
    /// Retrieves the email address associated with the current instance.
    /// </summary>
    /// <returns>A string containing the email address. The value may be empty if no email address is set.</returns>
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
    bool HasRole(string role);

    /// <summary>
    /// Determines whether the current principal is assigned any of the specified roles.
    /// </summary>
    /// <param name="roles">An array of role names to check against the current principal. Each element represents a role to evaluate.
    /// Cannot be null or contain null elements.</param>
    /// <returns>true if the current principal is in at least one of the specified roles; otherwise, false.</returns>
    [Pure]
    bool HasRoles(params string[] roles);

    /// <summary>
    /// Shorthand for HasUserRole(Admin). Will NOT throw an exception.
    /// </summary>
    [Pure]
    bool IsAdmin();

    /// <summary>
    /// Determines whether the current user does not have administrative privileges.
    /// </summary>
    /// <returns><see langword="true"/> if the current user is not an administrator; otherwise, <see langword="false"/>.</returns>
    [Pure]
    bool IsNotAdmin();

    /// <summary>
    /// Grabs the header from the current request's context
    /// </summary>
    /// <returns>null if the key is not present</returns>
    [Pure]
    string? GetApiKey();
}