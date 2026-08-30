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

    /// <summary>
    /// Sets an internal context for system or service use.
    /// </summary>
    void SetInternalContext(string domain);

    /// <summary>
    /// Grabs the user id from the current context
    /// Throws an auth error if no user id is found
    /// </summary>
    /// <exception cref="UnauthorizedException"></exception>
    /// <returns>Grabs the user id from the current context Throws an auth error if no user id is found.</returns>
    [Pure]
    string GetId();

    /// <summary>
    /// Grabs the user id from the current context. If it's not found it returns null.
    /// </summary>
    /// <returns>Grabs the user id from the current context. If it's not found it returns null.</returns>
    [Pure]
    string? GetIdSafe();

    /// <summary>
    /// Retrieves the email address from the current context.
    /// </summary>
    /// <returns>The non-empty email claim value.</returns>
    /// <exception cref="UnauthorizedException">Thrown when no current user or non-empty email claim is available.</exception>
    [Pure]
    string GetEmail();

    /// <summary>
    /// Grabs the JWT from the current context
    /// Throws an auth error if not found
    /// </summary>
    /// <exception cref="UnauthorizedException"></exception>
    /// <returns>Grabs the JWT from the current context Throws an auth error if not found.</returns>
    [Pure]
    string GetJwt();

    /// <summary>
    /// Determines whether the current authenticated principal belongs to a role.
    /// </summary>
    /// <param name="role">The role name.</param>
    /// <returns>True when the principal has the role.</returns>
    [Pure]
    bool HasRole(string role);

    /// <summary>
    /// Determines whether the current principal is assigned every specified role.
    /// </summary>
    /// <param name="roles">An array of role names to check against the current principal. Each element represents a role to evaluate.
    /// Cannot be null or contain null elements.</param>
    /// <returns><see langword="true"/> if the current principal is in every specified role; otherwise, <see langword="false"/>. An empty role array returns <see langword="true"/> when a current user exists.</returns>
    [Pure]
    bool HasRoles(params string[] roles);

    /// <summary>
    /// Shorthand for HasUserRole(Admin). Will NOT throw an exception.
    /// </summary>
    /// <returns>Shorthand for HasUserRole(Admin). Will NOT throw an exception.</returns>
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

    /// <summary>
    /// Sets an API key override for the current context instance.
    /// </summary>
    /// <param name="apiKey">The API key to use.</param>
    void SetApiKey(string apiKey);
}
