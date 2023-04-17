using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Soenneker.Utils.UserContext.Abstract;

namespace Soenneker.Utils.UserContext.Registrars;

/// <summary>
/// A utility library for retrieving various user information from the request context
/// </summary>
public static class UserContextRegistrar
{
    /// <summary>
    /// As Scoped
    /// </summary>
    public static void AddUserContext(this IServiceCollection services)
    {
        services.TryAddScoped<IUserContext, UserContext>();
    }
}
