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
    /// Adds user context as scoped.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The result of the operation.</returns>
    public static IServiceCollection AddUserContextAsScoped(this IServiceCollection services)
    {
        services.AddHttpContextAccessor()
                .TryAddScoped<IUserContext, UserContext>();

        return services;
    }
}