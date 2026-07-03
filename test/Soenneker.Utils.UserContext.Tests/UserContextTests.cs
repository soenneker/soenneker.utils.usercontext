using Soenneker.Utils.UserContext.Abstract;
using Soenneker.Tests.HostedUnit;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Soenneker.Utils.UserContext.Tests;

[ClassDataSource<Host>(Shared = SharedType.PerTestSession)]
public class UserContextTests : HostedUnitTest
{
    private readonly IUserContext _util;

    public UserContextTests(Host host) : base(host)
    {
        _util = Resolve<IUserContext>(true);
    }

    [Test]
    public async ValueTask GetId_should_read_supported_user_id_claims()
    {
        (string Type, string Value)[] claims =
        [
            ("http://schemas.microsoft.com/identity/claims/objectidentifier", "object-id"),
            ("oid", "oid-id"),
            (ClaimTypes.NameIdentifier, "name-identifier-id"),
            ("sub", "subject-id")
        ];

        foreach ((string type, string value) in claims)
        {
            var userContext = CreateUserContext(new Claim(type, value));

            await Assert.That(userContext.GetId()).IsEqualTo(value);
        }
    }

    [Test]
    public async ValueTask GetIdSafe_should_read_supported_user_id_claims()
    {
        var userContext = CreateUserContext(new Claim("sub", "subject-id"));

        await Assert.That(userContext.GetIdSafe()).IsEqualTo("subject-id");
    }

    private static IUserContext CreateUserContext(params Claim[] claims)
    {
        var httpContext = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(claims, "Test"))
        };

        return new UserContext(new HttpContextAccessor {HttpContext = httpContext}, NullLogger<UserContext>.Instance);
    }
}
