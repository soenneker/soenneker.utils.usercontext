using Soenneker.Utils.UserContext.Abstract;
using Soenneker.Tests.FixturedUnit;
using Xunit;

namespace Soenneker.Utils.UserContext.Tests;

[Collection("Collection")]
public class UserContextTests : FixturedUnitTest
{
    private readonly IUserContext _util;

    public UserContextTests(Fixture fixture, ITestOutputHelper output) : base(fixture, output)
    {
        _util = Resolve<IUserContext>(true);
    }

    [Fact]
    public void Default()
    {

    }
}
