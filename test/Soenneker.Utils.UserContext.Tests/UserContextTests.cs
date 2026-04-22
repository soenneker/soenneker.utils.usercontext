using Soenneker.Utils.UserContext.Abstract;
using Soenneker.Tests.HostedUnit;

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
    public void Default()
    {

    }
}
