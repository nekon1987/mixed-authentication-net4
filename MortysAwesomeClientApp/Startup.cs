using System;
using System.Threading.Tasks;
using Microsoft.Owin;
using Owin;

namespace MortysAwesomeClientApp
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true;
        }
    }
}
