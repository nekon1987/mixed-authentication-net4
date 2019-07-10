using log4net;
using Morty.Security.Routing;
using System;
using System.Web;

namespace Morty.Security.AuthenticationModules
{
    public class SessionAuthenticationModule : System.IdentityModel.Services.SessionAuthenticationModule
    {
        private readonly ILog log = LogManager.GetLogger("SessionModule");

        protected override void OnAuthenticateRequest(object sender, EventArgs eventArgs)
        {
            var preferredAuthenticationModule = AuthenticationRoutingService
                .GetPreferredAuthenticationModule(((HttpApplication)sender).Context);

            if (preferredAuthenticationModule == AuthenticationModuleTypes.WSFederation)
            {
                log.Debug("Executing native OnAuthenticateRequest");
                base.OnAuthenticateRequest(sender, eventArgs);
            }
            else
            {
                log.Debug("Bypassing native OnAuthenticateRequest");
            }
        }
    }
}
