using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace Morty.Security
{
    public class SessionAuthenticationModule : System.IdentityModel.Services.SessionAuthenticationModule
    {
        protected override void InitializeModule(HttpApplication context)
        {
            base.InitializeModule(context);
        }

        protected override void InitializePropertiesFromConfiguration()
        {
            base.InitializePropertiesFromConfiguration();
        }

        protected override void OnAuthenticateRequest(object sender, EventArgs eventArgs)
        {
            base.OnAuthenticateRequest(sender, eventArgs);
            return;


            HttpApplication httpApplication = (HttpApplication)sender;


            IIdentity identity = Thread.CurrentPrincipal.Identity;

            // in case of federative authentication (URL not in exclusions)
            // if user is authenticated, but it is not federative authentication, reset authentication
            if (identity.IsAuthenticated || identity.AuthenticationType != "Federation")
            {
                httpApplication.Context.User = null;
            }

            // if user is not authenticated, try to authenticate as usual by FedAuth cookie
            base.OnAuthenticateRequest(sender, eventArgs);
        }
    }
}
