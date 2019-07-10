using log4net;
using System;
using System.IdentityModel.Services;
using System.Net;
using System.Reflection;
using System.Security.Principal;
using System.Web;

namespace Morty.Security
{
    public class FederationAuthenticationModule : WSFederationAuthenticationModule
    {
        private readonly ILog log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);

        protected override void OnAuthorizationFailed(AuthorizationFailedEventArgs e)
        {
            base.OnAuthorizationFailed(e);
        }

        protected override void OnEndRequest(object sender, EventArgs args)
        {
            HttpApplication httpApplication = (HttpApplication)sender;

            log.Info($"WSFederation -> {Test_ShouldUseFederationAuthenticationBasedOn10secondWindow}");
            if (false)
            {
                log.Info($"WSFederation -> Module logic is executed");
                if (CheckIfWindowAuthenticationDetailsExist(httpApplication))
                {
                    log.Info($"WSFederation -> Clearing windows credentials");
                 //   ClearWSFederationAuthenticationDetails();
                   // ClearWindowsIntegratedAuthenticationDetails(httpApplication);
                    return;
                }
                log.Info($"WSFederation -> Serving request with base code");
                base.OnEndRequest(sender, args);
            }
            else
            {
                log.Info($"WSFederation -> Module logic is bypassed");
                /* 
                 * If base.OnEndRequest isnt executed this will cause pipeline to 
                 * pass authentication to the next configured module
                 */
                if (CheckIfWSFederationAuthenticationDetailsExist())
                {
                    log.Info($"WSFederation -> Clearing WSFederation credentials for windows module which should be executed next");
                  //  ClearWSFederationAuthenticationDetails();
                 //   ClearWindowsIntegratedAuthenticationDetails(httpApplication);
                }
            }
        }

        private bool CheckIfWSFederationAuthenticationDetailsExist()
        {
            return FederatedAuthentication.SessionAuthenticationModule.ContextSessionSecurityToken != null &&
                   FederatedAuthentication.SessionAuthenticationModule.ContextSessionSecurityToken.ClaimsPrincipal.Identity.IsAuthenticated;
        }

        private bool CheckIfWindowAuthenticationDetailsExist(HttpApplication httpApplication)
        {
            return httpApplication.Request.RequestContext.HttpContext.User is WindowsPrincipal &&
                   httpApplication.Request.RequestContext.HttpContext.User.Identity.IsAuthenticated;
        }

        private void ClearWSFederationAuthenticationDetails()
        {
            FederatedAuthentication.WSFederationAuthenticationModule.SignOut();
            //FederatedAuthentication.SessionAuthenticationModule.SignOut();
        }

        private void ClearWindowsIntegratedAuthenticationDetails(HttpApplication httpApplication)
        {
            httpApplication.Request.RequestContext.HttpContext.User = null;
            if (httpApplication.Request.RequestContext.HttpContext.Request.Cookies[".AspNet.Cookies"] != null)
            {
                httpApplication.Request.RequestContext.HttpContext.Request.Cookies[".AspNet.Cookies"].Value = string.Empty;
                httpApplication.Request.RequestContext.HttpContext.Request.Cookies[".AspNet.Cookies"].Expires = DateTime.Now.AddMonths(-20);
            }

            httpApplication.Response.AppendHeader("Connection", "close");
            httpApplication.Response.StatusCode = 403;
            httpApplication.Response.Clear();
            httpApplication.Response.Write("Unauthorized. Reload the page to try again...");
            httpApplication.Response.End();
        }

        /// <summary>
        /// Accessor for custom logic that steering authentication between ADFS and WindowsIntegrated
        /// </summary>
        private bool ShouldUseFederationAuthentication
        {
            get { return true; }
        }

        /// <summary>
        /// Dummy switch for testing purposes - with this, authentication method will switch every 10 seconds
        /// </summary>
        private bool Test_ShouldUseFederationAuthenticationBasedOn10secondWindow
        {
            get
            {
                var first10secOfMinute = DateTime.Now.Second >= 0 && DateTime.Now.Second <= 10;
                var third10secOfMinute = DateTime.Now.Second > 20 && DateTime.Now.Second <= 30;
                var fifth10secOfMinute = DateTime.Now.Second > 50 && DateTime.Now.Second <= 60;

                return first10secOfMinute || third10secOfMinute || fifth10secOfMinute;
            }
        }
    }
}
