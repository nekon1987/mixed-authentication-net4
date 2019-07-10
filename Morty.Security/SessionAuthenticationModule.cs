using log4net;
using System;
using System.Collections.Generic;
using System.IdentityModel.Services;
using System.Linq;
using System.Reflection;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace Morty.Security
{
    public class SessionAuthenticationModule : System.IdentityModel.Services.SessionAuthenticationModule
    {
        private readonly ILog log = LogManager.GetLogger("SessionModule");
        
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
            HttpApplication httpApplication = (HttpApplication)sender;

            if (Test_ShouldUseFederationAuthenticationBasedOn10secondWindow)
            {
                //if(CheckIfWindowAuthenticationDetailsExist(httpApplication))
                //{
                //    log.Info($"SESSION -> Clearing windows");
                //    ClearWindowsIntegratedAuthenticationDetails(httpApplication);
                //}

                log.Info($"SESSION -> Using");
                base.OnAuthenticateRequest(sender, eventArgs);
                return;
            }
            else
            {
                //if (CheckIfWSFederationAuthenticationDetailsExist())
                //{
                //    log.Info($"SESSION -> Clearing WSFed");
                //    ClearWSFederationAuthenticationDetails();
                //}

                log.Info($"SESSION -> NOT Using");
                return;
            }


            //log.Info("Session Auth");

            //IIdentity identity = Thread.CurrentPrincipal.Identity;

            //// in case of federative authentication (URL not in exclusions)
            //// if user is authenticated, but it is not federative authentication, reset authentication

            //log.Info($"Auth Mode: {identity.AuthenticationType}");
            //if (identity.IsAuthenticated || identity.AuthenticationType != "Federation")
            //{
            ////    httpApplication.Context.User = null;
            //}


            //if(false)
            //{
            //    log.Info("Session Auth Executing");
            //    base.OnAuthenticateRequest(sender, eventArgs);
            //}
            //else
            //{
            //    log.Info("Session Auth Bypassing");
            //    return;
            //}


            // if user is not authenticated, try to authenticate as usual by FedAuth cookie
        
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
                return false;
                var firstSection = DateTime.Now.Second >= 0 && DateTime.Now.Second <= 30;
                var SecondSection = DateTime.Now.Second > 30 && DateTime.Now.Second <= 60;
                var ThirdSection = DateTime.Now.Second > 40 && DateTime.Now.Second <= 60;

                return firstSection;
            }
        }
    }
}
