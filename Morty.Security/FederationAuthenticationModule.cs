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
        private readonly ILog log = LogManager.GetLogger("WSFedModule");

        protected override void OnAuthorizationFailed(AuthorizationFailedEventArgs e)
        {
            base.OnAuthorizationFailed(e);
        }

        protected override void OnPostAuthenticateRequest(object sender, EventArgs e)
        {
            base.OnPostAuthenticateRequest(sender, e);
        }

        protected override void OnAuthenticateRequest(object sender, EventArgs args)
        {
            if (Test_ShouldUseFederationAuthenticationBasedOn10secondWindow)
            {
                log.Info($"FED2 -> Using");
                base.OnAuthenticateRequest(sender, args);
            }
        }

        // with this uncom it fails - simplify just to do base call - HSOUDL WORK !!!!
        //protected override void OnAuthenticateRequest(object sender, EventArgs args)
        //{
        //    // base.OnEndRequest(sender, args);
        //    if (Test_ShouldUseFederationAuthenticationBasedOn10secondWindow)
        //    {
        //        log.Info($"FED2 -> Using");
        //        base.OnEndRequest(sender, args);               
        //    }
        //    else
        //    {
        //        log.Info($"FED2 -> NOT Using");
        //    }
        //}

        protected override void OnEndRequest(object sender, EventArgs args)
        {
            if (Test_ShouldUseFederationAuthenticationBasedOn10secondWindow)
            {
                log.Info($"FED -> Using");
                base.OnEndRequest(sender, args);
            }
            else
            {
                log.Info($"FED -> NOT Using");
            }

            //log.Info($"WSFederation EXECUTING ###");
            //base.OnEndRequest(sender, args);
            //return;
            //HttpApplication httpApplication = (HttpApplication)sender;

            //log.Info($"WSFederation -> {Test_ShouldUseFederationAuthenticationBasedOn10secondWindow}");
            //if (false)
            //{
            //    //string url = HttpContext.Current.Request.Url.AbsolutePath;
            //    //string lastChar = url[url.Length - 1].ToString();
            //    //if (lastChar != "/")
            //    //{
            //    //    url = url + "/";
            //    //    httpApplication.Response.Clear();
            //    //    httpApplication.Response.Status = "301 Moved Permanently";
            //    //    httpApplication.Response.AddHeader("Location", url);
            //    //    httpApplication.Response.End();
            //    //    return;
            //    //}

            //    log.Info($"WSFederation -> Module logic is executed");
            //    if (CheckIfWindowAuthenticationDetailsExist(httpApplication))
            //    {
            //        log.Info($"WSFederation -> Clearing windows credentials");
            //        //ClearWSFederationAuthenticationDetails();
            //        ClearWindowsIntegratedAuthenticationDetails(httpApplication);
            //        return;
            //    }
            //    log.Info($"WSFederation -> Serving request with base code");
            //    base.OnEndRequest(sender, args);
            //}
            //else
            //{
            //    //string url = HttpContext.Current.Request.Url.AbsolutePath;
            //    //string lastChar = url[url.Length - 1].ToString();
            //    //if (lastChar == "/" || lastChar == "\\")
            //    //{
            //    //    url = url.Substring(0, url.Length - 1);
            //    //    httpApplication.Response.Clear();
            //    //    httpApplication.Response.Status = "301 Moved Permanently";
            //    //    httpApplication.Response.AddHeader("Location", url);
            //    //    httpApplication.Response.End();
            //    //}

            //    log.Info($"WSFederation -> Module logic is bypassed");
            //    /* 
            //     * If base.OnEndRequest isnt executed this will cause pipeline to 
            //     * pass authentication to the next configured module
            //     */
            //    if (CheckIfWSFederationAuthenticationDetailsExist())
            //    {
            //        log.Info($"WSFederation -> Clearing WSFederation credentials for windows module which should be executed next");
            //        ClearWSFederationAuthenticationDetails();
            //      //  ClearWindowsIntegratedAuthenticationDetails(httpApplication);
            //    }
            //}
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
