using log4net;
using System;
using System.Web;

namespace Morty.Security.Routing
{
    public class AuthenticationRoutingService
    {
        private const string EXTERNAL_CLIENT_HEADER = "ExternalClient";
        private static readonly ILog log = LogManager.GetLogger("RoutingService");

        public static AuthenticationModuleTypes GetPreferredAuthenticationModule(HttpContext httpContext)
        {
            LogRequestDetails(httpContext);

            // Test Mode - Switching from WindowsIntegrated to WSFederation every 30 seconds
            // return Test_ShouldUseFederationAuthenticationBasedOn30secondWindow;

            if (CheckRequestForExternalClientHeader(httpContext.Request))
                return AuthenticationModuleTypes.WSFederation;
            else
                return AuthenticationModuleTypes.WindowsIntegrated;
        }

        private static bool CheckRequestForExternalClientHeader(HttpRequest request)
        {
            if (request != null && request.Headers != null)
                return request.Headers[EXTERNAL_CLIENT_HEADER] != null;

            return false;
        }

        private static void LogRequestDetails(HttpContext httpContext)
        {
            log.Debug($"Incomming request from -> {httpContext.Request.UserHostAddress}");

            if (httpContext.Request != null && httpContext.Request.Headers != null)
            {
                log.Debug("Listing incomming request headers:");
                foreach (var header in httpContext.Request.Headers.AllKeys)
                {
                    log.Debug($"{header} -> {httpContext.Request.Headers[header].ToString()}");
                }
            }
        }

        /// <summary>
        /// Dummy switch for testing purposes - with this, authentication method will switch every 30 seconds
        /// </summary>
        private static AuthenticationModuleTypes Test_ShouldUseFederationAuthenticationBasedOn30secondWindow
        {
            get
            {
                return DateTime.Now.Second >= 0 && DateTime.Now.Second <= 30
                    ? AuthenticationModuleTypes.WSFederation
                    : AuthenticationModuleTypes.WindowsIntegrated;
            }
        }
    }
}
