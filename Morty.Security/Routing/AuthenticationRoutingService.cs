using log4net;
using Morty.Security.Communication;
using Morty.Security.Configuration;
using System;
using System.Web;

namespace Morty.Security.Routing
{
    public class AuthenticationRoutingService
    {
        private const string EXTERNAL_CLIENT_HEADER = "ExternalClient";
        private static readonly ILog log = LogManager.GetLogger("RoutingService");

        private static readonly bool IsFederationAuthorityUrlReachable = HttpHelper
            .IsUrlReachable(MortysMixedAuthenticationConfiguration.Settings.TokenIssuingAuthorityUri);

        public static AuthenticationModuleTypes GetPreferredAuthenticationModule(HttpContext httpContext)
        {
            LogRequestDetails(httpContext);

            if (IsFederationAuthorityUrlReachable && CheckRequestForExternalClientHeader(httpContext.Request))
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
    }
}
