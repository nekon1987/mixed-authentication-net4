using log4net;
using log4net.Config;
using Morty.Security.AuthenticationModules;
using Morty.Security.Configuration;
using System;
using System.Collections.Generic;
using System.IdentityModel.Services;
using System.IdentityModel.Services.Configuration;
using System.Linq;
using System.Reflection;
using System.ServiceModel.Security;
using System.Web;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;

namespace MortysAwesomeClientApp
{
    public class MvcApplication : System.Web.HttpApplication
    {
        private readonly ILog log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
    
        protected void Application_Start()
        {
            XmlConfigurator.Configure();
            this.log.Info("Application startup");

            AreaRegistration.RegisterAllAreas();
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);

            FederatedAuthentication.FederationConfigurationCreated += FederatedAuthentication_FederationConfigurationCreated;           
        }

        private void FederatedAuthentication_FederationConfigurationCreated(object sender, FederationConfigurationCreatedEventArgs e)
        {
            log.Info("Configuring WSFederation");

            log.Info($"ClientApplicationUri:  {MortysMixedAuthenticationConfiguration.Settings.ClientApplicationUri}");
            log.Info($"SecurityTokenIssuerUri:  {MortysMixedAuthenticationConfiguration.Settings.SecurityTokenIssuerUri}");
            log.Info($"TokenIssuingAuthorityUri:  {MortysMixedAuthenticationConfiguration.Settings.TokenIssuingAuthorityUri}");
            log.Info($"TokenSigningSertificateThumbprint:  {MortysMixedAuthenticationConfiguration.Settings.TokenSigningSertificateThumbprint}");

            e.FederationConfiguration = FederationAuthenticationModule.LoadConfigurationSection();
        }
        protected void Application_Error()
        {
            log.Error(Server.GetLastError());
        }
    }
}
