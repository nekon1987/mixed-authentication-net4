using log4net;
using log4net.Config;
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

        protected void Application_Error()
        {
            var ex = Server.GetLastError();
            log.Error(ex);
            //log the error!
        }

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

        //protected void Application_BeginRequest(object sender, EventArgs e)
        //{
        //    // Do Not Allow URL to end in trailing slash
        //    string url = HttpContext.Current.Request.Url.AbsolutePath;
        //    if (string.IsNullOrEmpty(url)) return;

        //    string lastChar = url[url.Length - 1].ToString();
        //    if (lastChar == "/" || lastChar == "\\")
        //    {
        //        url = url.Substring(0, url.Length - 1);
        //        Response.Clear();
        //        Response.Status = "301 Moved Permanently";
        //        Response.AddHeader("Location", url);
        //        Response.End();
        //    }
        //}

        private void FederatedAuthentication_FederationConfigurationCreated(object sender, FederationConfigurationCreatedEventArgs e)
        {
            this.log.Info("Configuring WSFederation");
            //from appsettings...
            const string allowedAudience = "https://gy-gd-k120/MortysAwesomeClientApp/";
            const string rpRealm = "https://gy-gd-k120/MortysAwesomeClientApp/";
            const string domain = "";
            const bool requireSsl = true;
            const string issuer = "https://mortycorp-dc.mortycorp.local/adfs/ls"; // "http://sts/token/create";
            const string certThumbprint = "350c0b0fe744ee3bc3cbbb2182ad6628692ddbab";
            const string authCookieName = "StsAuth";

            var federationConfiguration = new FederationConfiguration();
            federationConfiguration.IdentityConfiguration.AudienceRestriction.AllowedAudienceUris.Add(new Uri(allowedAudience));
      
            var issuingAuthority = new System.IdentityModel.Tokens.IssuingAuthority("http://mortycorp-dc.mortycorp.local/adfs/services/trust");
            issuingAuthority.Thumbprints.Add(certThumbprint);
            issuingAuthority.Issuers.Add("http://mortycorp-dc.mortycorp.local/adfs/services/trust");
            var issuingAuthorities = new List<System.IdentityModel.Tokens.IssuingAuthority> { issuingAuthority };

            var validatingIssuerNameRegistry = new System.IdentityModel.Tokens.ValidatingIssuerNameRegistry
            {
                IssuingAuthorities = issuingAuthorities
            };
            federationConfiguration.IdentityConfiguration.IssuerNameRegistry = validatingIssuerNameRegistry;
            federationConfiguration.IdentityConfiguration.CertificateValidationMode = X509CertificateValidationMode.None;

            var chunkedCookieHandler = new ChunkedCookieHandler { RequireSsl = false, Name = authCookieName, Domain = domain, PersistentSessionLifetime = new TimeSpan(0, 0, 30, 0) };
            federationConfiguration.CookieHandler = chunkedCookieHandler;
            federationConfiguration.WsFederationConfiguration.Issuer = issuer;
            federationConfiguration.WsFederationConfiguration.Realm = rpRealm;
            federationConfiguration.WsFederationConfiguration.RequireHttps = requireSsl;
            federationConfiguration.WsFederationConfiguration.PassiveRedirectEnabled = true;

            e.FederationConfiguration = federationConfiguration;
        }
    }
}
