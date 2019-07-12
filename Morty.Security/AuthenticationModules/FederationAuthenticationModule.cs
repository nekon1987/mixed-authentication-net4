using log4net;
using Morty.Security.Configuration;
using Morty.Security.Routing;
using System;
using System.Collections.Generic;
using System.IdentityModel.Services;
using System.IdentityModel.Services.Configuration;
using System.IdentityModel.Tokens;
using System.ServiceModel.Security;
using System.Web;

namespace Morty.Security.AuthenticationModules
{
    public class FederationAuthenticationModule : WSFederationAuthenticationModule
    {
        private readonly ILog log = LogManager.GetLogger("FederationModule");

        protected override void OnAuthenticateRequest(object sender, EventArgs args)
        {
            var preferredAuthenticationModule = AuthenticationRoutingService
                .GetPreferredAuthenticationModule(((HttpApplication)sender).Context);

            if (preferredAuthenticationModule == AuthenticationModuleTypes.WSFederation)
            {
                log.Debug("Executing native OnAuthenticateRequest");
                base.OnAuthenticateRequest(sender, args);
            }
            else
            {
                log.Debug("Bypassing native OnAuthenticateRequest");
            }
        }

        protected override void OnEndRequest(object sender, EventArgs args)
        {
            var preferredAuthenticationModule = AuthenticationRoutingService
                .GetPreferredAuthenticationModule(((HttpApplication)sender).Context);

            if (preferredAuthenticationModule == AuthenticationModuleTypes.WSFederation)
            {
                log.Debug("Executing native OnEndRequest");
                base.OnEndRequest(sender, args);
            }
            else
            {
                log.Debug("Bypassing native OnEndRequest");
            }
        }

        public static FederationConfiguration LoadConfigurationSection()
        {      
            var allowedAudience = MortysMixedAuthenticationConfiguration.Settings.ClientApplicationUri;
            var rpRealm = MortysMixedAuthenticationConfiguration.Settings.ClientApplicationUri;
            var domain = "";
            var requireSsl = true;
            var issuer = MortysMixedAuthenticationConfiguration.Settings.SecurityTokenIssuerUri;
            var certThumbprint = MortysMixedAuthenticationConfiguration.Settings.TokenSigningSertificateThumbprint;
            var issuingAuthorityUri = MortysMixedAuthenticationConfiguration.Settings.TokenIssuingAuthorityUri;
            var authCookieName = "FocusFederatedAuth";

            var federationConfiguration = new FederationConfiguration();
            federationConfiguration.IdentityConfiguration.AudienceRestriction.AllowedAudienceUris.Add(new Uri(allowedAudience));

            var issuingAuthority = new IssuingAuthority(issuingAuthorityUri);
            issuingAuthority.Thumbprints.Add(certThumbprint);
            issuingAuthority.Issuers.Add(issuingAuthorityUri);

            var validatingIssuerNameRegistry = new ValidatingIssuerNameRegistry
            {
                IssuingAuthorities = new List<IssuingAuthority> { issuingAuthority }
            };
            federationConfiguration.IdentityConfiguration.IssuerNameRegistry = validatingIssuerNameRegistry;
            federationConfiguration.IdentityConfiguration.CertificateValidationMode = X509CertificateValidationMode.None;

            var chunkedCookieHandler = new ChunkedCookieHandler { RequireSsl = false, Name = authCookieName, Domain = domain, PersistentSessionLifetime = new TimeSpan(0, 0, 30, 0) };
            federationConfiguration.CookieHandler = chunkedCookieHandler;

            federationConfiguration.WsFederationConfiguration.Issuer = issuer;
            federationConfiguration.WsFederationConfiguration.Realm = rpRealm;
            federationConfiguration.WsFederationConfiguration.RequireHttps = requireSsl;
            federationConfiguration.WsFederationConfiguration.PassiveRedirectEnabled = true;

            return federationConfiguration;
        }
    }
}
