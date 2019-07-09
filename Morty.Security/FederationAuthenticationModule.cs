using System;
using System.Collections.Generic;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace Morty.Security
{
    public class FederationAuthenticationModule : System.IdentityModel.Services.WSFederationAuthenticationModule
    {
        public override bool CanReadSignInResponse(HttpRequestBase request, bool onPage)
        {
            return base.CanReadSignInResponse(request, onPage);
        }

        public override SecurityToken GetSecurityToken(HttpRequestBase request)
        {
            return base.GetSecurityToken(request);
        }

        protected override string GetReferencedResult(string resultPtr)
        {
            return base.GetReferencedResult(resultPtr);
        }

        public override SecurityToken GetSecurityToken(SignInResponseMessage message)
        {
            return base.GetSecurityToken(message);
        }

        protected override string GetSessionTokenContext()
        {
            return base.GetSessionTokenContext();
        }

        protected override void InitializeModule(HttpApplication context)
        {
            base.InitializeModule(context);
        }

        public override string GetXmlTokenFromMessage(SignInResponseMessage message, WSFederationSerializer federationSerializer)
        {
            return base.GetXmlTokenFromMessage(message, federationSerializer);
        }

        protected override string GetReturnUrlFromResponse(HttpRequestBase request)
        {
            return base.GetReturnUrlFromResponse(request);
        }

        public override SignInResponseMessage GetSignInResponseMessage(HttpRequestBase request)
        {
            return base.GetSignInResponseMessage(request);
        }

        protected override string GetSignOutRedirectUrl(SignOutCleanupRequestMessage signOutMessage)
        {
            return base.GetSignOutRedirectUrl(signOutMessage);
        }

        protected override void OnSignOutError(ErrorEventArgs args)
        {
            base.OnSignOutError(args);
        }

        public override string GetXmlTokenFromMessage(SignInResponseMessage message)
        {
            return base.GetXmlTokenFromMessage(message);
        }

        protected override void InitializePropertiesFromConfiguration()
        {
            base.InitializePropertiesFromConfiguration();
        }

        public override bool IsSignInResponse(HttpRequestBase request)
        {
            return base.IsSignInResponse(request);
        }

        protected override void OnPostAuthenticateRequest(object sender, EventArgs e)
        {
            base.OnPostAuthenticateRequest(sender, e);
        }

        protected override void OnAuthorizationFailed(AuthorizationFailedEventArgs e)
        {
            base.OnAuthorizationFailed(e);
        }

        protected override void OnSessionSecurityTokenCreated(SessionSecurityTokenCreatedEventArgs args)
        {
            base.OnSessionSecurityTokenCreated(args);
        }
        protected override void OnSignedIn(EventArgs args)
        {
            base.OnSignedIn(args);
        }

        public override void SignOut()
        {
            base.SignOut();
        }

        protected override void OnSignedOut(EventArgs args)
        {
            base.OnSignedOut(args);
        }

        public override void SignIn(string ControlId)
        {
            base.SignIn(ControlId);
        }

        public override void SignOut(bool isIPRequest)
        {
            base.SignOut(isIPRequest);
        }


        protected override void OnSignInError(ErrorEventArgs args)
        {
            base.OnSignInError(args);
        }

        protected override void OnSigningOut(SigningOutEventArgs args)
        {
            base.OnSigningOut(args);

        }

        public override void SignOut(string redirectUrl)
        {
            base.SignOut(redirectUrl);
        }

        public override void SignOut(string redirectUrl, bool initiateSignoutCleanup)
        {
            base.SignOut(redirectUrl, initiateSignoutCleanup);
        }

        public override void RedirectToIdentityProvider(string uniqueId, string returnUrl, bool persist)
        {
            base.RedirectToIdentityProvider(uniqueId, returnUrl, persist);
        }

        protected override void OnRedirectingToIdentityProvider(RedirectingToIdentityProviderEventArgs e)
        {
            base.OnRedirectingToIdentityProvider(e);
        }

        protected override void OnAuthenticateRequest(object sender, EventArgs args)
        {
            base.OnAuthenticateRequest(sender, args);
        }

        protected override void OnEndRequest(object sender, EventArgs args)
        {
            return;
            base.OnEndRequest(sender, args);
            return;

            HttpApplication httpApplication = (HttpApplication)sender;

            var shouldUseThisModule = false; // = DateTime.Now.Minute % 2 == 0; // #TestMode >> only for even minutes 

            if (shouldUseThisModule)
            {
                base.OnEndRequest(sender, args);
            }
            else
            {
                /* 
                 * If base.OnEndRequest isnt executed this will cause pipeline to 
                 * pass authentication to the next configured module
                 */
            }
        }
    }
}
