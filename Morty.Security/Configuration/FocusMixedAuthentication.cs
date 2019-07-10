using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Morty.Security.Configuration
{
    public class FocusMixedAuthentication: ConfigurationSection
    {
        public static FocusMixedAuthentication Settings { get; } =
            ConfigurationManager.GetSection("FocusMixedAuthentication") as FocusMixedAuthentication;

        [ConfigurationProperty("ClientApplicationUri", IsRequired = true)]
        public string ClientApplicationUri
        {
            get { return (string)this["ClientApplicationUri"]; }
            set { this["ClientApplicationUri"] = value; }
        }

        [ConfigurationProperty("SecurityTokenIssuerUri", IsRequired = true)]
        public string SecurityTokenIssuerUri
        {
            get { return (string)this["SecurityTokenIssuerUri"]; }
            set { this["SecurityTokenIssuerUri"] = value; }
        }

        [ConfigurationProperty("TokenSigningSertificateThumbprint", IsRequired = true)]
        public string TokenSigningSertificateThumbprint
        {
            get { return (string)this["TokenSigningSertificateThumbprint"]; }
            set { this["TokenSigningSertificateThumbprint"] = value; }
        }

        [ConfigurationProperty("TokenIssuingAuthorityUri", IsRequired = true)]
        public string TokenIssuingAuthorityUri
        {
            get { return (string)this["TokenIssuingAuthorityUri"]; }
            set { this["TokenIssuingAuthorityUri"] = value; }
        }
    }
}
