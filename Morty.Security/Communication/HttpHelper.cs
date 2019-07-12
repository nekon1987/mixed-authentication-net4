using log4net;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Morty.Security.Communication
{
    public class HttpHelper
    {
        private static readonly ILog log = LogManager.GetLogger("HttpHelper");

        public static bool IsUrlReachable(string url)
        {
            try
            {
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
                request.Timeout = 5000;
                request.Method = "HEAD"; // As per Lasse's comment
                try
                {
                    using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                    {
                        return response.StatusCode == HttpStatusCode.OK;
                    }
                }
                catch (WebException)
                {
                    return false;
                }

            }
            catch (Exception ex)
            {
                log.Error($"Url {url} - unable to probe", ex);
                return false;
            }
        }
    }
}
