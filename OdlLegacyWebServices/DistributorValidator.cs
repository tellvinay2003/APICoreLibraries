using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Web;
using System.Web;

namespace OdlLegacyWebServices
{
    public class DistributorValidator : ServiceAuthorizationManager
    {
        //protected override bool CheckAccessCore(OperationContext operationContext)
        //{
        //    // //string auth = OperationContext.Current.IncomingMessageHeaders.GetHeader<string>("Authorization", "https://localhost:44313/GetMappingsValue");
        //    // //var token = HttpContext.Current.Request.Headers["Token"];
        //    // //var authHeader = WebOperationContext.Current.IncomingRequest.Headers["Authorization"];
        //    // //var messageHdr = operationContext.IncomingMessageHeaders;

        //    // string tokenStr = string.Empty;

        //    // OperationContext context = OperationContext.Current;
        //    // if (context != null && context.RequestContext != null)
        //    // {
        //    //     System.ServiceModel.Channels.Message msg = context.RequestContext.RequestMessage;
        //    //     tokenStr = msg.ToString();
        //    // }

        //    ////  string token = GetTokenValue(tokenStr);

        //    // if (!string.IsNullOrEmpty(tokenStr))
        //    //     return true;
        //    // else
        //    //     return false;
        //    return true;
        //}

        private string GetTokenValue(string envlopeData)
        {
            int index = envlopeData.IndexOf("Bearer");
            envlopeData = envlopeData.Substring(index, envlopeData.Length - index);
            index = envlopeData.IndexOf("</Token>");
            envlopeData = envlopeData.Substring(0, index);
            return envlopeData;
        }
    }
}