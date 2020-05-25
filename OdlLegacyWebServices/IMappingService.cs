using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.ServiceModel;
using System.ServiceModel.Web;
using System.Text;

namespace OdlLegacyWebServices
{
    // NOTE: You can use the "Rename" command on the "Refactor" menu to change the interface name "IMappingService" in both code and config file together.
    [ServiceContract]
   
    public interface IMappingService
    {
        [OperationContract]
        [WebInvoke(Method = "POST", RequestFormat = WebMessageFormat.Json, ResponseFormat = WebMessageFormat.Json, BodyStyle = WebMessageBodyStyle.Bare)]
        List<string> GetMappingDetails();
    }
}
