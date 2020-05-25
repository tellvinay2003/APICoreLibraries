using OdlLegacyWebServices.BusinessManagers;
using OdlLegacyWebServices.BusinessManagers.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Security.Permissions;
using System.ServiceModel;
using System.ServiceModel.Activation;
using System.ServiceModel.Web;
using System.Text;

namespace OdlLegacyWebServices
{
    // [PrincipalPermission(SecurityAction.Demand, Authenticated = true)]
    [AspNetCompatibilityRequirements(RequirementsMode = AspNetCompatibilityRequirementsMode.Allowed)]
    [ServiceBehavior(InstanceContextMode = InstanceContextMode.Single)]
    public class MappingService : IMappingService
    {
        public List<string> GetMappingDetails()
        {
            string tokenStr = string.Empty;

            OperationContext context = OperationContext.Current;
            if (context != null && context.RequestContext != null)
            {
                System.ServiceModel.Channels.Message msg = context.RequestContext.RequestMessage;
                tokenStr = msg.ToString();
            }

            //TODO: implement Unity to use MappingServiceManager class
            IMappingServiceManager serviceManager = new MappingServiceManager();
            var result = serviceManager.GetMappingDetails().ToList();
            result.Add("token: "+tokenStr);
            
            return result;
        }
    }
}
