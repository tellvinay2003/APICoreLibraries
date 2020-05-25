using OdlLegacyWebServices.BusinessManagers.Interfaces;
using OdlLegacyWebServices.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace OdlLegacyWebServices.BusinessManagers
{
    public class MappingServiceManager: IMappingServiceManager
    {
        private readonly TSDbEntities _dbContext = new TSDbEntities();
        public List<string> GetMappingDetails()
        {
            var mappingResult = _dbContext.MAPPINGS.Select(x => x.MAPPINGNAME).ToList();
            return mappingResult;

        }
    }
}