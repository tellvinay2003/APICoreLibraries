using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace OdlLegacyServiceSolution
{
    public class Authorize: Attribute
    {
        public bool IsValid()
        {
            return true;
        }
    }
}