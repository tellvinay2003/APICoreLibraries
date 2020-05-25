using Microsoft.AspNetCore.Authorization;
using System;
using System.Collections.Generic;

using System.Linq;
using System.Web;
using System.Web.Http;

namespace OdlLegacyWebServices
{
    public class LoggedOrAuthorizedAttribute: AuthorizeAttribute
    {
        //public override void OnAuthorization(AuthorizationContext filterContext)
        //{
        //    base.OnAuthorization(filterContext);
        //    CheckIfUserIsAuthenticated(filterContext);
        //}

        //private void CheckIfUserIsAuthenticated(AuthorizationContext filterContext)
        //{
        //    // If Result is null, we're OK: the user is authenticated and authorized. 
        //    if (filterContext.Result == null)
        //        return;

        //    // If here, you're getting an HTTP 401 status code. In particular,
        //    // filterContext.Result is of HttpUnauthorizedResult type. Check Ajax here. 
        //    if (filterContext.HttpContext.User.Identity.IsAuthenticated)
        //    {
        //        if (String.IsNullOrEmpty(View))
        //            return;
        //        var result = new ViewResult { ViewName = View, MasterName = Master };
        //        filterContext.Result = result;
        //    }
        //}
    }
}