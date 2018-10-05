using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(AzureAD_ASPmvcWebApp.Startup))]
namespace AzureAD_ASPmvcWebApp
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
