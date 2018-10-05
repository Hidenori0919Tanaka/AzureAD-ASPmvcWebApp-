using System;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Google;
using Owin;
using AzureAD_ASPmvcWebApp.Models;
using System.Threading.Tasks;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Identity.Client;
using System.IdentityModel.Claims;
using System.Web;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Security;
using System.Configuration;

namespace AzureAD_ASPmvcWebApp
{
    public partial class Startup
    {
        // App config settings
        public static string ClientId = ConfigurationManager.AppSettings["ida:ClientId"];
        public static string ClientSecret = ConfigurationManager.AppSettings["ida:ClientSecret"];
        public static string AadInstance = ConfigurationManager.AppSettings["ida:AadInstance"];
        public static string Tenant = ConfigurationManager.AppSettings["ida:Tenant"];
        public static string RedirectUri = ConfigurationManager.AppSettings["ida:RedirectUri"];
        public static string ServiceUrl = ConfigurationManager.AppSettings["api:TaskServiceUrl"];

        // B2C policy identifiers
        public static string SignUpSignInPolicyId = ConfigurationManager.AppSettings["ida:SignUpSignInPolicyId"];
        public static string EditProfilePolicyId = ConfigurationManager.AppSettings["ida:EditProfilePolicyId"];
        public static string ResetPasswordPolicyId = ConfigurationManager.AppSettings["ida:ResetPasswordPolicyId"];

        public static string DefaultPolicy = SignUpSignInPolicyId;

        // API Scopes
        public static string ApiIdentifier = ConfigurationManager.AppSettings["api:ApiIdentifier"];
        public static string ReadTasksScope = ApiIdentifier + ConfigurationManager.AppSettings["api:ReadScope"];
        public static string WriteTasksScope = ApiIdentifier + ConfigurationManager.AppSettings["api:WriteScope"];
        public static string[] Scopes = new string[] { ReadTasksScope, WriteTasksScope };

        // OWIN auth middleware constants
        public const string ObjectIdElement = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier";

        // Authorities
        public static string Authority = String.Format(AadInstance, Tenant, DefaultPolicy);

        /*
        * Configure the OWIN middleware 
        */
        public void ConfigureAuth(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions());

            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    // Generate the metadata address using the tenant and policy information
                    MetadataAddress = String.Format(AadInstance, Tenant, DefaultPolicy),

                    // These are standard OpenID Connect parameters, with values pulled from web.config
                    ClientId = ClientId,
                    RedirectUri = RedirectUri,
                    PostLogoutRedirectUri = RedirectUri,

                    // Specify the callbacks for each type of notifications
                    Notifications = new OpenIdConnectAuthenticationNotifications
                    {
                        RedirectToIdentityProvider = OnRedirectToIdentityProvider,
                        AuthorizationCodeReceived = OnAuthorizationCodeReceived,
                        AuthenticationFailed = OnAuthenticationFailed,
                    },

                    // Specify the claim type that specifies the Name property.
                    TokenValidationParameters = new TokenValidationParameters
                    {
                        NameClaimType = "name"
                    },

                    // Specify the scope by appending all of the scopes requested into one string (separated by a blank space)
                    Scope = $"openid profile offline_access {ReadTasksScope} {WriteTasksScope}"
                }
            );
        }

        /*
         *  On each call to Azure AD B2C, check if a policy (e.g. the profile edit or password reset policy) has been specified in the OWIN context.
         *  If so, use that policy when making the call. Also, don't request a code (since it won't be needed).
         */
        private Task OnRedirectToIdentityProvider(RedirectToIdentityProviderNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> notification)
        {
            var policy = notification.OwinContext.Get<string>("Policy");

            if (!string.IsNullOrEmpty(policy) && !policy.Equals(DefaultPolicy))
            {
                notification.ProtocolMessage.Scope = OpenIdConnectScope.OpenId;
                notification.ProtocolMessage.ResponseType = OpenIdConnectResponseType.IdToken;
                notification.ProtocolMessage.IssuerAddress = notification.ProtocolMessage.IssuerAddress.ToLower().Replace(DefaultPolicy.ToLower(), policy.ToLower());
            }

            return Task.FromResult(0);
        }

        /*
         * Catch any failures received by the authentication middleware and handle appropriately
         */
        private Task OnAuthenticationFailed(AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> notification)
        {
            notification.HandleResponse();

            // Handle the error code that Azure AD B2C throws when trying to reset a password from the login page 
            // because password reset is not supported by a "sign-up or sign-in policy"
            if (notification.ProtocolMessage.ErrorDescription != null && notification.ProtocolMessage.ErrorDescription.Contains("AADB2C90118"))
            {
                // If the user clicked the reset password link, redirect to the reset password route
                notification.Response.Redirect("/Account/ResetPassword");
            }
            else if (notification.Exception.Message == "access_denied")
            {
                notification.Response.Redirect("/");
            }
            else
            {
                notification.Response.Redirect("/Home/Error?message=" + notification.Exception.Message);
            }

            return Task.FromResult(0);
        }


        /*
         * Callback function when an authorization code is received 
         */
        private async Task OnAuthorizationCodeReceived(AuthorizationCodeReceivedNotification notification)
        {
            // Extract the code from the response notification
            var code = notification.Code;

            string signedInUserID = notification.AuthenticationTicket.Identity.FindFirst(ClaimTypes.NameIdentifier).Value;
            TokenCache userTokenCache = new MSALSessionCache(signedInUserID, notification.OwinContext.Environment["System.Web.HttpContextBase"] as HttpContextBase).GetMsalCacheInstance();
            ConfidentialClientApplication cca = new ConfidentialClientApplication(ClientId, Authority, RedirectUri, new ClientCredential(ClientSecret), userTokenCache: userTokenCache, appTokenCache: null);
            try
            {
                AuthenticationResult result = await cca.AcquireTokenByAuthorizationCodeAsync(code, Scopes);
            }
            catch (Exception ex)
            {
                //TODO: Handle
                throw;
            }
        }

        //// 認証の構成の詳細については、https://go.microsoft.com/fwlink/?LinkId=301864 を参照してください
        //public void ConfigureAuth(IAppBuilder app)
        //{
        //    // 1 要求につき 1 インスタンスのみを使用するように DB コンテキスト、ユーザー マネージャー、サインイン マネージャーを構成します。
        //    app.CreatePerOwinContext(ApplicationDbContext.Create);
        //    app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);
        //    app.CreatePerOwinContext<ApplicationSignInManager>(ApplicationSignInManager.Create);

        //    // アプリケーションが Cookie を使用して、サインインしたユーザーの情報を格納できるようにします
        //    // また、サードパーティのログイン プロバイダーを使用してログインするユーザーに関する情報を、Cookie を使用して一時的に保存できるようにします
        //    // サインイン Cookie の設定
        //    app.UseCookieAuthentication(new CookieAuthenticationOptions
        //    {
        //        AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
        //        LoginPath = new PathString("/Account/Login"),
        //        Provider = new CookieAuthenticationProvider
        //        {
        //            // ユーザーがログインするときにセキュリティ スタンプを検証するように設定します。
        //            // これはセキュリティ機能の 1 つであり、パスワードを変更するときやアカウントに外部ログインを追加するときに使用されます。
        //            OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<ApplicationUserManager, ApplicationUser>(
        //                validateInterval: TimeSpan.FromMinutes(30),
        //                regenerateIdentity: (manager, user) => user.GenerateUserIdentityAsync(manager))
        //        }
        //    });            
        //    app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

        //    // 2 要素認証プロセスの中で 2 つ目の要素を確認するときにユーザー情報を一時的に保存するように設定します。
        //    app.UseTwoFactorSignInCookie(DefaultAuthenticationTypes.TwoFactorCookie, TimeSpan.FromMinutes(5));

        //    // 2 つ目のログイン確認要素 (電話や電子メールなど) を記憶するように設定します。
        //    // このオプションをオンにすると、ログイン プロセスの中の確認の第 2 ステップは、ログインに使用されたデバイスに保存されます。
        //    // これは、ログイン時の「このアカウントを記憶する」オプションに似ています。
        //    app.UseTwoFactorRememberBrowserCookie(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);

        //    // 次の行のコメントを解除して、サード パーティのログイン プロバイダーを使用したログインを有効にします
        //    //app.UseMicrosoftAccountAuthentication(
        //    //    clientId: "",
        //    //    clientSecret: "");

        //    //app.UseTwitterAuthentication(
        //    //   consumerKey: "",
        //    //   consumerSecret: "");

        //    //app.UseFacebookAuthentication(
        //    //   appId: "",
        //    //   appSecret: "");

        //    //app.UseGoogleAuthentication(new GoogleOAuth2AuthenticationOptions()
        //    //{
        //    //    ClientId = "",
        //    //    ClientSecret = ""
        //    //});
        //}
    }
}