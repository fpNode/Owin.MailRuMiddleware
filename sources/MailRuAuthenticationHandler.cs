using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using fpNode.Owin.MailRuMiddleware.Provider;
using System.Security.Cryptography;
using Newtonsoft.Json.Linq;

namespace fpNode.Owin.MailRuMiddleware
{
    public class MailRuAuthenticationHandler : AuthenticationHandler<MailRuAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
        private const string TokenEndpoint = "https://connect.mail.ru";
        private const string GraphApiEndpoint = "http://www.appsmail.ru/platform/api";

        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;        

        public MailRuAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        //<summary>step 1
        //called at the end of server request after site controllers
        //if client not autorized 401 - redirect to mail.ru - It is start point of the authorization process
        //Redirect user to mail.ru where he need loging and allow access to your app
        //after that redirect back to {host}/signin-mailru
        //</summary
        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            //Helper checking if that module called for login
            AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                string baseUri =
                    Request.Scheme +
                    Uri.SchemeDelimiter +
                    Request.Host +
                    Request.PathBase;

                string currentUri =
                    baseUri +
                    Request.Path +
                    Request.QueryString;

                string redirectUri =
                    baseUri +
                    Options.CallbackPath;

                AuthenticationProperties properties = challenge.Properties;
                if (string.IsNullOrEmpty(properties.RedirectUri))
                {
                    properties.RedirectUri = currentUri;
                }

                // OAuth2 10.12 CSRF
                GenerateCorrelationId(properties);

                // comma separated
                string scope = Options.Scope;

                string state = Options.StateDataFormat.Protect(properties);

                Options.StoreState = state;

                string authorizationEndpoint =
                    "https://connect.mail.ru/oauth/authorize" +
                        "?client_id=" + Uri.EscapeDataString(Options.AppId) +
                        "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                        "&scope=" + Uri.EscapeDataString(scope) +
                        "&response_type=code";

                Response.Redirect(authorizationEndpoint);
            }

            return Task.FromResult<object>(null);
        }

        //<summary>step 2.0
        //Called at start of page request, before site controllers
        //</summary>
        public override async Task<bool> InvokeAsync()
        {
            return await InvokeReplyPathAsync();
        }

        //step 2.1
        //called at start of page request - checking if request match with "{host}/signin-mailru" url {?code=*******************}
        //if matched - making AuthenticationTicket 
        private async Task<bool> InvokeReplyPathAsync()
        {
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
            {
                AuthenticationTicket ticket = await AuthenticateAsync(); //call Task<AuthenticationTicket> AuthenticateCoreAsync() step 2.3
                if (ticket == null)
                {
                    _logger.WriteWarning("Invalid return state, unable to redirect.");
                    Response.StatusCode = 500;
                    return true;
                }

                var context = new MailRuReturnEndpointContext(Context, ticket);
                context.SignInAsAuthenticationType = Options.SignInAsAuthenticationType;
                context.RedirectUri = ticket.Properties.RedirectUri;

                await Options.Provider.ReturnEndpoint(context);

                if (context.SignInAsAuthenticationType != null &&
                    context.Identity != null)
                {
                    ClaimsIdentity grantIdentity = context.Identity;
                    if (!string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                    {
                        grantIdentity = new ClaimsIdentity(grantIdentity.Claims, context.SignInAsAuthenticationType, grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
                    }
                    Context.Authentication.SignIn(context.Properties, grantIdentity);
                }

                if (!context.IsRequestCompleted && context.RedirectUri != null)
                {
                    string redirectUri = context.RedirectUri;
                    if (context.Identity == null)
                    {
                        // add a redirect hint that sign-in failed in some way
                        redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
                    }
                    Response.Redirect(redirectUri);
                    context.RequestCompleted();
                }

                return context.IsRequestCompleted;
            }

            return false;
        }

        //step 2.3
        //making AuthenticationTicket after client return from mail.ru
        //here we make actually autorization work
        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {
                string code = "";

                IReadableStringCollection query = Request.Query;
                IList<string> values = query.GetValues("code");

                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }

                properties = Options.StateDataFormat.Unprotect(Options.StoreState);
                if (properties == null)
                {
                    return null;
                }

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, _logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                string requestPrefix = Request.Scheme + Uri.SchemeDelimiter + Request.Host;
                string redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

                var content = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("client_id", Options.AppId),
                    new KeyValuePair<string, string>("client_secret", Options.AppSecret),
                    new KeyValuePair<string, string>("grant_type", "authorization_code"),
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("redirect_uri", redirectUri)
                });

                if (_httpClient.BaseAddress == null)
                    _httpClient.BaseAddress = new Uri(TokenEndpoint);
                HttpResponseMessage tokenResponse = await _httpClient.PostAsync("/oauth/token", content, Request.CallCancelled);
                tokenResponse.EnsureSuccessStatusCode();
                string text = await tokenResponse.Content.ReadAsStringAsync();
                var JsonResponse = JsonConvert.DeserializeObject<dynamic>(text);

                string accessToken = JsonResponse["access_token"];
                string expires = JsonResponse["expires_in"];
                string userid = JsonResponse["x_mailru_vid"];

                string signature = string.Format("app_id={0}method={1}secure=1session_key={2}uids={3}{4}",
                    Options.AppId,
                    "users.getInfo",
                    accessToken,
                    userid,
                    Options.AppSecret
                    );


                var provider = new MD5CryptoServiceProvider();
                var bytes = Encoding.UTF8.GetBytes(signature);
                bytes = provider.ComputeHash(bytes);
                signature =  BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();

                //public method which dont require token
                string userInfoLink = GraphApiEndpoint +
                                      "?method=users.getInfo" +
                                      "&app_id=" + Uri.EscapeDataString(Options.AppId) +
                                      "&secure=1&session_key=" + Uri.EscapeDataString(accessToken) +
                                      "&sig=" + signature +
                                      "&uids=" + Uri.EscapeDataString(userid);

                HttpResponseMessage graphResponse = await _httpClient.GetAsync(userInfoLink, Request.CallCancelled);
                graphResponse.EnsureSuccessStatusCode();
                text = await graphResponse.Content.ReadAsStringAsync();
                JArray a = JArray.Parse(text);
                var UserInfoResponseJson = (JObject)a.First();

                var context = new MailRuAuthenticatedContext(Context, UserInfoResponseJson, accessToken, expires);
                context.Identity = new ClaimsIdentity(
                    Options.AuthenticationType,
                    ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);

                if (!string.IsNullOrEmpty(context.Id))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.DefaultName))
                {
                    context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, context.DefaultName, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.FullName))
                {
                    context.Identity.AddClaim(new Claim("urn:MailRu:name", context.FullName, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Email))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.Email, XmlSchemaString, Options.AuthenticationType));
                }
                context.Properties = properties;

                await Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);

            }
            catch (Exception ex)
            {
                _logger.WriteError(ex.Message);
            }
            return new AuthenticationTicket(null, properties);
        }
    }
}
