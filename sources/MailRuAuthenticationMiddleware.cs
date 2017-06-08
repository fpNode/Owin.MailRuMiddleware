using System;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin;
using fpNode.Owin.MailRuMiddleware.Provider;

namespace fpNode.Owin.MailRuMiddleware
{
    public class MailRuAuthenticationMiddleware : AuthenticationMiddleware<MailRuAuthenticationOptions>
    {
        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        /// <summary>
        /// Initializes a <see cref="MailRuAuthenticationMiddleware"/>
        /// </summary>
        /// <param name="next">The next middleware in the OWIN pipeline to invoke</param>
        /// <param name="app">The OWIN application</param>
        /// <param name="options">Configuration options for the middleware</param>
        public MailRuAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, MailRuAuthenticationOptions options)
            : base(next, options)
        {
            if (next == null)
                throw new ArgumentNullException("next");

            if (options == null)
                throw new ArgumentException("options can't be null or empty");

            _logger = app.CreateLogger<MailRuAuthenticationMiddleware>();


            if (Options.Provider == null)
            {
                Options.Provider = new MailRuAuthenticationProvider();
            }
            if (Options.StateDataFormat == null)
            {
                IDataProtector dataProtector = app.CreateDataProtector(
                    typeof(MailRuAuthenticationMiddleware).FullName,
                    Options.AuthenticationType, "v1");
                Options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }
            if (String.IsNullOrEmpty(Options.SignInAsAuthenticationType))
            {
                Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
            }

            _httpClient = new HttpClient(ResolveHttpMessageHandler(Options));
            _httpClient.Timeout = Options.BackchannelTimeout;
            _httpClient.MaxResponseContentBufferSize = 1024 * 1024 * 10; // 10 MB
        }

        /// <summary>
        /// Provides the <see cref="AuthenticationHandler"/> object for processing authentication-related requests. 
        /// Called at start of every page request.
        /// </summary>
        /// <returns>An <see cref="AuthenticationHandler"/> configured with the <see cref="MailRuAuthenticationOptions"/> supplied to the constructor.</returns>
        protected override AuthenticationHandler<MailRuAuthenticationOptions> CreateHandler()
        {
            return new MailRuAuthenticationHandler(_httpClient, _logger);
        }

        [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Managed by caller")]
        private static HttpMessageHandler ResolveHttpMessageHandler(MailRuAuthenticationOptions options)
        {
            HttpMessageHandler handler = options.BackchannelHttpHandler ?? new WebRequestHandler();

            // If they provided a validator, apply it or fail.
            if (options.BackchannelCertificateValidator != null)
            {
                // Set the cert validate callback
                var webRequestHandler = handler as WebRequestHandler;
                if (webRequestHandler == null)
                {
                    throw new InvalidOperationException("An ICertificateValidator cannot be specified at the same time as an HttpMessageHandler unless it is a WebRequestHandler.");
                }
                webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;
            }

            return handler;
        }
    }
}
