using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using fpNode.Owin.MailRuMiddleware.Provider;

namespace fpNode.Owin.MailRuMiddleware
{
    /// <summary>
    /// Configuration options for <see cref="MailRuAuthenticationMiddleware"/>
    /// </summary>
    [SuppressMessage("Microsoft.Globalization", "CA1303:Do not pass literals as localized parameters", MessageId = "MailRuMiddleware.MailRuAuthenticationOptions.set_Caption(System.String)", Justification = "Not localizable.")]
    public class MailRuAuthenticationOptions : AuthenticationOptions
    {
        public const string DefaultCaption = "MailRu";

        /// <summary>
        /// Initializes a new <see cref="MailRuAuthenticationOptions"/>
        /// </summary>
        public MailRuAuthenticationOptions()
            : base(DefaultCaption)
        {
            Caption = DefaultCaption;
            CallbackPath = new PathString("/signin-mailru");
            AuthenticationMode = AuthenticationMode.Passive;
            Scope = "";
            BackchannelTimeout = TimeSpan.FromSeconds(60);
        }

        /// <summary>
        /// Gets or sets the appId
        /// </summary>
        public string AppId { get; set; }

        /// <summary>
        /// Gets or sets the app secret
        /// </summary>
        public string AppSecret { get; set; }

        /// <summary>
        /// Gets or sets the a pinned certificate validator to use to validate the endpoints used
        /// in back channel communications belong to MailRu.
        /// </summary>
        /// <value>
        /// The pinned certificate validator.
        /// </value>
        /// <remarks>If this property is null then the default certificate checks are performed,
        /// validating the subject name and if the signing chain is a trusted party.</remarks>
        public ICertificateValidator BackchannelCertificateValidator { get; set; }

        /// <summary>
        /// Gets or sets timeout value in milliseconds for back channel communications with MailRu.
        /// </summary>
        /// <value>
        /// The back channel timeout in milliseconds.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        /// The HttpMessageHandler used to communicate with MailRu.
        /// This cannot be set at the same time as BackchannelCertificateValidator unless the value 
        /// can be downcast to a WebRequestHandler.
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        /// Get or sets the text that the user can display on a sign in user interface.
        /// </summary>
        public string Caption
        {
            get { return Description.Caption; }
            set { Description.Caption = value; }
        }

        /// <summary>
        /// The request path within the application's base path where the user-agent will be returned.
        /// The middleware will process this request when it arrives.
        /// Default value is "/signin-MailRu".
        /// </summary>
        public PathString CallbackPath { get; set; }

        /// <summary>
        /// Gets or sets the name of another authentication middleware which will be responsible for actually issuing a user <see cref="System.Security.Claims.ClaimsIdentity"/>.
        /// </summary>
        public string SignInAsAuthenticationType { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="IMailRuAuthenticationProvider"/> used to handle authentication events.
        /// </summary>
        public IMailRuAuthenticationProvider Provider { get; set; }

        /// <summary>
        /// Gets or sets the type used to secure data handled by the middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        /// <summary>
        /// Gets or sets the site redirect url after login 
        /// </summary>
        public string StoreState { get; set; }

        /// <summary>
        /// A list of permissions to request.
        /// Can be something like that "audio,video,pages" and etc. More info http://api.mail.ru/docs/guides/restapi/#permissions
        /// </summary>
        public string Scope { get; set; }
    }
}
