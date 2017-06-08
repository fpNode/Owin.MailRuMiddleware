using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace fpNode.Owin.MailRuMiddleware.Provider
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class MailRuAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="MailRuAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="userjson">The JObject with user info</param>
        /// <param name="accessToken">Access token</param>
        /// <param name="expires">Seconds until expiration</param>
        public MailRuAuthenticatedContext(IOwinContext context, JObject userjson, string accessToken, string expires)
            : base(context)
        {
            UserJson = userjson;
            AccessToken = accessToken;

            int expiresValue;
            if (Int32.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }

            Id = TryGetValue("uid");
            Name = TryGetValue("first_name");
            LastName = TryGetValue("last_name");
            Nickname = TryGetValue("nick");
            Email = TryGetValue("email");
        }

        /// <summary>
        /// Gets the document with user info
        /// </summary>
        public JObject UserJson { get; private set; }

        /// <summary>
        /// Gets the access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the access token expiration time
        /// </summary>
        public TimeSpan? ExpiresIn { get; set; }

        /// <summary>
        /// Gets the user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the user's name
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Gets the user's last name
        /// </summary>
        public string LastName { get; private set; }

        /// <summary>
        /// Gets the user's full name
        /// </summary>
        public string FullName
        {
            get
            {
                return Name + " " + LastName;
            }
        }


        /// <summary>
        /// Gets the user's DefaultName
        /// </summary>
        public string DefaultName
        {
            get
            {
                if (!String.IsNullOrEmpty(Nickname))
                    return Nickname;

                return FullName;
            }
        }

         /// <summary>
        /// Gets the Nickname
        /// </summary>
        public string Nickname { get; private set; }

        /// <summary>
        /// Gets the Email
        /// </summary>
        public string Email { get; private set; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        private string TryGetValue(string propertyName)
        {
            JToken t;
            if (UserJson.TryGetValue(propertyName, out t))
            {
                return t.ToString();
            }
            return String.Empty;
        }
    }
}
