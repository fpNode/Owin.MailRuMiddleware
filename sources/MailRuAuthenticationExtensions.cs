using System;
using fpNode.Owin.MailRuMiddleware;
using Microsoft.Owin.Security;

namespace Owin
{
    /// <summary>
    /// Extension methods for using <see cref="MailRuAuthenticationMiddleware"/>
    /// </summary>
    public static class MailRuAuthenticationExtensions
    {
        /// <summary>
        /// Authenticate users using MailRu
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="options">Middleware configuration options</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseMailRuAuthentication(this IAppBuilder app, MailRuAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(MailRuAuthenticationMiddleware), app, options);
            return app;
        }

        /// <summary>
        /// Authenticate users using MailRu
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="appId">The appId assigned by MailRu</param>
        /// <param name="appSecret">The appSecret assigned by MailRu</param>
        /// <param name="scope">The permissions list. Comma separated. Like "audio,video,photos"</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseMailRuAuthentication(
            this IAppBuilder app,
            string appId,
            string appSecret,
            string scope)
        {
            return UseMailRuAuthentication(
                app,
                new MailRuAuthenticationOptions
                {
                    AppId = appId,
                    AppSecret = appSecret,
                    Scope = scope
                });
        }
    }
}
