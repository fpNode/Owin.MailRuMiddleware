MailRuMiddleware
===================

mvc 5 owin module for mail.ru

How to use?
-------------
1) Add nuget package - search for "fpNode.Owin.MailRuMiddleware"
2) Add module in Startup.Auth.cs of your mvc 5 project

app.UseMailRuAuthentication("{AppId}", "{AppSecret}", "{PERMISSIONS}");

{PERMISSIONS} - it is the comma-separated string.
More info here http://api.mail.ru/docs/guides/restapi/#permissions

How to register app in mail.ru?
-------------
Info here http://api.mail.ru/sites/my/add

Live examples 
-------------
 https://farpoint-nn.ru/
