using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;
using System.Net.Http.Headers;

namespace WebAPI.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class _KeycloakController : ControllerBase
    {
        private string m_clientId_kc = string.Empty;
        private string m_clientSecret_kc = string.Empty;
        private string m_loginUri_kc = string.Empty;
        private string m_logoutUri_kc = string.Empty;
        private string m_requestAccessTokenUri_kc = string.Empty;
        private string m_requestUserInfoUri_kc = string.Empty;
        private string m_status_kc = string.Empty;

        private string m_redirectUri_kc = string.Empty;
        private string m_logoutApi_kc = string.Empty;

        private const string m_contentTypeAppJson = @"application/json";
        private const string m_tokenTypeBearer = "Bearer";

        /* need to use HttpClientFactory, this is only temporary */
        private static readonly HttpClient client = new HttpClient();

        private static readonly string m_verifier = Functions.GenerateCodeVerifier();
        private static readonly string m_challenge = Functions.GenerateCodeChallenge(m_verifier);

        public _KeycloakController(IConfiguration config)
        {
            m_clientId_kc = config["Settings:IdentityServer:OAuth:ClientId_keycloak"];

            m_clientSecret_kc = config["Settings:IdentityServer:OAuth:ClientSecret_keycloak"];

            m_loginUri_kc = config["Settings:IdentityServer:Address:Keycloak"]
                            + "/realms/" + config["Settings:IdentityServer:Address:RealmName_keycloak"]
                            + "/protocol/openid-connect/auth";

            m_logoutUri_kc = config["Settings:IdentityServer:Address:Keycloak"]
                            + "/realms/" + config["Settings:IdentityServer:Address:RealmName_keycloak"]
                            + "/protocol/openid-connect/logout";

            m_requestAccessTokenUri_kc = config["Settings:IdentityServer:Address:Keycloak"]
                            + "/realms/" + config["Settings:IdentityServer:Address:RealmName_keycloak"]
                            + "/protocol/openid-connect/token";

            m_requestUserInfoUri_kc = config["Settings:IdentityServer:Address:Keycloak"]
                            + "/realms/" + config["Settings:IdentityServer:Address:RealmName_keycloak"]
                            + "/protocol/openid-connect/userinfo";

            m_redirectUri_kc = config["Settings:WebApi"]
                            + "/_keycloak/callback";

            m_logoutApi_kc = config["Settings:WebApi"]
                            + "/_keycloak/logout";

            m_status_kc = config["Settings:IdentityServer:Address:Keycloak"]
                           + "/realms/" + config["Settings:IdentityServer:Address:RealmName_keycloak"];

        }

        /* Test if _Keycloak is up and running */
        [HttpGet("")]
        public async Task<IActionResult> Index()
        {
            try
            {
                var response = await client.GetAsync(m_status_kc);
                var content = await response.Content.ReadAsStringAsync();

                if (response.IsSuccessStatusCode)
                {
                    return Ok("\n_KEYCLOAK:\n" + content + "\n");
                }
                else
                {
                    return BadRequest("\n_KEYCLOAK:\n" + content + "\n");
                }
            }
            catch (Exception ex)
            {
                return BadRequest("\n_KEYCLOAK:\n" + ex.Message + "\n");
            }
        }

        [HttpGet("version")]
        public IActionResult VersionHandler_kc()
        {
            System.Diagnostics.Debug.Print("VersionHandler kc");

            Functions.SetCookie(Response, "endpoint", "/_keycloak/version");

            var address = "/_keycloak/login" +
                "?uri=" + m_redirectUri_kc +
                "&challenge=" + m_challenge;

            var token = Functions.GetTokenCookie(Request);
            var code = Functions.GetCodeCookie(Request);
            if (token != null)
            {
                if (Functions.ValidToken(token))
                {
                    var tokenParams =
                         "\n\naccess_token:" + token.access_token +
                         "\n\nexpires_in:" + token.expires_in +
                         "\n\nid_token:" + token.id_token +
                         "\n\nrefresh_token:" + token.refresh_token +
                         "\n\nrefresh_expires_in:" + token.refresh_expires_in +
                         "\n\ntoken_type:" + token.token_type +
                         "\n\nuserId:" + token.userId +
                         "\n\nsession_state:" + token.session_state +
                         "\n\nscope:" + token.scope;

                    return Ok("Version _keycloak Auth\n\n" + tokenParams + "\n\ncode:" + code);
                }
                else
                {
                    return Redirect(address);
                }
            }
            else
            {
                return Redirect(address);
            }
        }

        [HttpGet("login")]
        public IActionResult LoginHandler_kc(string challenge, string uri)
        {
            System.Diagnostics.Debug.Print("LoginHandler kc");

            if (!string.IsNullOrWhiteSpace(challenge) && !string.IsNullOrWhiteSpace(uri))
            {
                var address = m_loginUri_kc +
                          "?client_id=" + m_clientId_kc +
                          "&response_type=code" +
                          "&redirect_uri=" + uri +
                          "&scope=offline_access%20openid" +
                          "&state=" + "state" +
                          "&code_challenge=" + challenge +
                          "&code_challenge_method=S256";
                return Redirect(address);
            }
            else
            {
                string error;
                if (string.IsNullOrEmpty(challenge) && string.IsNullOrEmpty(uri))
                {
                    error = "{ \"error_description\": \"The login request requires a redirect uri and code challenge!\" }";
                }
                else if (string.IsNullOrEmpty(challenge))
                {
                    error = "{ \"error_description\": \"The login request requires a code challenge!\" }";
                }
                else
                {
                    error = "{ \"error_description\": \"The login request requires a redirect uri!\" }";
                }
                return BadRequest(error);
            }
        }

        /* In the identity server, ensure you put http://<your-ip>:5053/keycloak/callback */
        /* This function is used to get the access token using the auth code */
        [HttpGet("callback")]
        public async Task<IActionResult> CallbackHandler_kc(string code)
        {
            System.Diagnostics.Debug.Print("CallbackHandler kc");
            System.Diagnostics.Debug.Print($"Authorization code: {code}");
            System.Diagnostics.Debug.Print($"Received code verifier: {m_verifier}");

            Functions.SetCookie(Response, "code", code);

            var requestBody = new Dictionary<string, string>
            {
                { "client_id", m_clientId_kc },
                { "client_secret", m_clientSecret_kc },
                { "code", code },
                { "grant_type", "authorization_code" },
                { "redirect_uri", m_redirectUri_kc },
                { "code_verifier", m_verifier }
            };

            var response = await client.PostAsync(m_requestAccessTokenUri_kc, new FormUrlEncodedContent(requestBody));

            if (!response.IsSuccessStatusCode)
            {
                System.Diagnostics.Debug.Print($"Failed to exchange code: {response.StatusCode}");
                return Ok($"Callback_kc - Failed to exchange code: {response.StatusCode}");
            }

            var content = await response.Content.ReadAsStringAsync();
            Functions.SetCookie(Response, "token_content", content);

            var endpoint = Functions.GetEndpointCookie(Request);
            if (null == endpoint || string.Empty == endpoint)
            {
                return Ok("Endpoint error");
            }
            else
            {
                return Redirect(endpoint);
            }
        }

        /* Get access token using refresh token */
        [HttpGet("refreshtoken")]
        public async Task<IActionResult> GetAccessTokenViaRefreshToken_kc()
        {
            System.Diagnostics.Debug.Print("GetAccessTokenViaRefreshToken kc");

            var token = Functions.GetTokenCookie(Request);

            if (token != null)
            {
                var requestBody = new Dictionary<string, string>
                {
                    { "client_id", m_clientId_kc },
                    { "client_secret", m_clientSecret_kc },
                    { "grant_type", "refresh_token" },
                    { "refresh_token", token.refresh_token }
                };

                var response = await client.PostAsync(m_requestAccessTokenUri_kc, new FormUrlEncodedContent(requestBody));
                var content = await response.Content.ReadAsStringAsync();

                if (!response.IsSuccessStatusCode)
                {
                    System.Diagnostics.Debug.Print($"Kc - RefreshToken - Failed to exchange code: {response.StatusCode}");
                    return Ok($"Kc - RefreshToken - Failed to exchange code: {response.StatusCode}");
                }
                else
                {
                    return new ContentResult
                    {
                        Content = content,
                        ContentType = m_contentTypeAppJson
                    };
                }
            }
            else
            {
                Functions.SetCookie(Response, "endpoint", "/_keycloak/refreshtoken");
                var address = "/_keycloak/login" +
                                "?uri=" + m_redirectUri_kc +
                                 "&challenge=" + m_challenge;
                return Redirect(address);
            }
        }

        [HttpGet("userinfo")]
        public async Task<IActionResult> GetUserInfo_kc()
        {
            System.Diagnostics.Debug.Print("GetUserInfo kc");

            /* extract access token from authorization header */
            var authorization = Request.Headers[HeaderNames.Authorization];

            if (/*AuthenticationHeaderValue.TryParse(authorization, out var headerValue)*/true)
            {
                if (/*null != headerValue*/true)
                {
                    string? tokenType = m_tokenTypeBearer;   //headerValue.Scheme;
                    string? accessToken;
                    var token = Functions.GetTokenCookie(Request);
                    if (token != null)
                    {
                        accessToken = token.access_token;    //headerValue.Parameter;
                    }
                    else
                    {
                        Functions.SetCookie(Response, "endpoint", "/_keycloak/userinfo");
                        var address = "/_keycloak/login" +
                                      "?uri=" + m_redirectUri_kc +
                                      "&challenge=" + m_challenge;
                        return Redirect(address);
                    }
                    if ((m_tokenTypeBearer == tokenType) && !string.IsNullOrWhiteSpace(accessToken))
                    {
                        using (var requestMessage = new HttpRequestMessage(HttpMethod.Post, m_requestUserInfoUri_kc))
                        {
                            requestMessage.Headers.Authorization = new AuthenticationHeaderValue(m_tokenTypeBearer, accessToken);

                            var response = await client.SendAsync(requestMessage);
                            var content = await response.Content.ReadAsStringAsync();

                            if (!response.IsSuccessStatusCode)
                            {
                                System.Diagnostics.Debug.Print($"Failed to exchange code: {response.StatusCode}");
                                Functions.SetCookie(Response, "endpoint", "/_keycloak/userinfo");
                                var address = "/_keycloak/login" +
                                              "?uri=" + m_redirectUri_kc +
                                              "&challenge=" + m_challenge;
                                return Redirect(address);
                            }
                            else
                            {
                                return new ContentResult
                                {
                                    Content = content,
                                    ContentType = m_contentTypeAppJson
                                };
                            }
                        }
                    }
                    else
                    {
                        string error = "{ \"error_description\": \"Invalid token type or access token is NULL!\" }";
                        return BadRequest(error);
                    }
                }
                else
                {
                    string error = "{ \"error_description\": \"Authentication header values not found!\" }";
                    return BadRequest(error);
                }
            }
            else
            {
                string error = "{ \"error_description\": \"Authentication header values invalid!\" }";
                return BadRequest(error);
            }
        }

        [HttpGet("logout")]
        public async Task<IActionResult> Logout_kc()
        {
            System.Diagnostics.Debug.Print("Logout kc");

            var token = Functions.GetTokenCookie(Request);
            if (token != null)
            {
                var requestBody = new Dictionary<string, string>
                {
                                    { "client_id", m_clientId_kc },
                                    { "client_secret", m_clientSecret_kc },
                                    { "refresh_token", token.refresh_token }
                };

                await client.PostAsync(m_logoutUri_kc, new FormUrlEncodedContent(requestBody));

                /* Clear after requestUri is set */
                Functions.ClearCookies(Response);

                var uri = m_logoutApi_kc; /* Do not rename this, must match the var name in RedirectLogout */
                return RedirectToAction(nameof(RedirectLogout), new { uri });
            }
            else
            {
                return Ok("Keycloak - Successfully logged out");
            }
        }

        [HttpGet("redirect_logout")]
        public IActionResult RedirectLogout(string uri)
        {
            if (!string.IsNullOrWhiteSpace(uri))
            {
                string htmlContent = @"<!DOCTYPE html>
                            <html lang=""en"">
                            <head>
                                <title>Logging out</title>
                                <meta http-equiv=""Refresh"" content=""2; url={uri}"">
                                <style>
                                    body {
                                        font-size: 30px;
                                    }

                                    .loading-bar {
                                        width: 400px;
                                        height: 40px;
                                        background-color: #ccc;
                                        position: relative;
                                    }

                                    .loading-bar::after {
                                        content: """";
                                        display: block;
                                        width: 0;
                                        height: 100%;
                                        background-color: #007bff;
                                        animation: loadingAnimation 2s linear;
                                        position: absolute;
                                    }

                                    @keyframes loadingAnimation {
                                        0% { width: 0; }
                                        100% { width: 100%; }
                                    }
                                </style>
                            </head>
                            <body>
                                <h2 style=""font-size: 2em;"">Logging out...</h2>
                                <div class=""loading-bar""></div>
                            </body>
                            </html>";

                htmlContent = htmlContent.Replace("{uri}", uri);

                return Content(htmlContent, "text/html");
            }
            string error = "{ \"error_description\": \"Invalid redirect URI!\" }";
            return BadRequest(error);
        }

    }
}