using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;
using System;
using System.Net.Http.Headers;

namespace WebAPI.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class _Auth0Controller : ControllerBase
    {
        private string m_clientId = string.Empty;
        private string m_clientSecret = string.Empty;
        private string m_loginUri = string.Empty;
        private string m_logoutUri = string.Empty;
        private string m_requestAccessTokenUri = string.Empty;
        private string m_requestUserInfoUri = string.Empty;
        private string m_status = string.Empty;

        private string m_redirectUri = string.Empty;
        private string m_logoutApi = string.Empty;

        private const string m_contentTypeAppJson = @"application/json";
        private const string m_tokenTypeBearer = "Bearer";

        /* need to use HttpClientFactory, this is only temporary */
        private static readonly HttpClient client = new HttpClient();

        private static readonly string m_verifier = Functions.GenerateCodeVerifier();
        private static readonly string m_challenge = Functions.GenerateCodeChallenge(m_verifier);

        public _Auth0Controller(IConfiguration config)
        {
            m_clientId = config["Settings:IdentityServer:OAuth:ClientId_auth0"];

            m_clientSecret = config["Settings:IdentityServer:OAuth:ClientSecret_auth0"];

            m_loginUri = config["Settings:IdentityServer:Address:auth0"]
                            + "/authorize";

            m_logoutUri = config["Settings:IdentityServer:Address:auth0"]
                           + "/oidc/logout";

            m_logoutApi = config["Settings:WebApi"]
                        + "/_auth0/logout";

            m_requestAccessTokenUri = config["Settings:IdentityServer:Address:auth0"]
                            + "/oauth/token";

            m_requestUserInfoUri = config["Settings:IdentityServer:Address:auth0"]
                + "/userinfo";


            m_redirectUri = config["Settings:WebApi"]
                            + "/_auth0/callback";

            m_status = config["Settings:IdentityServer:Address:auth0"]
                            + "/.well-known/jwks.json";
        }

        /* Test if auth0 is up and running */
        [HttpGet("")]
        public async Task<IActionResult> Index()
        {
            try
            {
                var response = await client.GetAsync(m_status);
                var content = await response.Content.ReadAsStringAsync();

                if (response.IsSuccessStatusCode)
                {
                    return Ok("\n_auth0:\n" + content + "\n");
                }
                else
                {
                    return BadRequest("\n_auth0:\n" + content + "\n");
                }
            }
            catch (Exception ex)
            {
                return BadRequest("\n_auth0:\n" + ex.Message + "\n");
            }
        }

        [HttpGet("version")]
        public IActionResult VersionHandler()
        {
            System.Diagnostics.Debug.Print("VersionHandler _auth0");

            Functions.SetCookie(Response, "endpoint", "/_auth0/version");

            var address = "/_auth0/login" +
                "?uri=" + m_redirectUri +
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

                    return Ok("Version auht0 Auth\n\n" + tokenParams + "\n\ncode:" + code);
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
        public async Task<IActionResult> Login(string challenge, string uri)
        {
            System.Diagnostics.Debug.Print("LoginHandler _auth0");

            if (!string.IsNullOrWhiteSpace(uri))
            {
                var address = m_loginUri +
                          "?client_id=" + m_clientId +
                          "&response_type=code" +
                          "&redirect_uri=" + uri +
                          "&scope=openid%20profile%20email%20offline_access" +
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

        /* In the identity server, ensure you put http://<your-ip>:5053/_auth0/callback */
        /* This function is used to get the access token using the auth code */
        [HttpGet("callback")]
        public async Task<IActionResult> CallbackHandler(string code)
        {
            System.Diagnostics.Debug.Print("CallbackHandler auth0");
            System.Diagnostics.Debug.Print($"Authorization code: {code}");
            System.Diagnostics.Debug.Print($"Received code verifier: {m_verifier}");


            Functions.SetCookie(Response, "code", code);

            var requestBody = new Dictionary<string, string>
            {
                { "client_id", m_clientId },
                { "client_secret", m_clientSecret },
                { "code", code },
                { "grant_type", "authorization_code" },
                { "redirect_uri", m_redirectUri },
                { "code_verifier", m_verifier }
            };

            var response = await client.PostAsync(m_requestAccessTokenUri, new FormUrlEncodedContent(requestBody));

            if (!response.IsSuccessStatusCode)
            {
                System.Diagnostics.Debug.Print($"Failed to exchange code: {response.StatusCode}");
                return Ok($"Callback auth0 - Failed to exchange code: {response.StatusCode}");
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
        public async Task<IActionResult> GetAccessTokenViaRefreshToken()
        {
            System.Diagnostics.Debug.Print("GetAccessTokenViaRefreshToken auth0");

            var token = Functions.GetTokenCookie(Request);

            if (token != null)
            {
                var requestBody = new Dictionary<string, string>
                {
                    { "client_id", m_clientId },
                    { "client_secret", m_clientSecret },
                    { "grant_type", "refresh_token" },
                    { "refresh_token", token.refresh_token }
                };

                var response = await client.PostAsync(m_requestAccessTokenUri, new FormUrlEncodedContent(requestBody));
                var content = await response.Content.ReadAsStringAsync();

                if (!response.IsSuccessStatusCode)
                {
                    System.Diagnostics.Debug.Print($"Auth0 - RefreshToken - Failed to exchange code: {response.StatusCode}");
                    return Ok($"Auth0 - RefreshToken - Failed to exchange code: {response.StatusCode}");
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
                Functions.SetCookie(Response, "endpoint", "/_auth0/refreshtoken");
                var address = "/_auth0/login" +
                                "?uri=" + m_redirectUri +
                                 "&challenge=" + m_challenge;
                return Redirect(address);
            }
        }

        [HttpGet("userinfo")]
        public async Task<IActionResult> GetUserInfo()
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
                        Functions.SetCookie(Response, "endpoint", "/_auth0/userinfo");
                        var address = "/_auth0/login" +
                                      "?uri=" + m_redirectUri +
                                      "&challenge=" + m_challenge;
                        return Redirect(address);
                    }
                    if ((m_tokenTypeBearer == tokenType) && !string.IsNullOrWhiteSpace(accessToken))
                    {
                        using (var requestMessage = new HttpRequestMessage(HttpMethod.Post, m_requestUserInfoUri))
                        {
                            requestMessage.Headers.Authorization = new AuthenticationHeaderValue(m_tokenTypeBearer, accessToken);

                            var response = await client.SendAsync(requestMessage);
                            var content = await response.Content.ReadAsStringAsync();

                            if (!response.IsSuccessStatusCode)
                            {
                                System.Diagnostics.Debug.Print($"Failed to exchange code: {response.StatusCode}");
                                Functions.SetCookie(Response, "endpoint", "/_auth0/userinfo");
                                var address = "/_auth0/login" +
                                              "?uri=" + m_redirectUri +
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
        public async Task<IActionResult> Logout()
        {

            System.Diagnostics.Debug.Print("Logout _auth0");

            var token = Functions.GetTokenCookie(Request);
            if (token != null)
            {
                var address = m_loginUri +
                         "?id_token_hint=" + token.id_token;

                await client.GetAsync(address);

                await client.GetAsync(address);

                /* Clear after requestUri is set */
                Functions.ClearCookies(Response);
                
                var uri = m_logoutApi; /* Do not rename this, must match the var name in RedirectLogout */
                return RedirectToAction(nameof(RedirectLogout), new { uri });
            }
            else
            {
                return Ok("Auth0 - Successfully logged out");
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
