using System.Net.Http.Headers;
using Microsoft.AspNetCore.Mvc;
using WebAPI.Models;
using System.Text.Json;

namespace WebAPI.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class Auth0Controller : ControllerBase
    {
        private string m_clientId = string.Empty;
        private string m_clientSecret = string.Empty;
        private string m_loginUri = string.Empty;
        private string m_logoutUri = string.Empty;
        private string m_requestRevokeTokenUri = string.Empty;
        private string m_requestAccessTokenUri = string.Empty;
        private string m_requestUserInfoUri = string.Empty;
        private string m_redirectUri = string.Empty;
        private string m_status = string.Empty;

        private const string m_contentTypeAppJson = @"application/json";
        private const string m_tokenTypeBearer = "Bearer";
        private const string m_tokenTypeOffline = "Offline";

        /* need to use HttpClientFactory, this is only temporary */
        private static readonly HttpClient client = new HttpClient();

        private static readonly string m_verifier = Functions.GenerateCodeVerifier();
        private static readonly string m_challenge = Functions.GenerateCodeChallenge(m_verifier);

        public Auth0Controller(IConfiguration config)
        {
            m_clientId = config["Settings:IdentityServer:OAuth:ClientId_auth0"];

            m_clientSecret = config["Settings:IdentityServer:OAuth:ClientSecret_auth0"];

            m_loginUri = config["Settings:IdentityServer:Address:auth0"]
                            + "/authorize";

            m_logoutUri = config["Settings:IdentityServer:Address:auth0"]
                            + "/logout";

            m_requestRevokeTokenUri = config["Settings:IdentityServer:Address:auth0"]
                            + "/revoke";

            m_requestAccessTokenUri = config["Settings:IdentityServer:Address:auth0"]
                        + "/token";

            m_requestUserInfoUri = config["Settings:IdentityServer:Address:auth0"]
                            + "/userinfo";

            m_redirectUri = config["Settings:WebApi"]
                            + "/keycloak/callback";

            m_status = config["Settings:IdentityServer:Address:auth0"]
                            + "/status";
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
                    return Ok("\nauth0:\n" + content + "\n");
                }
                else
                {
                    return BadRequest("\nauth0:\n" + content + "\n");
                }
            }
            catch (Exception ex)
            {
                return BadRequest("\nauth0:\n" + ex.Message + "\n");
            }
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] AuthLoginParameters param)
        {
            string? challenge = param.challenge;
            string? redirectUri = param.uri;

            System.Diagnostics.Debug.Print("LoginHandler Auth0");

            if (!string.IsNullOrWhiteSpace(challenge) && !string.IsNullOrWhiteSpace(redirectUri))
            {
                string address = m_loginUri
                                 + @"?client_id=" + m_clientId
                                 + @"&response_type=code"
                                 + @"&redirect_uri=" + redirectUri
                                 + @"&scope=offline_access openid"
                                 + @"&code_challenge=" + challenge
                                 + @"&code_challenge_method=S256";

                return Redirect(address);
            }
            else
            {
                string error;
                if (string.IsNullOrEmpty(challenge) && string.IsNullOrEmpty(redirectUri))
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

        /* In the identity server, ensure you put http://<your-ip>:<your-port>/<Auth0/callback */
        [HttpGet("callback")]
        public async Task<IActionResult> CallbackHandler_kc(string code)
        {
            System.Diagnostics.Debug.Print("CallbackHandler kc");
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
                return Ok($"Callback - Failed to exchange code: {response.StatusCode}");
            }

            var content = await response.Content.ReadAsStringAsync();
            Functions.SetCookie(Response, "token_content", content);

            var endpoint = Functions.GetEndpointCookie(Request);
            if (endpoint == null)
            {
                return Ok("Endpoint error");
            }
            else
            {
                return Redirect(endpoint);
            }
        }

        [HttpPost("accesstoken")]
        public async Task<IActionResult> GetAccessToken([FromBody] AuthAccessTokenParameters param)
        {
            if (!string.IsNullOrWhiteSpace(param.uri))
            {
                string decodedUri = System.Uri.UnescapeDataString(param.uri);

                var requestBody = new Dictionary<string, string>
                {
                    { "client_id", m_clientId },
                    { "client_secret", m_clientSecret },
                    { "code", param.code },
                    { "grant_type", "authorization_code" },
                    { "redirect_uri", decodedUri },
                    { "code_verifier", param.verifier }
                };

                var response = await client.PostAsync(m_requestAccessTokenUri, new FormUrlEncodedContent(requestBody));
                var content = await response.Content.ReadAsStringAsync();

                if (response.IsSuccessStatusCode)
                {
                    return new ContentResult
                    {
                        Content = content,
                        ContentType = m_contentTypeAppJson
                    };
                }
                else
                {
                    return BadRequest(content);
                }
            }
            else
            {
                string error = "{ \"error_description\": \"The uri parameter cannot be NULL or empty!\" }";
                return BadRequest(error);
            }
        }

        /* Get access token using refresh token */
        [HttpGet("refreshtoken")]
        public async Task<IActionResult> GetAccessTokenViaRefreshToken([FromHeader(Name = "Authorization")] string authorization)
        {
            if (AuthenticationHeaderValue.TryParse(authorization, out var headerValue))
            {
                if (null != headerValue)
                {
                    string? tokenType = headerValue.Scheme;
                    string? token = headerValue.Parameter;

                    if ((m_tokenTypeOffline == tokenType) && !string.IsNullOrWhiteSpace(token))
                    {
                        if (Functions.ValidToken(token))
                        {
                            var requestBody = new Dictionary<string, string>
                            {
                                { "client_id", m_clientId },
                                { "client_secret", m_clientSecret },
                                { "grant_type", "refresh_token" },
                                { "refresh_token", token }
                            };

                            var response = await client.PostAsync(m_requestAccessTokenUri, new FormUrlEncodedContent(requestBody));
                            var content = await response.Content.ReadAsStringAsync();

                            /* Check received refresh token if it is usable */
                            var jsonObject = JsonDocument.Parse(content).RootElement;
                            TokenParameters tokenParams = JsonSerializer.Deserialize<TokenParameters>(jsonObject.GetRawText());
                            if (!string.IsNullOrWhiteSpace(tokenParams.refresh_token))
                            {
                                System.Diagnostics.Debug.Print("\nUsable refresh token for renewing access token.\n");
                                Functions.ValidToken(tokenParams.refresh_token);
                            }
                            else
                            {
                                System.Diagnostics.Debug.Print("\nUnusable refresh token for renewing access token! Either revoked or session no longer valid\n");
                            }

                            if (response.IsSuccessStatusCode)
                            {
                                return new ContentResult
                                {
                                    Content = content,
                                    ContentType = m_contentTypeAppJson
                                };
                            }
                            else
                            {
                                return BadRequest(content);
                            }
                        }
                        else
                        {
                            string error = "{ \"error_description\": \"Token has expired!\" }";
                            return BadRequest(error);
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

        [HttpGet("userinfo")]
        public async Task<IActionResult> GetUserInfo([FromHeader(Name = "Authorization")] string authorization)
        {
            if (AuthenticationHeaderValue.TryParse(authorization, out var headerValue))
            {
                if (null != headerValue)
                {
                    string? tokenType = headerValue.Scheme;
                    string? accessToken = headerValue.Parameter;

                    if ((m_tokenTypeBearer == tokenType) && !string.IsNullOrWhiteSpace(accessToken))
                    {
                        if (Functions.ValidToken(accessToken))
                        {
                            using var requestMessage = new HttpRequestMessage(HttpMethod.Post, m_requestUserInfoUri);
                            requestMessage.Headers.Authorization = new AuthenticationHeaderValue(m_tokenTypeBearer, accessToken);

                            var response = await client.SendAsync(requestMessage);
                            var content = await response.Content.ReadAsStringAsync();

                            if (response.IsSuccessStatusCode)
                            {
                                return new ContentResult
                                {
                                    Content = content,
                                    ContentType = m_contentTypeAppJson
                                };
                            }
                            else
                            {
                                return BadRequest(content);
                            }
                        }
                        else
                        {
                            string error = "{ \"error_description\": \"Token has expired!\" }";
                            return BadRequest(error);
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

        [HttpPost("logout")]
        public async Task<IActionResult> Logout([FromBody] AuthLogoutParameters param, [FromHeader(Name = "Authorization")] string authorization)
        {
            if (AuthenticationHeaderValue.TryParse(authorization, out var headerValue))
            {
                if (null != headerValue)
                {
                    string? tokenType = headerValue.Scheme;
                    string? refreshToken = headerValue.Parameter;

                    if ((m_tokenTypeOffline == tokenType) && !string.IsNullOrWhiteSpace(refreshToken) && !string.IsNullOrWhiteSpace(param.uri))
                    {
                        var requestBody = new Dictionary<string, string>
                        {
                                    { "client_id", m_clientId },
                                    { "client_secret", m_clientSecret },
                                    { "refresh_token", refreshToken }
                        };

                        /* ends user session */
                        await client.PostAsync(m_logoutUri, new FormUrlEncodedContent(requestBody));

                        /* explicitly revokes token, as the user could have clicked remember me */
                        await client.PostAsync(m_requestRevokeTokenUri, new FormUrlEncodedContent(requestBody));

                        return RedirectToAction(nameof(RedirectLogout), new { param.uri });
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