using WebAPI.Models;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http.Headers;
using System.Text.Json;

namespace WebAPI.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class KeycloakController : ControllerBase
    {
        private string m_clientId_kc = string.Empty;
        private string m_clientSecret_kc = string.Empty;
        private string m_loginUri_kc = string.Empty;
        private string m_logoutUri_kc = string.Empty;
        private string m_requestAccessTokenUri_kc = string.Empty;
        private string m_requestUserInfoUri_kc = string.Empty;
        private string m_status_kc = string.Empty;

        private const string m_contentTypeAppJson = @"application/json";
        private const string m_tokenTypeBearer = "Bearer";
        private const string m_tokenTypeOffline = "Offline";

        /* need to use HttpClientFactory, this is only temporary */
        private static readonly HttpClient client = new HttpClient();

        public KeycloakController(IConfiguration config)
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

            m_status_kc = config["Settings:IdentityServer:Address:Keycloak"]
                            + "/realms/" + config["Settings:IdentityServer:Address:RealmName_keycloak"];
        }

        /* Test if Keycloak is up and running */
        [HttpGet("")]
        public async Task<IActionResult> Index()
        {
            try
            {
                var response = await client.GetAsync(m_status_kc);
                var content = await response.Content.ReadAsStringAsync();

                if (response.IsSuccessStatusCode)
                {
                    return Ok("\nKEYCLOAK:\n" + content + "\n");
                }
                else
                {
                    return BadRequest("\nKEYCLOAK:\n" + content + "\n");
                }
            }
            catch (Exception ex)
            {
                return BadRequest("\nKEYCLOAK:\n" + ex.Message + " " + ex.InnerException.Message + "\n");
            }
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] AuthLoginParameters param)
        {
            string? challenge = param.challenge;
            string? redirectUri = param.uri;

            if (!string.IsNullOrWhiteSpace(challenge) && !string.IsNullOrWhiteSpace(redirectUri))
            {
                string address = m_loginUri_kc
                    + @"?client_id=" + m_clientId_kc
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

        [HttpPost("accesstoken")]
        public async Task<IActionResult> GetAccessToken([FromBody] AuthAccessTokenParameters param)
        {
            if (!string.IsNullOrWhiteSpace(param.uri))
            {
                string decodedUri = System.Uri.UnescapeDataString(param.uri);

                var requestBody = new Dictionary<string, string>
                {
                    { "client_id", m_clientId_kc },
                    { "client_secret", m_clientSecret_kc },
                    { "code", param.code },
                    { "grant_type", "authorization_code" },
                    { "redirect_uri", decodedUri },
                    { "code_verifier", param.verifier }
                };

                var response = await client.PostAsync(m_requestAccessTokenUri_kc, new FormUrlEncodedContent(requestBody));
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
                                { "client_id", m_clientId_kc },
                                { "client_secret", m_clientSecret_kc },
                                { "grant_type", "refresh_token" },
                                { "refresh_token", token }
                            };

                            var response = await client.PostAsync(m_requestAccessTokenUri_kc, new FormUrlEncodedContent(requestBody));
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
                            using var requestMessage = new HttpRequestMessage(HttpMethod.Post, m_requestUserInfoUri_kc);
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
                                    { "client_id", m_clientId_kc },
                                    { "client_secret", m_clientSecret_kc },
                                    { "refresh_token", refreshToken }
                        };

                        /* ends user session */
                        await client.PostAsync(m_logoutUri_kc, new FormUrlEncodedContent(requestBody));
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