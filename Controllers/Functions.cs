using WebAPI.Models;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text;
using Microsoft.AspNetCore.Mvc;

namespace WebAPI.Controllers
{
    public class Functions : ControllerBase
    {
        public static string ToQueryString(IDictionary<string, string> dict)
        {
            var list = new List<string>();
            foreach (var kvp in dict)
            {
                list.Add($"{kvp.Key}={Uri.EscapeDataString(kvp.Value)}");
            }
            return "?" + string.Join("&", list);
        }

        #region Challenge

        public static string GenerateCodeVerifier()
        {
            byte[] verifier = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(verifier);
            }
            return Base64UrlEncode(verifier);
        }

        public static string GenerateCodeChallenge(string verifier)
        {
            byte[] verifierBytes = Encoding.UTF8.GetBytes(verifier);

            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(verifierBytes);
                return Base64UrlEncode(hash);
            }
        }

        public static string Base64UrlEncode(byte[] data)
        {
            string base64 = Convert.ToBase64String(data);
            return base64.TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        public static byte[] Base64UrlDecode(string input)
        {
            string padded = input.Length % 4 == 0 ? input : input + "====".Substring(input.Length % 4);
            string base64 = padded.Replace("_", "/").Replace("-", "+");
            return Convert.FromBase64String(base64);
        }
        public static string ConvertToGuid(string input)
        {
            Guid guid = Guid.Parse(input.Replace("-", "").ToLower());
            string output = guid.ToString();
            return output;
        }

        public class PKCEpair
        {
            public string? verifier { get; set; }
            public string? challenge { get; set; }
        }

        public static PKCEpair GetPKCEPair()
        {
            var verifier = GenerateCodeVerifier();
            var challenge = GenerateCodeChallenge(verifier);

            PKCEpair pKCEpair = new()
            {
                verifier = verifier,
                challenge = challenge
            };
            return pKCEpair;
        }

        #endregion

        #region Cookies

        public static string GetCookieChunks(HttpRequest request, string name)
        {
            StringBuilder fullContent = new();
            int partIndex = 0;

            while (true)
            {
                string chunkName = $"{name}_part{partIndex}";
                if (request.Cookies.TryGetValue(chunkName, out var chunkContent))
                {
                    fullContent.Append(chunkContent);
                    partIndex++;
                }
                else
                {
                    break;
                }
            }

            return fullContent.ToString();

        }

        public static string GetEndpointCookie(HttpRequest request)
        {
            System.Diagnostics.Debug.Print("GetEndpointCookie");

            return GetCookieChunks(request, "endpoint");
        }

        public static TokenParameters GetTokenCookie(HttpRequest request)
        {
            System.Diagnostics.Debug.Print("GetTokenCookie");

            var content = GetCookieChunks(request, "token_content");

            if (!string.IsNullOrEmpty(content))
            {
                System.Diagnostics.Debug.Print(content);

                /* Deserialize the JSON string */
                var jsonObject = JsonDocument.Parse(content).RootElement;

                /* Extract the content */
                TokenParameters tokenParams = JsonSerializer.Deserialize<TokenParameters>(jsonObject.GetRawText());

                System.Diagnostics.Debug.Print("----------------access token-----------------------");
                string encodedToken = tokenParams.access_token;
                var tokenParts = encodedToken.Split('.');
                var jwtPayload = Base64UrlDecode(tokenParts[1]);
                var payloadJson = Encoding.UTF8.GetString(jwtPayload);
                var payloadDocument = JsonDocument.Parse(payloadJson);
                foreach (JsonProperty property in payloadDocument.RootElement.EnumerateObject())
                {
                    string propertyName = property.Name;
                    JsonElement propertyValue = property.Value;
                    System.Diagnostics.Debug.Print($"{propertyName}: {propertyValue}");
                }

                System.Diagnostics.Debug.Print("----------------token-----------------------");
                string encodedToken1;
                if (tokenParams.refresh_token.Contains('.'))
                {
                    encodedToken1 = tokenParams.refresh_token;
                }
                else
                {
                    /* Extract data from the id token instead */
                    encodedToken1 = tokenParams.id_token;
                }
                var tokenParts1 = encodedToken1.Split('.');
                var jwtPayload1 = Base64UrlDecode(tokenParts1[1]);
                var payloadJson1 = Encoding.UTF8.GetString(jwtPayload1);
                var payloadDocument1 = JsonDocument.Parse(payloadJson1);
                foreach (JsonProperty property in payloadDocument1.RootElement.EnumerateObject())
                {
                    string propertyName = property.Name;
                    JsonElement propertyValue = property.Value;
                    System.Diagnostics.Debug.Print($"{propertyName}: {propertyValue}");
                }

                /* Extract data directly from token */
                tokenParams.expires_in = payloadDocument.RootElement.GetProperty("exp").GetInt32();
                tokenParams.scope = payloadDocument.RootElement.GetProperty("scope").GetString();
                tokenParams.session_state = payloadDocument.RootElement.GetProperty("sid").GetString();
                tokenParams.userId = payloadDocument.RootElement.GetProperty("sub").GetString();
                tokenParams.refresh_expires_in = payloadDocument1.RootElement.GetProperty("exp").GetInt32();

                return tokenParams;
            }
            return null;
        }

        public static string GetCodeCookie(HttpRequest request)
        {
            System.Diagnostics.Debug.Print("GetCodeCookie");

            return GetCookieChunks(request, "code");
        }

        public static void SetCookie(HttpResponse response, string name, string content)
        {
            System.Diagnostics.Debug.Print("SetCookie");

            int maxChunkSize = 2000;

            for (int i = 0; i < content.Length; i += maxChunkSize)
            {
                int chunkLength = Math.Min(maxChunkSize, content.Length - i);
                string chunkContent = content.Substring(i, chunkLength);

                string chunkName = $"{name}_part{i / maxChunkSize}";
                response.Cookies.Append(chunkName, chunkContent);
            }
        }

        public static void DeleteCookieChunks(HttpResponse response, string name)
        {
            for (int partIndex = 0; partIndex <= 5; partIndex++)
            {
                string chunkName = $"{name}_part{partIndex}";
                response.Cookies.Delete(chunkName);
            }
        }
        public static void ClearCookies(HttpResponse response)
        {
            System.Diagnostics.Debug.Print("ClearCookies");
            DeleteCookieChunks(response, "endpoint");
            DeleteCookieChunks(response, "code");
            DeleteCookieChunks(response, "token_content");
        }

        public static bool ValidToken(TokenParameters token)
        {
            long timeNow = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            System.Diagnostics.Debug.Print("Epoch Now: {0}", timeNow);
            if (token.refresh_expires_in - timeNow > 0)
            {
                System.Diagnostics.Debug.Print("Token valid for {0} seconds", token.refresh_expires_in - timeNow);
                return true;
            }
            else
            {
                System.Diagnostics.Debug.Print("Token expired");
                return false;
            }
        }

        public static bool ValidToken(string encodedToken)
        {
            var tokenParts = encodedToken.Split('.');
            var jwtPayload = Base64UrlDecode(tokenParts[1]);
            var payloadJson = Encoding.UTF8.GetString(jwtPayload);
            var payloadDocument = JsonDocument.Parse(payloadJson);
            var expires_in = payloadDocument.RootElement.GetProperty("exp").GetInt32();

            foreach (JsonProperty property in payloadDocument.RootElement.EnumerateObject())
            {
                string propertyName = property.Name;
                JsonElement propertyValue = property.Value;
                System.Diagnostics.Debug.Print($"{propertyName}: {propertyValue}");
            }

            long timeNow = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            System.Diagnostics.Debug.Print("Epoch Now: {0}", timeNow);
            if (expires_in - timeNow > 0)
            {
                System.Diagnostics.Debug.Print("Token valid for {0} seconds", expires_in - timeNow);
                return true;
            }
            else
            {
                System.Diagnostics.Debug.Print("Token expired");
                return false;
            }
        }

        #endregion

    }
}