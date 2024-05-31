using Microsoft.AspNetCore.Mvc;

namespace WebAPI.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class Diagnostics : ControllerBase
    {
        private const uint TIMEOUT = 5;
        private string m_postgres = string.Empty;
        private string m_keycloak = string.Empty;
        private string m_auth0 = string.Empty;

        /* need to use HttpClientFactory, this is only temporary */
        private static readonly HttpClient client = new HttpClient();

        public Diagnostics(IConfiguration config)
        {
            m_postgres = config["Settings:WebApi"]
                            + "/database";

            m_keycloak = config["Settings:WebApi"]
                            + "/keycloak";

            m_auth0 = config["Settings:WebApi"]
                            + "/auth0";
        }

        /* Test if Web API is up and running */
        [HttpGet("")]
        public async Task<IActionResult> IndexAsync()
        {
            var title = "Demo Web API\n";

            string postgresContent = await GetContentWithTimeout(client, m_postgres, "POSTGRES");
            string auth0Content = await GetContentWithTimeout(client, m_auth0, "AUTH0");
            string keycloakContent = await GetContentWithTimeout(client, m_keycloak, "KEYCLOAK");

            return Ok(title + postgresContent + auth0Content + keycloakContent);
        }

        private static async Task<string> GetContentWithTimeout(HttpClient client, string url, string service)
        {
            var timeoutTask = Task.Delay(TimeSpan.FromSeconds(TIMEOUT));
            var contentTask = client.GetAsync(url);

            var completedTask = await Task.WhenAny(timeoutTask, contentTask);

            if (completedTask == timeoutTask)
            {
                return $"\n{service}:\nSocket Timeout, took longer than expected!\n";
            }

            var response = await contentTask;

            return await response.Content.ReadAsStringAsync();
        }

    }
}