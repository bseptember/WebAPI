using Microsoft.AspNetCore.Mvc;
using WebAPI.Models;

namespace WebAPI.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly string m_authtype;

        private readonly Auth0Controller m_Auth0Controller;
        private readonly KeycloakController m_keycloakController;

        public AuthController(IConfiguration config, Auth0Controller Auth0Controller, KeycloakController keycloakController)
        {
            m_authtype = config["Settings:IdentityServer:Type"];
            m_Auth0Controller = Auth0Controller;
            m_keycloakController = keycloakController;
        }

        [HttpGet("")]
        public async Task<IActionResult> Index()
        {
            if (m_authtype == "keycloak")
            {
                return await m_keycloakController.Index();
            }
            else if (m_authtype == "auth0")
            {
                return await m_Auth0Controller.Index();
            }
            else
            {
                return BadRequest("Invalid authentication type.");
            }
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] AuthLoginParameters param)
        {
            if (m_authtype == "keycloak")
            {
                return m_keycloakController.Login(param);
            }
            else if (m_authtype == "auth0")
            {
                return m_Auth0Controller.Login(param);
            }
            else
            {
                return BadRequest("Invalid authentication type.");
            }
        }

        [HttpPost("accesstoken")]
        public async Task<IActionResult> GetAccessToken([FromBody] AuthAccessTokenParameters param)
         {
           if (m_authtype == "keycloak")
            {
                return await m_keycloakController.GetAccessToken(param);
            }
            else if (m_authtype == "auth0")
            {
                return await m_Auth0Controller.GetAccessToken(param);
            }
            else
            {
                return BadRequest("Invalid authentication type.");
            }
        }

        [HttpGet("refreshtoken")]
        public async Task<IActionResult> GetAccessTokenViaRefreshToken([FromHeader(Name = "Authorization")] string authorization)
        {
            if (m_authtype == "keycloak")
            {
                return await m_keycloakController.GetAccessTokenViaRefreshToken(authorization);
            }
            else if (m_authtype == "auth0")
            {
               return await m_Auth0Controller.GetAccessTokenViaRefreshToken(authorization);
            }
            else
            {
                return BadRequest("Invalid authentication type.");
            }
        }

        [HttpGet("userinfo")]
        public async Task<IActionResult> GetUserInfo([FromHeader(Name = "Authorization")] string authorization)
        {
            if (m_authtype == "keycloak")
            {
                return await m_keycloakController.GetUserInfo(authorization);
            }
            else if (m_authtype == "auth0")
            {
                return await m_Auth0Controller.GetUserInfo(authorization);
            }
            else
            {
                return BadRequest("Invalid authentication type.");
            }
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout([FromBody] AuthLogoutParameters param, [FromHeader(Name = "Authorization")] string authorization)
        {
            if (m_authtype == "keycloak")
            {
                return await m_keycloakController.Logout(param, authorization);
            }
            else if (m_authtype == "auth0")
            {
                return await m_Auth0Controller.Logout(param, authorization);
            }
            else
            {
                return BadRequest("Invalid authentication type.");
            }
        }

        [HttpGet("redirect_logout")]
        public IActionResult RedirectLogout(string uri)
        {
            if (m_authtype == "keycloak")
            {
                return m_keycloakController.RedirectLogout(uri);
            }
            else if (m_authtype == "auth0")
            {
                return m_Auth0Controller.RedirectLogout(uri);
            }
            else
            {
                return BadRequest("Invalid authentication type.");
            }
        }

    }
}