using Microsoft.AspNetCore.Mvc;

namespace Web_API.Controllers
{
    [ApiController]
    [Route("api")]
    public class HomeController : ControllerBase
    {
        // Root endpoint for connection checking
        [HttpGet]
        [HttpHead]
        public IActionResult Get()
        {
            return Ok(new { status = "API is running" });
        }
    }
} 