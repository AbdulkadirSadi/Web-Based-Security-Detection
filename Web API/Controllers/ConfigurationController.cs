using Microsoft.AspNetCore.Mvc;
using System;
using System.Threading.Tasks;
using Web_API.Models;

namespace Web_API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ConfigurationController : ControllerBase
    {
        private static ConfigurationModel _configuration = new ConfigurationModel
        {
            MonitoringPaths = new[] { Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) },
            MonitoredExtensions = new[] { ".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".wsh", ".msi" },
            IncludeSubdirectories = true,
            VirusTotalApiKey = "YOUR_VIRUSTOTAL_API_KEY", // Replace with your API key
            BackendApiUrl = "http://localhost:7260/api", // Default for local development
            AdditionalSuspiciousPatterns = new string[] { },
            EnableAlerts = true,
            EnableProcessMonitoring = true,
            AutoTerminateMaliciousProcesses = true,
            AutoDeleteMaliciousFiles = false,  // Safer default
            VirusTotalDetectionThreshold = 1
        };

        [HttpGet]
        public IActionResult GetConfiguration()
        {
            return Ok(_configuration);
        }

        [HttpPut]
        public IActionResult UpdateConfiguration([FromBody] ConfigurationModel configuration)
        {
            if (configuration == null)
            {
                return BadRequest("Invalid configuration data");
            }

            _configuration = configuration;
            return Ok(_configuration);
        }
    }
} 