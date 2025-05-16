using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Web_API.Models;
using System.Collections.Concurrent;

namespace Web_API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AgentController : ControllerBase
    {
        // Thread-safe queue to store scan requests
        private static readonly ConcurrentQueue<ScanRequestModel> _pendingScans = new();

        [HttpPost("scan")]
        public IActionResult TriggerScan([FromBody] ScanRequestModel request)
        {
            if (request == null || string.IsNullOrEmpty(request.Path))
            {
                return BadRequest("Invalid scan request data");
            }

            // Add to queue
            _pendingScans.Enqueue(request);

            return Ok(new
            {
                message = $"Scan queued for path: {request.Path}",
                scanId = Guid.NewGuid(),
                timestamp = DateTime.UtcNow
            });
        }

        [HttpGet("status")]
        public IActionResult GetAgentStatus()
        {
            // In a real implementation, this would get actual status from agents
            return Ok(new
            {
                status = "Online",
                lastCheckin = DateTime.UtcNow,
                version = "1.0.0",
                activeScans = 0
            });
        }

        // New endpoint: Returns pending scan requests
        [HttpGet("pending-scans")]
        public IActionResult GetPendingScans()
        {
            var scans = _pendingScans.ToArray();
            return Ok(scans);
        }

        // New endpoint: Removes a scan request from the queue (marks as processed)
        [HttpPost("pending-scans/remove")]
        public IActionResult RemovePendingScan([FromBody] ScanRequestModel request)
        {
            // Create a new queue without the processed request
            var newQueue = new ConcurrentQueue<ScanRequestModel>(_pendingScans.Where(x => x.Path != request.Path));
            while (_pendingScans.TryDequeue(out _)) { }
            foreach (var item in newQueue) _pendingScans.Enqueue(item);

            return Ok();
        }
    }
} 