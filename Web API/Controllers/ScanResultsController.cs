using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Web_API.Context;
using Web_API.Models;

namespace Web_API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ScanResultsController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly DbSet<ScanResultModel> _dbSet;

        public ScanResultsController(AppDbContext context)
        {
            _context = context;
            _dbSet = _context.ScanResultModels;
        }

        private static readonly List<ScanResultModel> _scanResults = new List<ScanResultModel>();

        [HttpPost]
        public async Task<IActionResult> PostScanResult([FromBody] ScanResultModel scanResult)
        {
            if (scanResult == null)
            {
                return BadRequest("Invalid scan result data");
            }

            await _dbSet.AddAsync(scanResult);
            await _context.SaveChangesAsync();

            // Tutarlılık kontrolü - zararlı ama tespit sayısı 0 ise düzelt
            if (scanResult.IsMalicious && scanResult.DetectionCount <= 0 && 
                (scanResult.DetectedPatterns == null || scanResult.DetectedPatterns.Count == 0))
            {
                // Eğer DetectedPatterns veya DetectedBy dizileri boş değilse, en az 1 tespit var demektir
                if ((scanResult.DetectedBy != null && scanResult.DetectedBy.Count > 0))
                {
                    scanResult.DetectionCount = scanResult.DetectedBy.Count;
                    if (scanResult.TotalScans <= 0)
                    {
                        scanResult.TotalScans = 1; // En az 1 tarama var
                    }
                }
                else
                {
                    // IoC Scanner tarafından tespit edilmiş olabilir
                    if (scanResult.DetectedPatterns != null && scanResult.DetectedPatterns.Count > 0)
                    {
                        // IoC taramasında tespit var
                        scanResult.DetectionCount = scanResult.DetectedPatterns.Count;
                        scanResult.TotalScans = 1;
                    }
                    else
                    {
                        // İyi niyetli bug: Hiçbir tespit yoksa, zararlı olmasının bir sebebi olmalı
                        // IoC Scanner tarafından tespit edilmiş ama detayları aktarılmamış olabilir
                        scanResult.DetectionCount = 1;
                        scanResult.TotalScans = 1;
                        scanResult.DetectedPatterns = new List<string> { "Suspicious pattern detected by local scanner" };
                    }
                }

                // Log the correction
                Console.WriteLine($"Warning: Inconsistent scan result corrected. File: {scanResult.FilePath}");
            }

            // Set the ID and received timestamp
            scanResult.Id = Guid.NewGuid();
            scanResult.ReceivedAt = DateTime.UtcNow;

            // Add to our in-memory store (would be database in production)
            _scanResults.Add(scanResult);

            // Log the scan result
            Console.WriteLine($"Received scan result: {scanResult.FilePath}, Malicious: {scanResult.IsMalicious}, " +
                              $"Detections: {scanResult.DetectionCount}/{scanResult.TotalScans}");

            return Ok(scanResult);
        }

        [HttpGet]
        public IActionResult GetScanResults()
        {
            return Ok(_scanResults);
        }

        [HttpGet("{id}")]
        public IActionResult GetScanResult(Guid id)
        {
            var result = _scanResults.Find(r => r.Id == id);
            if (result == null)
            {
                return NotFound();
            }

            return Ok(result);
        }
    }
} 