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
            
            // Log controller initialization to help in debugging
            Console.WriteLine("ScanResultsController initialized");
        }

        private static readonly List<ScanResultModel> _scanResults = new List<ScanResultModel>();

        [HttpPost]
        public async Task<IActionResult> PostScanResult([FromBody] ScanResultModel scanResult)
        {
            Console.WriteLine("----- POST /api/ScanResults started -----");
            try
            {
                if (scanResult == null)
                {
                    Console.WriteLine("Error: Received null scan result");
                    return BadRequest("Invalid scan result data");
                }

                Console.WriteLine($"Received scan request for: {scanResult.FilePath}");
                Console.WriteLine($"Request data: Malicious={scanResult.IsMalicious}, Detections={scanResult.DetectionCount}/{scanResult.TotalScans}");

                // Set the ID and received timestamp
                scanResult.Id = Guid.NewGuid();
                scanResult.ReceivedAt = DateTime.UtcNow;

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

                // Add to in-memory store
                _scanResults.Add(scanResult);
                Console.WriteLine($"Added scan result to in-memory store. Count: {_scanResults.Count}");

                // Add to database with robust error handling
                try
                {
                    Console.WriteLine("Attempting to save to database");
                    await _dbSet.AddAsync(scanResult);
                    
                    Console.WriteLine("Calling SaveChangesAsync");
                    int rowsAffected = await _context.SaveChangesAsync();
                    
                    Console.WriteLine($"Database SaveChanges complete. Rows affected: {rowsAffected}");
                    Console.WriteLine($"Successfully saved scan result to database. ID: {scanResult.Id}");
                }
                catch (DbUpdateException dbEx)
                {
                    Console.WriteLine($"Database error when saving scan result: {dbEx.Message}");
                    Console.WriteLine($"Inner exception: {dbEx.InnerException?.Message}");
                    Console.WriteLine($"Stack trace: {dbEx.StackTrace}");
                    
                    // Still return OK since we have the data in memory
                    return Ok(new { 
                        Message = "Scan result stored in memory but not in database due to error", 
                        Result = scanResult,
                        Error = dbEx.Message
                    });
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error saving scan result to database: {ex.Message}");
                    Console.WriteLine($"Exception type: {ex.GetType().Name}");
                    Console.WriteLine($"Stack trace: {ex.StackTrace}");
                    
                    // Still return OK since we have the data in memory
                    return Ok(new { 
                        Message = "Scan result stored in memory but not in database due to error", 
                        Result = scanResult,
                        Error = ex.Message
                    });
                }

                // Log the scan result
                Console.WriteLine($"Processed scan result: {scanResult.FilePath}, Malicious: {scanResult.IsMalicious}, " +
                                $"Detections: {scanResult.DetectionCount}/{scanResult.TotalScans}");
                Console.WriteLine("----- POST /api/ScanResults completed successfully -----");
                
                return Ok(scanResult);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Unhandled exception in PostScanResult: {ex.Message}");
                Console.WriteLine($"Exception type: {ex.GetType().Name}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
                Console.WriteLine("----- POST /api/ScanResults failed -----");
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        [HttpGet]
        public IActionResult GetScanResults()
        {
            try
            {
                // Try to get from database first
                try
                {
                    var dbResults = _dbSet.ToList();
                    Console.WriteLine($"Retrieved {dbResults.Count} scan results from database");
                    return Ok(dbResults);
                }
                catch (Exception dbEx)
                {
                    Console.WriteLine($"Error retrieving from database, returning in-memory results: {dbEx.Message}");
                    // Fallback to in-memory results
                    return Ok(_scanResults);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Unhandled exception in GetScanResults: {ex.Message}");
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        [HttpGet("{id}")]
        public IActionResult GetScanResult(Guid id)
        {
            try
            {
                // Try database first
                try
                {
                    var dbResult = _dbSet.Find(id);
                    if (dbResult != null)
                    {
                        return Ok(dbResult);
                    }
                }
                catch (Exception dbEx)
                {
                    Console.WriteLine($"Error retrieving from database: {dbEx.Message}");
                }

                // Fallback to in-memory
                var result = _scanResults.Find(r => r.Id == id);
                if (result == null)
                {
                    return NotFound();
                }

                return Ok(result);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Unhandled exception in GetScanResult: {ex.Message}");
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }
    }
} 