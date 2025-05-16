using System;
using System.IO;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace SecurityAgent
{
    public class IOCScanner
    {
        private readonly List<string> _suspiciousPatterns = new List<string>
        {
            // Common malicious patterns
            @"powershell.*-enc",
            @"cmd.*/c",
            @"regsvr32.*/s.*/u.*scrobj\.dll",
            @"mshta.*javascript",
            @"certutil.*-decode",
            @"bitsadmin.*/transfer",
            @"wmic.*process.*call.*create",
            @"rundll32.*javascript",
            @"msiexec.*/i.*http",
            @"schtasks.*/create.*/sc.*minute"
        };

        private readonly List<string> _suspiciousExtensions = new List<string>
        {
            ".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".wsh", ".msi"
        };

        public void AddSuspiciousPattern(string pattern)
        {
            if (!string.IsNullOrWhiteSpace(pattern) && !_suspiciousPatterns.Contains(pattern))
            {
                _suspiciousPatterns.Add(pattern);
            }
        }

        public IOCScanResult ScanFile(string filePath)
        {
            try
            {
                var result = new IOCScanResult
                {
                    FilePath = filePath,
                    IsSuspicious = false,
                    DetectedPatterns = new List<string>()
                };

                // Check file extension
                string extension = Path.GetExtension(filePath).ToLower();
                if (_suspiciousExtensions.Contains(extension))
                {
                    result.IsSuspicious = true;
                    result.DetectedPatterns.Add($"Suspicious extension: {extension}");
                }

                // Read file content and check for suspicious patterns
                string content = File.ReadAllText(filePath);
                foreach (var pattern in _suspiciousPatterns)
                {
                    if (Regex.IsMatch(content, pattern, RegexOptions.IgnoreCase))
                    {
                        result.IsSuspicious = true;
                        result.DetectedPatterns.Add($"Detected pattern: {pattern}");
                    }
                }

                return result;
            }
            catch (Exception ex)
            {
                return new IOCScanResult
                {
                    FilePath = filePath,
                    IsSuspicious = false,
                    Error = ex.Message
                };
            }
        }
    }

    public class IOCScanResult
    {
        public string FilePath { get; set; }
        public bool IsSuspicious { get; set; }
        public List<string> DetectedPatterns { get; set; }
        public string Error { get; set; }
    }
} 