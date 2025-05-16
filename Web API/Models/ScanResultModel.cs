using System;
using System.Collections.Generic;

namespace Web_API.Models
{
    public class ScanResultModel
    {
        public Guid Id { get; set; }
        public string FilePath { get; set; } = string.Empty;
        public DateTime ScanDate { get; set; }
        public DateTime ReceivedAt { get; set; }
        public bool IsMalicious { get; set; }
        public int DetectionCount { get; set; }
        public int TotalScans { get; set; }
        public List<string> DetectedBy { get; set; } = new List<string>();
        public List<string> DetectedPatterns { get; set; } = new List<string>();
    }
} 