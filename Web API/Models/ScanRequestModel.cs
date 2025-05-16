namespace Web_API.Models
{
    public class ScanRequestModel
    {
        public string Path { get; set; }
        public bool Recursive { get; set; } = true;
        public bool DeepScan { get; set; } = false;
    }
} 