using System;
using System.IO;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Text;
using System.Net.Http;
using Newtonsoft.Json;

namespace SecurityAgent
{
    public class Program
    {
        private static FileSystemWatcher[] _fileWatchers;
        private static VirusTotalClient _virusTotalClient;
        private static IOCScanner _iocScanner;
        private static BackendService _backendService;
        private static ProcessMonitor _processMonitor;
        private static Configuration _config;
        private static readonly string ConfigFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config.json");
        private static bool _isRunning = true;
        private static string _lastMaliciousFile = null;
        private static string _lastDetectionInfo = null;
        private static readonly object _consoleLock = new object(); // Console output synchronization

        // Write to console with synchronization
        public static void WriteLine(string message)
        {
            lock (_consoleLock)
            {
                Console.WriteLine(message);
            }
        }

        // Write to console with color and synchronization
        public static void WriteLine(string message, ConsoleColor color)
        {
            lock (_consoleLock)
            {
                ConsoleColor prevColor = Console.ForegroundColor;
                Console.ForegroundColor = color;
                Console.WriteLine(message);
                Console.ForegroundColor = prevColor;
            }
        }

        public static async Task Main(string[] args)
        {
            Console.WriteLine("Security Agent starting...");
            
            // Initialize logging and quarantine
            LogManager.Initialize();
            QuarantineManager.Initialize();
            
            // Load configuration
            LoadConfiguration();
            
            // Initialize components
            InitializeComponents();
            
            // Initialize file system watchers
            InitializeFileSystemWatchers();

            // Start process monitoring if enabled
            if (_config.EnableProcessMonitoring)
            {
                _processMonitor.Start();
            }

            // Set alert mode based on configuration
            NotificationService.AlertsEnabled = _config.EnableAlerts;
            
            // Start a command processing thread
            var commandThread = new Thread(ProcessCommands);
            commandThread.IsBackground = true;
            commandThread.Start();
            
            // New: Task to poll scan queue
            Task.Run(() => PollScanQueue());
            
            // Keep the application running
            Console.WriteLine("Security Agent is now running. Type 'help' for available commands.");
            while (_isRunning)
            {
                await Task.Delay(1000);
            }

            // Clean up if process monitoring is active
            if (_config.EnableProcessMonitoring)
            {
                _processMonitor.Stop();
            }
        }

        private static void ProcessCommands()
        {
            Console.WriteLine("Type 'help' to see available commands");
            
            while (_isRunning)
            {
                // Show prompt on its own thread to ensure it's visible
                lock (_consoleLock)
                {
                    // Make the prompt clearly visible
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.Write("\n> ");
                    Console.ResetColor();
                    
                    // Flush to ensure prompt appears immediately
                    Console.Out.Flush();
                }
                
                // Read command input
                string command = Console.ReadLine()?.Trim().ToLower() ?? "";
                
                // Skip empty commands
                if (string.IsNullOrWhiteSpace(command))
                {
                    continue;
                }
                
                // Process command
                ProcessCommand(command);
            }
        }

        private static void ProcessCommand(string command)
        {
            switch (command)
            {
                case "help":
                    DisplayHelp();
                    break;
                    
                case "exit":
                case "quit":
                    _isRunning = false;
                    Console.WriteLine("Exiting...");
                    break;
                    
                case "status":
                    DisplayStatus();
                    break;
                    
                case "alert":
                    ToggleAlerts();
                    break;
                    
                case "monitor":
                    DisplayMonitoredDirectories();
                    break;
                    
                case "add":
                    Console.Write("Enter directory path to monitor: ");
                    var dir = Console.ReadLine();
                    AddMonitoringDirectory(dir);
                    break;
                    
                case "remove":
                    Console.Write("Enter directory path to stop monitoring: ");
                    var removeDir = Console.ReadLine();
                    RemoveMonitoringDirectory(removeDir);
                    break;
                    
                case "save":
                    SaveConfiguration();
                    break;
                    
                case "process":
                    ToggleProcessMonitoring();
                    break;
                    
                case "config":
                    DisplayConfiguration();
                    break;

                case "scan":
                    Console.Write("Enter file path to scan: ");
                    var filePath = Console.ReadLine();
                    if (!string.IsNullOrEmpty(filePath) && File.Exists(filePath))
                    {
                        Task.Run(() => AnalyzeFile(filePath));
                    }
                    else
                    {
                        Console.WriteLine("Invalid file path");
                    }
                    break;
                    
                case "delete":
                    HandleDeleteMaliciousFile();
                    break;
                    
                case "quarantine":
                    HandleQuarantineMaliciousFile();
                    break;

                case "logs":
                    DisplayRecentLogs();
                    break;
                    
                case "qlist":
                    DisplayQuarantinedFiles();
                    break;
                    
                case "restore":
                    HandleRestoreFromQuarantine();
                    break;
                    
                case "qstats":
                    DisplayQuarantineStats();
                    break;
                    
                case "qclean":
                    CleanupQuarantine();
                    break;
                    
                case "detailed":
                    DisplayDetailedLogs();
                    break;
                    
                case "clear":
                    Console.Clear();
                    Console.WriteLine("Type 'help' for available commands");
                    break;
                    
                default:
                    Console.WriteLine("Unknown command. Type 'help' for available commands.");
                    break;
            }
        }

        private static void DisplayHelp()
        {
            Console.WriteLine("\nAvailable commands:");
            Console.WriteLine("  help       - Display this help message");
            Console.WriteLine("  scan       - Scan a file for malware");
            Console.WriteLine("  delete     - Delete the last detected malicious file");
            Console.WriteLine("  quarantine - Move the last detected malicious file to quarantine");
            Console.WriteLine("  monitor    - Display monitored directories");
            Console.WriteLine("  add        - Add a directory to monitor");
            Console.WriteLine("  remove     - Remove a monitored directory");
            Console.WriteLine("  process    - Toggle process monitoring");
            Console.WriteLine("  alert      - Toggle alerts");
            Console.WriteLine("  status     - Display current status");
            Console.WriteLine("  config     - Display current configuration");
            Console.WriteLine("  save       - Save current configuration");
            Console.WriteLine("  logs       - Display recent scan logs");
            Console.WriteLine("  qlist      - List quarantined files");
            Console.WriteLine("  qstats     - Display quarantine statistics");
            Console.WriteLine("  restore    - Restore a file from quarantine");
            Console.WriteLine("  qclean     - Clean up old quarantined files");
            Console.WriteLine("  detailed   - Show detailed scan logs");
            Console.WriteLine("  exit/quit  - Exit the application");
            Console.WriteLine();
        }

        private static void DisplayConfiguration()
        {
            Console.WriteLine("\nCurrent Configuration:");
            Console.WriteLine($"  Monitoring Paths: {string.Join(", ", _config.MonitoringPaths)}");
            Console.WriteLine($"  Include Subdirectories: {_config.IncludeSubdirectories}");
            Console.WriteLine($"  Alerts Enabled: {_config.EnableAlerts}");
            Console.WriteLine($"  Process Monitoring: {_config.EnableProcessMonitoring}");
            Console.WriteLine($"  Auto-Terminate Malicious Processes: {_config.AutoTerminateMaliciousProcesses}");
            Console.WriteLine($"  Auto-Delete Malicious Files: {_config.AutoDeleteMaliciousFiles}");
            Console.WriteLine($"  VirusTotal Detection Threshold: {_config.VirusTotalDetectionThreshold}");
            Console.WriteLine();
        }

        private static void DisplayMonitoredDirectories()
        {
            Console.WriteLine("\nCurrently monitored directories:");
            for (int i = 0; i < _config.MonitoringPaths.Length; i++)
            {
                Console.WriteLine($"  {i+1}. {_config.MonitoringPaths[i]} (including subdirectories: {_config.IncludeSubdirectories})");
            }
            Console.WriteLine();
        }

        private static void AddMonitoringDirectory(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                Console.WriteLine("Invalid directory path");
                return;
            }
            
            if (!Directory.Exists(path))
            {
                Console.WriteLine($"Directory does not exist: {path}");
                return;
            }
            
            if (_config.MonitoringPaths.Contains(path))
            {
                Console.WriteLine($"Already monitoring: {path}");
                return;
            }
            
            // Add to configuration
            var newPaths = new List<string>(_config.MonitoringPaths) { path };
            _config.MonitoringPaths = newPaths.ToArray();
            
            // Create a new watcher
            var watcher = new FileSystemWatcher
            {
                Path = path,
                IncludeSubdirectories = _config.IncludeSubdirectories,
                EnableRaisingEvents = true
            };
            
            watcher.Created += OnFileCreated;
            watcher.Changed += OnFileChanged;
            watcher.Renamed += OnFileRenamed;
            
            // Add to watchers array
            var newWatchers = new List<FileSystemWatcher>();
            if (_fileWatchers != null)
            {
                newWatchers.AddRange(_fileWatchers);
            }
            newWatchers.Add(watcher);
            _fileWatchers = newWatchers.ToArray();
            
            Console.WriteLine($"Now monitoring: {path}");
        }

        private static void RemoveMonitoringDirectory(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || _fileWatchers == null)
            {
                return;
            }
            
            var pathList = new List<string>(_config.MonitoringPaths);
            if (!pathList.Remove(path))
            {
                Console.WriteLine($"Not monitoring: {path}");
                return;
            }
            
            _config.MonitoringPaths = pathList.ToArray();
            
            // Find and dispose the watcher for this path
            var watcherList = new List<FileSystemWatcher>();
            foreach (var watcher in _fileWatchers)
            {
                if (watcher.Path == path)
                {
                    watcher.EnableRaisingEvents = false;
                    watcher.Created -= OnFileCreated;
                    watcher.Changed -= OnFileChanged;
                    watcher.Renamed -= OnFileRenamed;
                    watcher.Dispose();
                }
                else
                {
                    watcherList.Add(watcher);
                }
            }
            
            _fileWatchers = watcherList.ToArray();
            Console.WriteLine($"Stopped monitoring: {path}");
        }

        private static void SaveConfiguration()
        {
            _config.SaveToFile(ConfigFilePath);
            Console.WriteLine($"Configuration saved to: {ConfigFilePath}");
        }

        private static void ToggleAlerts()
        {
            _config.EnableAlerts = !_config.EnableAlerts;
            NotificationService.AlertsEnabled = _config.EnableAlerts;
            Console.WriteLine($"Alerts {(_config.EnableAlerts ? "enabled" : "disabled")}");
        }

        private static void ToggleProcessMonitoring()
        {
            _config.EnableProcessMonitoring = !_config.EnableProcessMonitoring;
            
            if (_config.EnableProcessMonitoring)
            {
                _processMonitor.Start();
                Console.WriteLine("Process monitoring started");
            }
            else
            {
                _processMonitor.Stop();
                Console.WriteLine("Process monitoring stopped");
            }
        }

        private static void LoadConfiguration()
        {
            Console.WriteLine("Loading configuration...");
            _config = Configuration.LoadFromFile(ConfigFilePath);
            
            // Create default configuration file if it doesn't exist
            if (!File.Exists(ConfigFilePath))
            {
                _config.SaveToFile(ConfigFilePath);
                Console.WriteLine($"Created default configuration file at: {ConfigFilePath}");
            }
        }

        private static void InitializeComponents()
        {
            // Initialize VirusTotal client
            _virusTotalClient = new VirusTotalClient(_config.VirusTotalApiKey);
            
            // Initialize IOC scanner with additional patterns from config
            _iocScanner = new IOCScanner();
            if (_config.AdditionalSuspiciousPatterns != null && _config.AdditionalSuspiciousPatterns.Count > 0)
            {
                foreach (var pattern in _config.AdditionalSuspiciousPatterns)
                {
                    _iocScanner.AddSuspiciousPattern(pattern);
                }
            }
            
            // Initialize backend service
            _backendService = new BackendService(_config.BackendApiUrl);

            // Initialize process monitor
            _processMonitor = new ProcessMonitor(_iocScanner);
        }

        private static void InitializeFileSystemWatchers()
        {
            _fileWatchers = new FileSystemWatcher[_config.MonitoringPaths.Length];
            
            for (int i = 0; i < _config.MonitoringPaths.Length; i++)
            {
                var path = _config.MonitoringPaths[i];
                
                if (!Directory.Exists(path))
                {
                    Console.WriteLine($"Warning: Monitoring path does not exist: {path}");
                    continue;
                }
                
                _fileWatchers[i] = new FileSystemWatcher
                {
                    Path = path,
                    IncludeSubdirectories = _config.IncludeSubdirectories,
                    EnableRaisingEvents = true
                };

                _fileWatchers[i].Created += OnFileCreated;
                _fileWatchers[i].Changed += OnFileChanged;
                _fileWatchers[i].Renamed += OnFileRenamed;

                Console.WriteLine($"Monitoring directory: {path}");
            }
        }

        private static async void OnFileCreated(object sender, FileSystemEventArgs e)
        {
            if (ShouldMonitorFile(e.FullPath))
            {
                Console.WriteLine($"New file detected: {e.FullPath}");
                await AnalyzeFile(e.FullPath);
            }
        }

        private static async void OnFileChanged(object sender, FileSystemEventArgs e)
        {
            if (ShouldMonitorFile(e.FullPath))
            {
                Console.WriteLine($"File modified: {e.FullPath}");
                await AnalyzeFile(e.FullPath);
            }
        }

        private static async void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            if (ShouldMonitorFile(e.FullPath))
            {
                Console.WriteLine($"File renamed: {e.OldFullPath} -> {e.FullPath}");
                await AnalyzeFile(e.FullPath);
            }
        }

        private static bool ShouldMonitorFile(string filePath)
        {
            string extension = Path.GetExtension(filePath).ToLower();
            return Array.Exists(_config.MonitoredExtensions, ext => ext.ToLower() == extension);
        }

        private static async Task AnalyzeFile(string filePath)
        {
            try
            {
                // Wait a bit to ensure the file is fully written to disk
                await Task.Delay(1000);
                
                if (!File.Exists(filePath))
                {
                    Console.WriteLine($"File no longer exists: {filePath}");
                    return;
                }
                
                bool isMalicious = false;
                int detectionCount = 0;
                int totalScans = 0;
                var detectedPatterns = new List<string>();
                var detectedBy = new List<string>();
                StringBuilder detectionInfo = new StringBuilder();

                // Clear previous malicious file information
                _lastMaliciousFile = null;
                _lastDetectionInfo = null;

                // Perform IOC scan
                var iocResult = _iocScanner.ScanFile(filePath);
                if (iocResult.IsSuspicious)
                {
                    // Alert about suspicious file with clear warning
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"⚠️ SECURITY WARNING: Suspicious content detected in file: {filePath}");
                    Console.WriteLine("------------------------------------------------------------");
                    Console.ResetColor();
                    
                    Console.WriteLine("Detected suspicious patterns:");
                    foreach (var pattern in iocResult.DetectedPatterns)
                    {
                        Console.WriteLine($"- {pattern}");
                        detectedPatterns.Add(pattern);
                        detectionInfo.AppendLine($"- {pattern}");
                    }
                    
                    isMalicious = true;
                    
                    // IOC taraması için detection count ve total scans değerlerini ayarla
                    detectionCount = detectedPatterns.Count;
                    totalScans = 1; // Local scanner olarak sayılır
                    
                    // Offer action options to the user
                    Console.WriteLine("------------------------------------------------------------");
                    Console.WriteLine("RECOMMENDED ACTIONS:");
                    Console.WriteLine("1. Delete the file");
                    Console.WriteLine("2. Move the file to quarantine");
                    Console.WriteLine("3. Ignore the file (security risk!)");
                    
                    // Show notification for suspicious file
                    if (_config.EnableAlerts)
                    {
                        NotificationService.ShowSuspiciousFileNotification(filePath, detectionInfo.ToString());
                    }
                    
                    // Store the malicious file info for potential user action
                    _lastMaliciousFile = filePath;
                    _lastDetectionInfo = detectionInfo.ToString();
                }

                // Perform VirusTotal analysis
                var vtResult = await _virusTotalClient.AnalyzeFile(filePath);
                if (vtResult.IsMalicious)
                {
                    // Alert about malicious file
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"🔴 HIGH RISK ALERT: Malicious content detected in file: {filePath}");
                    Console.WriteLine("===============================================================");
                    Console.ResetColor();
                    
                    Console.WriteLine($"Detected by {vtResult.DetectionCount} out of {vtResult.TotalScans} antivirus engines");
                    
                    detectionCount = vtResult.DetectionCount;
                    totalScans = vtResult.TotalScans;
                    
                    if (vtResult.DetectedBy != null && vtResult.DetectedBy.Count > 0)
                    {
                        Console.WriteLine("\nDetections by antivirus engines:");
                        foreach (var detection in vtResult.DetectedBy)
                        {
                            Console.WriteLine($"- {detection.Key}: {detection.Value}");
                            detectedBy.Add($"{detection.Key}: {detection.Value}");
                            detectionInfo.AppendLine($"- {detection.Key}: {detection.Value}");
                        }
                    }
                    
                    isMalicious = true;
                    
                    // Store the malicious file info for potential user action
                    _lastMaliciousFile = filePath;
                    _lastDetectionInfo = detectionInfo.ToString();
                    
                    // Delete file if set in configuration and at least one detection
                    if (_config.AutoDeleteMaliciousFiles && detectionCount >= _config.VirusTotalDetectionThreshold)
                    {
                        if (NotificationService.DeleteFile(filePath))
                        {
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine("\n✓ SECURITY ACTION: Malicious file automatically deleted.");
                            Console.ResetColor();
                            
                            // Show notification for deleted malicious file
                            if (_config.EnableAlerts)
                            {
                                NotificationService.ShowMaliciousFileNotification(filePath, detectionInfo.ToString());
                            }
                        }
                    }
                    else
                    {
                        // Offer action options to the user
                        Console.WriteLine("\nSECURITY ACTIONS:");
                        Console.WriteLine("You can perform the following actions on this malicious file:");
                        Console.WriteLine("1. Type 'delete' to delete the file");
                        Console.WriteLine("2. Type 'quarantine' to move the file to quarantine");
                        Console.WriteLine("3. Do nothing (security risk!)");
                    }
                }
                else if (!string.IsNullOrEmpty(vtResult.Error))
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"VirusTotal analysis error: {vtResult.Error}");
                    Console.ResetColor();
                    Console.WriteLine("Continuing with local IOC scan for suspicious content.");
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"✓ SAFE: File {filePath} appears to be safe according to VirusTotal");
                    Console.ResetColor();
                    Console.WriteLine($"Scanned by {vtResult.TotalScans} antivirus engines, no threats detected");
                }

                // Send results to backend
                var scanResult = new ScanResultData
                {
                    FilePath = filePath,
                    ScanDate = DateTime.UtcNow,
                    IsMalicious = isMalicious,
                    DetectionCount = detectionCount,
                    TotalScans = totalScans,
                    DetectedBy = detectedBy,
                    DetectedPatterns = detectedPatterns
                };

                bool sentSuccessfully = await _backendService.SendScanResult(scanResult);
                if (sentSuccessfully)
                {
                    Console.WriteLine("Scan results sent to backend successfully.");
                }
                else
                {
                    Console.WriteLine("Failed to send scan results to backend.");
                }
                
                if (isMalicious)
                {
                    Console.WriteLine("\n===============================================================");
                    Console.WriteLine("NOTE: This file contains security risks. Use caution!");
                    Console.WriteLine("===============================================================");
                }

                // Log the scan result
                LogManager.LogScanResult(filePath, isMalicious, detectionCount, totalScans, detectionInfo.ToString());
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error analyzing file {filePath}: {ex.Message}");
                LogManager.LogScanResult(filePath, false, 0, 0, $"Error: {ex.Message}");
            }
        }

        private static void HandleDeleteMaliciousFile()
        {
            if (string.IsNullOrEmpty(_lastMaliciousFile))
            {
                Console.WriteLine("No malicious file currently available for action.");
                Console.WriteLine("Tip: First scan a file using the 'scan' command.");
                return;
            }
            
            if (!File.Exists(_lastMaliciousFile))
            {
                Console.WriteLine($"File no longer exists: {_lastMaliciousFile}");
                _lastMaliciousFile = null;
                _lastDetectionInfo = null;
                return;
            }
            
            try
            {
                File.Delete(_lastMaliciousFile);
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"✓ Malicious file successfully deleted: {_lastMaliciousFile}");
                Console.ResetColor();
                
                // Show notification
                if (_config.EnableAlerts)
                {
                    NotificationService.ShowMaliciousFileNotification(_lastMaliciousFile, _lastDetectionInfo);
                }
                
                _lastMaliciousFile = null;
                _lastDetectionInfo = null;
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Error deleting file: {ex.Message}");
                Console.ResetColor();
            }
        }

        private static void HandleQuarantineMaliciousFile()
        {
            if (string.IsNullOrEmpty(_lastMaliciousFile))
            {
                Console.WriteLine("No malicious file currently available for action.");
                Console.WriteLine("Tip: First scan a file using the 'scan' command.");
                return;
            }
            
            if (!File.Exists(_lastMaliciousFile))
            {
                Console.WriteLine($"File no longer exists: {_lastMaliciousFile}");
                _lastMaliciousFile = null;
                _lastDetectionInfo = null;
                return;
            }
            
            try
            {
                string quarantinePath = QuarantineManager.QuarantineFile(_lastMaliciousFile, _lastDetectionInfo);
                if (quarantinePath != null)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"✓ File moved to quarantine: {_lastMaliciousFile}");
                    Console.WriteLine($"  Quarantine location: {quarantinePath}");
                    Console.ResetColor();
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Failed to quarantine file.");
                    Console.ResetColor();
                }
                
                _lastMaliciousFile = null;
                _lastDetectionInfo = null;
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Error quarantining file: {ex.Message}");
                Console.ResetColor();
            }
        }

        private static void DisplayStatus()
        {
            Console.WriteLine("\nSecurity Agent Status:");
            Console.WriteLine($"  Process Monitoring: {(_processMonitor != null && _config.EnableProcessMonitoring ? "Active" : "Inactive")}");
            Console.WriteLine($"  Alerts: {(_config.EnableAlerts ? "Enabled" : "Disabled")}");
            Console.WriteLine($"  Auto-Delete Malicious Files: {(_config.AutoDeleteMaliciousFiles ? "Enabled" : "Disabled")}");
            Console.WriteLine($"  Monitored Directories: {_config.MonitoringPaths.Length}");
            Console.WriteLine($"  Monitored File Types: {string.Join(", ", _config.MonitoredExtensions)}");
            Console.WriteLine($"  Backend Connection: {(_backendService.IsConnected ? "Connected" : "Disconnected")}");
            Console.WriteLine();
        }

        private static async Task PollScanQueue()
        {
            while (_isRunning)
            {
                try
                {
                    using var client = new HttpClient();
                    var response = await client.GetAsync(_config.BackendApiUrl.Replace("/api", "/api/agent/pending-scans"));
                    if (response.IsSuccessStatusCode)
                    {
                        var content = await response.Content.ReadAsStringAsync();
                        var pendingScans = JsonConvert.DeserializeObject<List<ScanRequestModel>>(content);

                        foreach (var scan in pendingScans)
                        {
                            if (!string.IsNullOrEmpty(scan.Path) && File.Exists(scan.Path))
                            {
                                Console.WriteLine($"[API] Scan request received for: {scan.Path}");
                                await AnalyzeFile(scan.Path);

                                // Notify Web API to remove processed request
                                var removeContent = new StringContent(
                                    JsonConvert.SerializeObject(scan),
                                    Encoding.UTF8, "application/json");
                                await client.PostAsync(_config.BackendApiUrl.Replace("/api", "/api/agent/pending-scans/remove"), removeContent);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[API] Error polling scan queue: {ex.Message}");
                }

                await Task.Delay(5000); // Check every 5 seconds
            }
        }

        private static void DisplayRecentLogs()
        {
            Console.WriteLine("\nRecent Scan Logs:");
            var logs = LogManager.GetRecentScanLogs();
            foreach (var log in logs)
            {
                Console.WriteLine(log);
            }

            var stats = LogManager.GetStatistics();
            Console.WriteLine("\nScan Statistics:");
            foreach (var stat in stats)
            {
                Console.WriteLine($"{stat.Key}: {stat.Value}");
            }
            Console.WriteLine();
        }

        private static void DisplayDetailedLogs()
        {
            Console.WriteLine("\nDetailed Scan Logs:");
            var logs = LogManager.GetDetailedScanLogs();
            foreach (var log in logs)
            {
                Console.WriteLine($"=== Scan at {log.ScanTime:yyyy-MM-dd HH:mm:ss} ===");
                Console.WriteLine($"File: {log.FilePath}");
                Console.WriteLine($"Status: {(log.IsMalicious ? "MALICIOUS" : "CLEAN")}");
                Console.WriteLine($"Detections: {log.DetectionCount}/{log.TotalScans}");
                Console.WriteLine($"File Size: {FormatFileSize(log.FileSize)}");
                Console.WriteLine($"File Hash: {log.FileHash}");
                Console.WriteLine($"File Type: {log.FileType}");
                
                if (log.DetectedThreats.Count > 0)
                {
                    Console.WriteLine("Detected Threats:");
                    foreach (var threat in log.DetectedThreats)
                    {
                        Console.WriteLine($"  - {threat}");
                    }
                }
                
                if (log.ScannerResults.Count > 0)
                {
                    Console.WriteLine("Scanner Results:");
                    foreach (var result in log.ScannerResults)
                    {
                        Console.WriteLine($"  {result.Key}: {result.Value}");
                    }
                }
                
                Console.WriteLine("=====================================");
            }
        }

        private static string FormatFileSize(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            int order = 0;
            double size = bytes;
            while (size >= 1024 && order < sizes.Length - 1)
            {
                order++;
                size = size / 1024;
            }
            return $"{size:0.##} {sizes[order]}";
        }

        private static void DisplayQuarantineStats()
        {
            var stats = QuarantineManager.GetStatistics();
            Console.WriteLine("\nQuarantine Statistics:");
            Console.WriteLine($"Total Files Ever Quarantined: {stats.TotalQuarantinedFiles}");
            Console.WriteLine($"Currently Quarantined Files: {stats.ActiveQuarantinedFiles}");
            Console.WriteLine($"Restored Files: {stats.RestoredFiles}");
            Console.WriteLine($"Deleted Files: {stats.DeletedFiles}");
            Console.WriteLine($"Total Quarantine Size: {FormatFileSize(stats.TotalQuarantineSize)}");
            Console.WriteLine($"Last Updated: {stats.LastUpdated:yyyy-MM-dd HH:mm:ss}");
            
            if (stats.FileTypeStats.Count > 0)
            {
                Console.WriteLine("\nFile Type Distribution:");
                foreach (var type in stats.FileTypeStats.OrderByDescending(x => x.Value))
                {
                    Console.WriteLine($"  {type.Key}: {type.Value} files");
                }
            }
            
            Console.WriteLine();
        }

        private static void CleanupQuarantine()
        {
            Console.Write("Enter number of days to keep files (default 30): ");
            var input = Console.ReadLine();
            int days = 30;
            
            if (!string.IsNullOrEmpty(input) && int.TryParse(input, out int customDays))
            {
                days = customDays;
            }

            var beforeCount = QuarantineManager.GetQuarantinedFiles().Count;
            QuarantineManager.CleanupOldFiles(days);
            var afterCount = QuarantineManager.GetQuarantinedFiles().Count;
            var removedCount = beforeCount - afterCount;

            Console.WriteLine($"Cleanup complete. Removed {removedCount} files older than {days} days.");
        }

        private static void DisplayQuarantinedFiles()
        {
            Console.WriteLine("\nQuarantined Files:");
            var files = QuarantineManager.GetQuarantinedFiles();
            if (files.Count == 0)
            {
                Console.WriteLine("No files in quarantine.");
                return;
            }

            for (int i = 0; i < files.Count; i++)
            {
                var file = files[i];
                Console.WriteLine($"{i + 1}. {Path.GetFileName(file.OriginalPath)}");
                Console.WriteLine($"   Original Path: {file.OriginalPath}");
                Console.WriteLine($"   Quarantined On: {file.QuarantineDate}");
                Console.WriteLine($"   File Size: {FormatFileSize(file.FileSize)}");
                Console.WriteLine($"   File Type: {file.FileType}");
                Console.WriteLine($"   File Hash: {file.FileHash}");
                Console.WriteLine($"   Reason: {file.Reason}");
                if (file.DetectionCount > 0)
                {
                    Console.WriteLine($"   Detections: {file.DetectionCount}");
                }
                Console.WriteLine();
            }
        }

        private static void HandleRestoreFromQuarantine()
        {
            var files = QuarantineManager.GetQuarantinedFiles();
            if (files.Count == 0)
            {
                Console.WriteLine("No files in quarantine.");
                return;
            }

            DisplayQuarantinedFiles();
            Console.Write("Enter the number of the file to restore (or 0 to cancel): ");
            if (int.TryParse(Console.ReadLine(), out int choice) && choice > 0 && choice <= files.Count)
            {
                var file = files[choice - 1];
                if (QuarantineManager.RestoreFile(file.QuarantinePath))
                {
                    Console.WriteLine($"Successfully restored: {file.OriginalPath}");
                }
                else
                {
                    Console.WriteLine("Failed to restore file.");
                }
            }
        }

        // ScanRequestModel class
        public class ScanRequestModel
        {
            public string Path { get; set; }
        }
    }
}
