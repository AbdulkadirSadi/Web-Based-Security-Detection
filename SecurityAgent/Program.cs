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
        private static FileSystemWatcher[]? _fileWatchers;
        private static VirusTotalClient? _virusTotalClient;
        private static IOCScanner? _iocScanner;
        private static BackendService? _backendService;
        private static ProcessMonitor? _processMonitor;
        private static Configuration? _config;
        private static readonly string ConfigFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config.json");
        private static bool _isRunning = true;
        private static string? _lastMaliciousFile = null;
        private static string? _lastDetectionInfo = null;
        private static readonly object _consoleLock = new object(); // Console output synchronization
        private static Dictionary<string, DateTime> _recentlyScannedFiles = new Dictionary<string, DateTime>();
        private static readonly TimeSpan _scanCooldown = TimeSpan.FromMinutes(5);

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
            
            // Check if command line arguments are provided
            if (args.Length > 0)
            {
                await ProcessCommandLineArguments(args);
                return; // Exit after processing command line arguments
            }
            
            // Start a command processing thread for interactive mode
            var commandThread = new Thread(ProcessCommands);
            commandThread.IsBackground = true;
            commandThread.Start();
            
            // New: Task to poll scan queue
            Task _ = Task.Run(() => PollScanQueue());
            
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
        
        private static async Task ProcessCommandLineArguments(string[] args)
        {
            if (args.Length == 0) return;
            
            string command = args[0].ToLower();
            if (command.StartsWith("--"))
            {
                command = command.Substring(2); // Remove leading --
            }
            else if (command.StartsWith("-"))
            {
                command = command.Substring(1); // Remove leading -
            }
            
            string parameter = args.Length > 1 ? args[1] : "";
            
            switch (command)
            {
                case "help":
                    DisplayHelp();
                    break;
                    
                case "scan":
                    if (!string.IsNullOrEmpty(parameter) && File.Exists(parameter))
                    {
                        Console.WriteLine($"Scanning file: {parameter}");
                        await AnalyzeFile(parameter);
                    }
                    else
                    {
                        Console.WriteLine("Invalid file path or file does not exist.");
                        Console.WriteLine("Usage: SecurityAgent --scan <file_path>");
                    }
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
                    if (!string.IsNullOrEmpty(parameter))
                    {
                        AddMonitoringDirectory(parameter);
                    }
                    else
                    {
                        Console.WriteLine("Missing directory path.");
                        Console.WriteLine("Usage: SecurityAgent --add <directory_path>");
                    }
                    break;
                    
                case "remove":
                    if (!string.IsNullOrEmpty(parameter))
                    {
                        RemoveMonitoringDirectory(parameter);
                    }
                    else
                    {
                        Console.WriteLine("Missing directory path.");
                        Console.WriteLine("Usage: SecurityAgent --remove <directory_path>");
                    }
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
                
                case "logs":
                    DisplayRecentLogs();
                    break;
                    
                case "qlist":
                    DisplayQuarantinedFiles();
                    break;
                    
                case "qstats":
                    DisplayQuarantineStats();
                    break;
                    
                case "restore":
                    if (!string.IsNullOrEmpty(parameter))
                    {
                        QuarantineManager.RestoreFile(parameter);
                        Console.WriteLine($"Restored file: {parameter}");
                    }
                    else
                    {
                        Console.WriteLine("Missing file ID.");
                        Console.WriteLine("Usage: SecurityAgent --restore <file_id>");
                        DisplayQuarantinedFiles();
                    }
                    break;
                    
                case "qclean":
                    CleanupQuarantine();
                    break;
                    
                case "detailed":
                    DisplayDetailedLogs();
                    break;
                    
                default:
                    Console.WriteLine($"Unknown command: {command}");
                    DisplayHelp();
                    break;
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

                // Kullanıcı girişini al
                string commandLine = "";
                
                // Özel bir okuma rutini ile kullanıcı girişini koruyarak al
                lock (_consoleLock)
                {
                    var keyList = new List<ConsoleKeyInfo>();
                    ConsoleKeyInfo key;
                    do
                    {
                        key = Console.ReadKey(true); // Tuş basışını ekranda gösterme
                        
                        if (key.Key == ConsoleKey.Backspace)
                        {
                            if (keyList.Count > 0)
                            {
                                keyList.RemoveAt(keyList.Count - 1);
                                Console.Write("\b \b"); // Karakteri silmek için geri git, boşluk yaz, tekrar geri git
                            }
                        }
                        else if (key.Key == ConsoleKey.Enter)
                        {
                            Console.WriteLine(); // Yeni satıra geç
                        }
                        else if (!char.IsControl(key.KeyChar))
                        {
                            keyList.Add(key);
                            Console.Write(key.KeyChar); // Karakteri ekrana yaz
                        }
                        
                    } while (key.Key != ConsoleKey.Enter);
                    
                    // Girişi string'e dönüştür
                    commandLine = new string(keyList.Select(k => k.KeyChar).ToArray()).Trim();
                }
                
                // Skip empty commands
                if (string.IsNullOrWhiteSpace(commandLine))
                {
                    continue;
                }
                
                // Parse command and parameters
                string[] parts = commandLine.Split(' ', 2);
                string command = parts[0].ToLower();
                string parameter = parts.Length > 1 ? parts[1] : "";

                // Process command
                ProcessCommand(command, parameter);
            }
        }

        private static void ProcessCommand(string command, string parameter = "")
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
                    if (!string.IsNullOrEmpty(parameter))
                    {
                        AddMonitoringDirectory(parameter);
                    }
                    else
                    {
                        Console.Write("Enter directory path to monitor: ");
                        string? dir = Console.ReadLine();
                        if (!string.IsNullOrEmpty(dir))
                        {
                            AddMonitoringDirectory(dir);
                        }
                        else
                        {
                            Console.WriteLine("Invalid directory path.");
                        }
                    }
                    break;
                    
                case "remove":
                    if (!string.IsNullOrEmpty(parameter))
                    {
                        RemoveMonitoringDirectory(parameter);
                    }
                    else
                    {
                        Console.Write("Enter directory path to stop monitoring: ");
                        string? removeDir = Console.ReadLine();
                         if (!string.IsNullOrEmpty(removeDir))
                        {
                            RemoveMonitoringDirectory(removeDir);
                        }
                        else
                        {
                            Console.WriteLine("Invalid directory path.");
                        }
                    }
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
                    if (!string.IsNullOrEmpty(parameter) && File.Exists(parameter))
                    {
                        Task.Run(() => AnalyzeFile(parameter));
                    }
                    else
                    {
                        Console.Write("Enter file path to scan: ");
                        string filePath = Console.ReadLine();
                        if (!string.IsNullOrEmpty(filePath) && File.Exists(filePath))
                        {
                            Task.Run(() => AnalyzeFile(filePath));
                        }
                        else
                        {
                            Console.WriteLine("Invalid file path");
                        }
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
                    if (!string.IsNullOrEmpty(parameter))
                    {
                        QuarantineManager.RestoreFile(parameter);
                        Console.WriteLine($"Restored file: {parameter}");
                    }
                    else
                    {
                        HandleRestoreFromQuarantine();
                    }
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
            
            Console.WriteLine("Command-line usage:");
            Console.WriteLine("  SecurityAgent --help                    - Display help information");
            Console.WriteLine("  SecurityAgent --scan <file_path>        - Scan a specific file");
            Console.WriteLine("  SecurityAgent --add <directory_path>    - Add a directory to monitor");
            Console.WriteLine("  SecurityAgent --remove <directory_path> - Remove a monitored directory");
            Console.WriteLine("  SecurityAgent --monitor                 - List monitored directories");
            Console.WriteLine("  SecurityAgent --status                  - Display agent status");
            Console.WriteLine("  SecurityAgent --config                  - Show current configuration");
            Console.WriteLine("  SecurityAgent --logs                    - Display recent logs");
            Console.WriteLine("  SecurityAgent --detailed                - Display detailed logs");
            Console.WriteLine("  SecurityAgent --qlist                   - List quarantined files");
            Console.WriteLine("  SecurityAgent --qstats                  - Show quarantine statistics");
            Console.WriteLine("  SecurityAgent --qclean                  - Clean old quarantine files");
            Console.WriteLine("  SecurityAgent --restore <file_id>       - Restore file from quarantine");
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
                // Check if file was recently scanned
                if (_recentlyScannedFiles.TryGetValue(filePath, out DateTime lastScan))
                {
                    if (DateTime.Now - lastScan < _scanCooldown)
                    {
                        Console.WriteLine($"File {filePath} was recently scanned. Skipping duplicate scan.");
                        return;
                    }
                }

                // Wait a bit to ensure the file is fully written to disk
                await Task.Delay(1000);
                
                if (!File.Exists(filePath))
                {
                    Console.WriteLine($"File no longer exists: {filePath}");
                    return;
                }

                // Update last scan time
                _recentlyScannedFiles[filePath] = DateTime.Now;

                // Clean up old entries
                var oldEntries = _recentlyScannedFiles.Where(kvp => DateTime.Now - kvp.Value > _scanCooldown).ToList();
                foreach (var entry in oldEntries)
                {
                    _recentlyScannedFiles.Remove(entry.Key);
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
                bool iocMalicious = false;
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
                    
                    iocMalicious = true;
                    
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
                bool vtMalicious = false;
                bool fileDeleted = false;
                if (vtResult != null && vtResult.IsMalicious)
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
                    
                    vtMalicious = true;
                    
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
                            
                            fileDeleted = true;
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
                else if (vtResult != null && !string.IsNullOrEmpty(vtResult.Error))
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"VirusTotal analysis error: {vtResult.Error}");
                    Console.ResetColor();
                    Console.WriteLine("Continuing with local IOC scan for suspicious content.");
                }
                else if (vtResult != null)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"✓ SAFE: File {filePath} appears to be safe according to VirusTotal");
                    Console.ResetColor();
                    Console.WriteLine($"Scanned by {vtResult.TotalScans} antivirus engines, no threats detected");
                }

                // Determine final malicious status
                isMalicious = fileDeleted || vtMalicious || (vtResult != null && !string.IsNullOrEmpty(vtResult.Error) && iocMalicious);

                // Create scan result data once
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

                // Try to save to database first
                bool dbSaveSuccess = false;
                try
                {
                    LogManager.LogScanResult(filePath, isMalicious, detectionCount, totalScans, detectionInfo.ToString());
                    dbSaveSuccess = true;
                    Console.WriteLine("Scan result saved to database successfully.");
                }
                catch (Exception dbEx)
                {
                    Console.WriteLine($"Error saving to database: {dbEx.Message}");
                }

                // Only try to send to backend if database save was successful
                if (dbSaveSuccess)
                {
                    int retryCount = 0;
                    const int maxRetries = 3;
                    bool sentSuccessfully = false;

                    while (!sentSuccessfully && retryCount < maxRetries)
                    {
                        sentSuccessfully = await _backendService.SendScanResult(scanResult);
                        if (!sentSuccessfully)
                        {
                            retryCount++;
                            if (retryCount < maxRetries)
                            {
                                Console.WriteLine($"Retrying to send scan results to backend... Attempt {retryCount + 1} of {maxRetries}");
                                await Task.Delay(1000 * retryCount); // Exponential backoff
                            }
                        }
                    }

                    if (sentSuccessfully)
                    {
                        Console.WriteLine("Scan results sent to backend successfully.");
                    }
                    else
                    {
                        Console.WriteLine($"Failed to send scan results to backend after {maxRetries} attempts.");
                        // Save locally if backend send fails
                        LogManager.SaveDetailedLog(new LogManager.DetailedScanResult
                        {
                            FilePath = filePath,
                            ScanTime = DateTime.Now,
                            IsMalicious = isMalicious,
                            DetectionCount = detectionCount,
                            TotalScans = totalScans,
                            FileHash = File.Exists(filePath) ? CalculateFileHash(filePath) : "N/A (file deleted)",
                            FileSize = new FileInfo(filePath).Length,
                            FileType = Path.GetExtension(filePath),
                            DetectedThreats = detectedBy,
                            ScannerResults = vtResult?.DetectedBy ?? new Dictionary<string, string>(),
                            Action = isMalicious ? "DELETED" : "SCANNED",
                            DetectedBy = string.Join(", ", detectedBy),
                            DetectedPatterns = string.Join(", ", detectedPatterns)
                        });
                    }
                }
                
                if (isMalicious)
                {
                    Console.WriteLine("\n===============================================================");
                    Console.WriteLine("NOTE: This file contains security risks. Use caution!");
                    Console.WriteLine("===============================================================");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error analyzing file {filePath}: {ex.Message}");
                // Only log error if we haven't already saved a result
                if (!_recentlyScannedFiles.ContainsKey(filePath))
                {
                    LogManager.LogScanResult(filePath, false, 0, 0, $"Error: {ex.Message}");
                }
            }
        }

        private static string CalculateFileHash(string filePath)
        {
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            using var stream = File.OpenRead(filePath);
            var hash = sha256.ComputeHash(stream);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
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
