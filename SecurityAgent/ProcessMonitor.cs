using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Threading;
using System.Threading.Tasks;
using System.IO;
using System.Text.RegularExpressions;
using System.Security.Principal;

namespace SecurityAgent
{
    public class ProcessMonitor
    {
        private readonly IOCScanner _iocScanner;
        private readonly List<string> _suspiciousProcessNames;
        private readonly List<string> _suspiciousCommandLines;
        private readonly Dictionary<int, bool> _monitoredProcessIds; // Store only IDs, not Process objects
        private readonly HashSet<int> _ignoredProcessIds; // Processes to ignore
        private bool _isRunning;
        private Thread _monitorThread;
        private readonly bool _isElevated;
        
        public ProcessMonitor(IOCScanner iocScanner)
        {
            _iocScanner = iocScanner;
            _monitoredProcessIds = new Dictionary<int, bool>();
            _ignoredProcessIds = new HashSet<int>();
            _isRunning = false;
            
            // Check if running as administrator
            _isElevated = IsAdministrator();
            
            // Define suspicious process names
            _suspiciousProcessNames = new List<string>
            {
                "mimikatz",
                "psexec",
                "pwdump",
                "procdump",
                "wce",
                "bloodhound",
                "crackmapexec",
                "winpeas",
                "linpeas",
                "lazagne",
                "netcat",
                "powersploit",
                "empire"
            };
            
            // Define suspicious command line patterns
            _suspiciousCommandLines = new List<string>
            {
                "powershell.*-enc",
                "powershell.*bypass",
                "powershell.*hidden",
                "powershell.*downloadstring",
                "cmd.*/c.*powershell",
                "certutil.*-decode",
                "certutil.*-urlcache",
                "bitsadmin.*/transfer",
                "regsvr32.*/s.*/u.*/i",
                "wmic.*process call create",
                "mshta.*javascript"
            };
        }
        
        private bool IsAdministrator()
        {
            try
            {
                WindowsIdentity identity = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }
        
        public void Start()
        {
            if (_isRunning) return;
            
            _isRunning = true;
            _monitorThread = new Thread(MonitorProcesses)
            {
                IsBackground = true
            };
            _monitorThread.Start();
            
            if (!_isElevated)
            {
                Console.WriteLine("Warning: Process monitoring is running without administrator privileges.");
                Console.WriteLine("Some processes cannot be monitored without elevated permissions.");
            }
            else
            {
                Console.WriteLine("Process monitoring started with administrator privileges.");
            }
        }
        
        public void Stop()
        {
            _isRunning = false;
            try
            {
                _monitorThread?.Join(1000);
            }
            catch
            {
                // Ignore thread join errors
            }
            Console.WriteLine("Process monitoring stopped");
        }
        
        private void MonitorProcesses()
        {
            // Get our own process ID to ignore
            int currentProcessId = -1;
            int vsProcessId = -1;
            
            // Get our own process ID safely
            try
            {
                using (var currentProcess = Process.GetCurrentProcess())
                {
                    currentProcessId = currentProcess.Id;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Could not get current process ID: {ex.Message}");
            }
            
            // Try to find Visual Studio process (if any) to ignore it
            try
            {
                var vsProcess = Process.GetProcessesByName("devenv").FirstOrDefault();
                if (vsProcess != null)
                {
                    vsProcessId = vsProcess.Id;
                }
            }
            catch
            {
                // Ignore errors
            }
            
            _ignoredProcessIds.Add(currentProcessId);
            if (vsProcessId > 0)
            {
                _ignoredProcessIds.Add(vsProcessId);
            }
            
            while (_isRunning)
            {
                try
                {
                    // Get all running processes but with a safer approach
                    Process[] processes = null;
                    try
                    {
                        processes = Process.GetProcesses();
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error getting processes: {ex.Message}");
                        Thread.Sleep(5000);
                        continue;
                    }
                    
                    foreach (var process in processes)
                    {
                        try
                        {
                            // Skip our own process and Visual Studio
                            if (_ignoredProcessIds.Contains(process.Id))
                            {
                                continue;
                            }
                            
                            // Skip system critical processes
                            if (IsCriticalSystemProcess(process))
                            {
                                _ignoredProcessIds.Add(process.Id);
                                continue;
                            }
                            
                            if (!_monitoredProcessIds.ContainsKey(process.Id))
                            {
                                _monitoredProcessIds[process.Id] = true;
                                
                                // Check for suspicious process (safely)
                                Task.Run(() => 
                                {
                                    try 
                                    {
                                        CheckProcess(process);
                                    }
                                    catch
                                    {
                                        // Ignore any errors in checking
                                    }
                                });
                            }
                        }
                        catch
                        {
                            // Ignore individual process errors
                        }
                        finally
                        {
                            // Ensure we dispose the process properly to avoid handle leaks
                            try
                            {
                                process.Dispose();
                            }
                            catch
                            {
                                // Ignore disposal errors
                            }
                        }
                    }
                    
                    // Clean up terminated process IDs (with safer approach)
                    var currentPids = new HashSet<int>();
                    foreach (var process in processes)
                    {
                        try
                        {
                            currentPids.Add(process.Id);
                        }
                        catch
                        {
                            // Ignore errors
                        }
                    }
                    
                    var terminatedProcessIds = _monitoredProcessIds.Keys
                        .Where(pid => !currentPids.Contains(pid))
                        .ToList();
                    
                    foreach (var pid in terminatedProcessIds)
                    {
                        _monitoredProcessIds.Remove(pid);
                    }
                    
                    Thread.Sleep(2000); // Check every 2 seconds to reduce CPU usage
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error in process monitoring loop: {ex.Message}");
                    Thread.Sleep(5000); // Wait longer on error
                }
            }
        }
        
        private bool IsCriticalSystemProcess(Process process)
        {
            try
            {
                string processName = process.ProcessName.ToLower();
                
                // List of critical system processes to ignore
                string[] criticalProcesses = new string[]
                {
                    "system", "smss", "csrss", "wininit", "services", "lsass", "winlogon",
                    "explorer", "svchost", "spoolsv", "devenv", "taskmgr", "mmc", "rundll32",
                    "dllhost"
                };
                
                if (criticalProcesses.Any(p => processName.Equals(p)))
                {
                    return true;
                }
                
                // Also ignore Visual Studio related processes
                if (processName.Contains("vs") || 
                    processName.Contains("visual studio") ||
                    processName.Contains("msbuild") ||
                    processName.StartsWith("dotnet"))
                {
                    return true;
                }
                
                return false;
            }
            catch
            {
                // When in doubt, assume it's a system process for safety
                return true;
            }
        }
        
        private void CheckProcess(Process process)
        {
            try
            {
                if (!_isRunning || _ignoredProcessIds.Contains(process.Id))
                {
                    return;
                }
                
                string processName = "";
                try
                {
                    processName = process.ProcessName.ToLower();
                }
                catch
                {
                    return; // Skip if we can't even get the process name
                }
                
                // Skip checking system processes to avoid issues
                if (IsCriticalSystemProcess(process))
                {
                    _ignoredProcessIds.Add(process.Id);
                    return;
                }
                
                // Check for suspicious process name
                if (_suspiciousProcessNames.Any(name => processName.Contains(name)))
                {
                    TerminateSuspiciousProcess(process, $"Suspicious process name: {processName}");
                    return;
                }
                
                // Only try to get command line if we're running as admin
                string commandLine = "";
                if (_isElevated)
                {
                    try
                    {
                        commandLine = GetCommandLine(process.Id);
                    }
                    catch
                    {
                        // Ignore command line errors
                    }
                }
                
                // Check for suspicious command line
                if (!string.IsNullOrEmpty(commandLine))
                {
                    foreach (var pattern in _suspiciousCommandLines)
                    {
                        try
                        {
                            if (Regex.IsMatch(commandLine, pattern, RegexOptions.IgnoreCase))
                            {
                                TerminateSuspiciousProcess(process, $"Suspicious command line detected: {pattern}");
                                return;
                            }
                        }
                        catch
                        {
                            // Ignore regex errors
                        }
                    }
                }
                
                // Only scan executable if we're running as admin
                if (_isElevated)
                {
                    // Check executable file if available
                    string executablePath = "";
                    try 
                    {
                        executablePath = GetExecutablePath(process);
                    }
                    catch
                    {
                        // Ignore path errors
                    }
                    
                    if (!string.IsNullOrEmpty(executablePath) && File.Exists(executablePath))
                    {
                        try
                        {
                            var iocResult = _iocScanner.ScanFile(executablePath);
                            if (iocResult.IsSuspicious)
                            {
                                TerminateSuspiciousProcess(process, $"IOC scan detected suspicious patterns in executable: {string.Join(", ", iocResult.DetectedPatterns)}");
                                return;
                            }
                        }
                        catch
                        {
                            // Ignore scan errors
                        }
                    }
                }
            }
            catch (Exception)
            {
                // Process might have terminated, ignore errors
            }
        }
        
        private void TerminateSuspiciousProcess(Process process, string reason)
        {
            try
            {
                // Get process details before terminating
                string processName = process.ProcessName;
                int processId = process.Id;
                string executablePath = GetExecutablePath(process);
                
                // Display detailed warning
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n⚠️⚠️⚠️ SUSPICIOUS PROCESS DETECTED ⚠️⚠️⚠️");
                Console.WriteLine("===============================================================");
                Console.WriteLine($"Process Name: {processName}");
                Console.WriteLine($"Process ID: {processId}");
                
                if (!string.IsNullOrEmpty(executablePath))
                {
                    Console.WriteLine($"Executable Path: {executablePath}");
                }
                
                Console.WriteLine($"Detection Reason: {reason}");
                Console.ResetColor();
                
                // Only terminate if auto-termination is enabled in configuration
                Configuration config = Configuration.Default; // Get a reference to the configuration
                if (config.AutoTerminateMaliciousProcesses)
                {
                    try
                    {
                        process.Kill();
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("✓ Suspicious process successfully terminated");
                        Console.ResetColor();
                        
                        // Send notification
                        NotificationService.ShowMaliciousProcessNotification(process, reason);
                    }
                    catch (Exception ex)
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine($"Could not terminate process: {ex.Message}");
                        Console.ResetColor();
                    }
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("! Automatic process termination is disabled.");
                    Console.WriteLine("! This suspicious process continues to run actively!");
                    Console.ResetColor();
                    
                    // Show notification without termination
                    NotificationService.ShowSuspiciousProcessNotification(process, reason);
                }
                
                Console.WriteLine("===============================================================");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error handling suspicious process: {ex.Message}");
            }
        }
        
        private bool CanAccessProcess(Process process)
        {
            try
            {
                // Try to get some process info as a test for access rights
                var temp = process.Id;
                var temp2 = process.ProcessName;
                var temp3 = process.MainModule; // Will throw if we don't have access
                return true;
            }
            catch
            {
                return false;
            }
        }
        
        private string GetCommandLine(int processId)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher($"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {processId}"))
                using (var results = searcher.Get())
                {
                    foreach (var obj in results)
                    {
                        try
                        {
                            return obj["CommandLine"]?.ToString() ?? string.Empty;
                        }
                        finally
                        {
                            obj?.Dispose();
                        }
                    }
                }
            }
            catch
            {
                // WMI might not be available or permission issues
            }
            
            return string.Empty;
        }
        
        private string GetExecutablePath(Process process)
        {
            try
            {
                return process.MainModule?.FileName ?? string.Empty;
            }
            catch
            {
                // Might not have permission to access the module
                return string.Empty;
            }
        }
    }
} 