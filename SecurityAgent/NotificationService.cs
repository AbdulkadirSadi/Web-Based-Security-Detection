using System;
using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SecurityAgent
{
    public class NotificationService
    {
        private static bool _alertsEnabled = true;
        
        public static bool AlertsEnabled 
        { 
            get { return _alertsEnabled; } 
            set { _alertsEnabled = value; } 
        }

        // On Windows, we can use MessageBeep for simple notifications
        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool MessageBeep(uint uType);

        private const uint MB_ICONASTERISK = 0x00000040;
        private const uint MB_ICONWARNING = 0x00000030;
        private const uint MB_ICONERROR = 0x00000010;
        
        public static void ShowMaliciousFileNotification(string filePath, string detectionInfo)
        {
            if (!_alertsEnabled) return;
            
            try
            {
                string fileName = Path.GetFileName(filePath);
                
                // Display in console
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"🔴 SECURITY ALERT: Malicious file detected and deleted: {filePath}");
                Console.WriteLine(detectionInfo);
                Console.ResetColor();
                
                // Play sound alert
                MessageBeep(MB_ICONERROR);
                
                // On Windows, try to show a notification using cmd
                try 
                {
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {
                        string message = $"Security Alert: Malicious file '{fileName}' detected and deleted!";
                        ShowBalloonTip("SecurityAgent", message);
                    }
                }
                catch
                {
                    // Fallback to console only if balloon tip fails
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to show notification: {ex.Message}");
            }
        }
        
        public static void ShowSuspiciousFileNotification(string filePath, string detectionInfo)
        {
            if (!_alertsEnabled) return;
            
            try
            {
                string fileName = Path.GetFileName(filePath);
                
                // Display in console
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"⚠️ SECURITY ALERT: Suspicious file detected: {filePath}");
                Console.WriteLine(detectionInfo);
                Console.ResetColor();
                
                // Play sound alert
                MessageBeep(MB_ICONWARNING);
                
                // On Windows, try to show a notification using cmd
                try 
                {
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {
                        string message = $"Security Alert: Suspicious file '{fileName}' detected!";
                        ShowBalloonTip("SecurityAgent", message);
                    }
                }
                catch
                {
                    // Fallback to console only if balloon tip fails
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to show notification: {ex.Message}");
            }
        }
        
        public static void ShowMaliciousProcessNotification(Process process, string reason)
        {
            if (!_alertsEnabled) return;
            
            try
            {
                string processName = process.ProcessName;
                int processId = process.Id;
                
                // Display in console
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"🔴 SECURITY ALERT: Malicious process terminated: {processName} (PID: {processId})");
                Console.WriteLine(reason);
                Console.ResetColor();
                
                // Play sound alert
                MessageBeep(MB_ICONERROR);
                
                // On Windows, try to show a notification using cmd
                try 
                {
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {
                        string message = $"Security Alert: Malicious process '{processName}' terminated!";
                        ShowBalloonTip("SecurityAgent", message);
                    }
                }
                catch
                {
                    // Fallback to console only if balloon tip fails
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to show notification: {ex.Message}");
            }
        }
        
        public static void ShowSuspiciousProcessNotification(Process process, string reason)
        {
            if (!_alertsEnabled) return;
            
            try
            {
                string processName = process.ProcessName;
                int processId = process.Id;
                
                // Display in console
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"⚠️ SECURITY ALERT: Suspicious process detected: {processName} (PID: {processId})");
                Console.WriteLine(reason);
                Console.ResetColor();
                
                // Play sound alert
                MessageBeep(MB_ICONWARNING);
                
                // On Windows, try to show a notification
                try 
                {
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {
                        string message = $"Security Alert: Suspicious process '{processName}' detected! Manual review recommended.";
                        ShowBalloonTip("SecurityAgent", message);
                    }
                }
                catch
                {
                    // Fallback to console only if balloon tip fails
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to show notification: {ex.Message}");
            }
        }
        
        // Shows a balloon tip notification by creating a temporary PowerShell script
        private static void ShowBalloonTip(string title, string message)
        {
            string script = $@"
[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms') | Out-Null
$notification = New-Object System.Windows.Forms.NotifyIcon
$notification.Icon = [System.Drawing.SystemIcons]::Information
$notification.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Warning
$notification.BalloonTipTitle = '{title}'
$notification.BalloonTipText = '{message}'
$notification.Visible = $true
$notification.ShowBalloonTip(5000)
Start-Sleep -s 1
$notification.Dispose()
";

            // Create a temporary file for the script
            string tempFile = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName() + ".ps1");
            File.WriteAllText(tempFile, script);

            try
            {
                // Execute PowerShell with bypass execution policy to show notification
                ProcessStartInfo startInfo = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-ExecutionPolicy Bypass -WindowStyle Hidden -File \"{tempFile}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (Process process = Process.Start(startInfo))
                {
                    // Don't wait for process to exit, it will run in the background
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to show balloon notification: {ex.Message}");
            }
            finally
            {
                // Try to clean up the temporary file
                try
                {
                    File.Delete(tempFile);
                }
                catch
                {
                    // Ignore cleanup errors
                }
            }
        }
        
        public static bool TerminateProcess(int processId)
        {
            try
            {
                Process process = Process.GetProcessById(processId);
                process.Kill();
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to terminate process: {ex.Message}");
                return false;
            }
        }
        
        public static bool DeleteFile(string filePath)
        {
            try
            {
                if (File.Exists(filePath))
                {
                    File.Delete(filePath);
                    return true;
                }
                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to delete file: {ex.Message}");
                return false;
            }
        }
    }
} 