# Web Based Security Detection

A web-based real-time security detection system - SecurityAgent application for file and process analysis.

## About the Project

This project is a web-based antivirus system that monitors computer security in real-time. Main components:

1. **SecurityAgent**: A background agent running on the computer that monitors the system in real-time
2. **Backend API**: A cloud-based database for storing scanned file data (needs to be developed separately)
3. **AI Module**: Uses machine learning model to detect malware (future feature)

This repository contains the SecurityAgent component.

## Features

SecurityAgent has the following features:

- **Real-Time File Monitoring**: Monitors file creation, modification, and renaming events in specified folders
- **IOC (Indicators of Compromise) Scanning**: Locally scans files for known malicious patterns
- **VirusTotal Integration**: Analyzes files using the VirusTotal API
- **Process Monitoring**: Detects suspicious processes and terminates them if necessary
- **Automatic Response**: Can automatically delete malicious files and send notifications
- **Windows Notifications**: Displays detected threats as notifications
- **Configurable Monitoring**: Can customize monitored folders and file types
- **Local Logging**: Logs scan results locally

## Installation

### Requirements

- .NET 7.0 or higher
- Windows Operating System
- VirusTotal API Key (optional but recommended)

### Steps

1. Clone or download this repository
2. Open the project with Visual Studio or another IDE
3. Build the project (can also be done with `dotnet build`)
4. Run the generated `SecurityAgent.exe` file
5. Modify the `config.json` file according to your needs (automatically created on first run)

## Configuration

The default configuration file looks like this:

```json
{
  "MonitoringPaths": ["C:\\Users\\YourUsername"],
  "MonitoredExtensions": [".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".wsh", ".msi"],
  "IncludeSubdirectories": true,
  "VirusTotalApiKey": "YOUR_VIRUSTOTAL_API_KEY",
  "BackendApiUrl": "https://localhost:7260/api",
  "AdditionalSuspiciousPatterns": [],
  "EnableAlerts": true,
  "EnableProcessMonitoring": true,
  "AutoTerminateMaliciousProcesses": true,
  "AutoDeleteMaliciousFiles": true,
  "VirusTotalDetectionThreshold": 1
}
```

### Configuration Parameters

- **MonitoringPaths**: Array of folders to monitor
- **MonitoredExtensions**: File extensions to monitor
- **IncludeSubdirectories**: Whether to monitor subdirectories
- **VirusTotalApiKey**: VirusTotal API key - you can create a free account [here](https://www.virustotal.com/gui/join-us)
- **BackendApiUrl**: Backend API URL (if you don't have an API yet, results are saved locally)
- **AdditionalSuspiciousPatterns**: Additional suspicious patterns you want to add
- **EnableAlerts**: Enable notifications
- **EnableProcessMonitoring**: Enable process monitoring
- **AutoTerminateMaliciousProcesses**: Automatically terminate malicious processes
- **AutoDeleteMaliciousFiles**: Automatically delete malicious files
- **VirusTotalDetectionThreshold**: Minimum number of antivirus engine detections required to mark a file as malicious

## Usage

### Getting Started

When you run the program, you'll see a command-line interface. By default, your user directory starts being monitored.

### Commands

You can use the following commands to control the program:

- `help`: Shows list of available commands
- `dirs`: Shows monitored directories
- `add`: Adds a new monitoring directory
- `remove`: Removes a monitoring directory
- `save`: Saves configuration
- `alert`: Toggles notifications
- `process`: Toggles process monitoring
- `config`: Shows current configuration
- `scan`: Manually scans a specific file
- `exit` or `quit`: Exits the program

### Scan Results

Scan results are displayed and saved as follows:

1. **Console**: Scan results and detections are shown directly in the console
2. **Notifications**: Windows notifications are shown when malicious or suspicious files are detected
3. **Logs**: Scan results are saved to `SecurityAgent/bin/Debug/net7.0/Logs/scan_results.log`
4. **Backend** (if configured): Results are sent to the specified API

## Security Notes

1. **Administrator Privileges**: Administrator privileges may be required to access certain files and processes
2. **False Positives**: Like all security software, this tool may produce false positives
3. **System Processes**: The program does not modify or terminate Windows critical system processes

## Future Features

- AI-based malware detection
- Web interface and remote management
- Network traffic monitoring
- USB drive monitoring and protection
- Comprehensive reporting

## Troubleshooting

- **VirusTotal Error**: Make sure you've configured the API key
- **Backend Issues**: If Backend API URL is not set, data is saved locally
- **Permission Issues**: Try running as administrator
- **Performance Issues**: Reduce the number of monitored folders

## Contributing

If you want to contribute to this project, please submit an issue or pull request.
