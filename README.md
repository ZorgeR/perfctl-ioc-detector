# Linux Compromise (perfctl) Detection Tool

This tool is designed to detect potential system compromises, particularly focusing on the `perfctl` malware family and similar threats. It performs various checks to identify suspicious files, processes, and system configurations that might indicate a compromise.

## Features

- Detects known malicious files and paths
- Identifies suspicious running processes
- Checks for suspicious cron jobs
- Analyzes systemd services
- Monitors Docker containers for crypto mining activity
- Checks for exposed Portainer agent
- Detects potential SSH backdoors
- Identifies LD_PRELOAD hijacking attempts

## Requirements

- Python 3.6+
- Root/sudo access (for some checks)
- Linux operating system

## Installation

1. Clone or download the script to your system
2. Make the script executable:
   ```bash
   chmod +x linux_compromise_detector.py
   ```

## Usage

Run the script with root privileges for full functionality:

```bash
sudo python3 linux_compromise_detector.py
```

The tool will generate a JSON report containing:
- Scan timestamp
- List of findings with severity levels
- Total number of findings

## Output Example

```json
{
  "scan_time": "2024-01-01T12:00:00.000000",
  "findings": [
    {
      "type": "suspicious_file",
      "severity": "HIGH",
      "details": "Found suspicious file: /tmp/.xdiag/",
      "timestamp": "2024-01-01T12:00:00.000000"
    }
  ],
  "total_findings": 1
}
```

## Severity Levels

- **HIGH**: Immediate attention required, likely indicates compromise
- **MEDIUM**: Suspicious activity that requires investigation
- **LOW**: Potential issues or errors in detection

## Security Considerations

- Run this tool regularly as part of your security monitoring
- Keep the tool updated with new IOCs (Indicators of Compromise)
- Review all findings, especially those marked as HIGH severity
- Consider running in a cron job for automated monitoring

## Limitations

- Some checks require root privileges
- False positives may occur
- Tool effectiveness depends on known IOCs
- Some malware may actively hide from detection

## Contributing

Feel free to contribute by:
- Adding new detection methods
- Updating IOCs
- Improving detection accuracy
- Adding support for new malware families

## License

MIT License 