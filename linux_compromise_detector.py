#!/usr/bin/env python3
import os
import subprocess
import hashlib
import re
import json
from datetime import datetime
from pathlib import Path

class CompromiseDetector:
    def __init__(self):
        self.findings = []
        # Directories to check (must end with /)
        self.suspicious_dirs = [
            "/tmp/.xdiag/",
        ]
        
        # Files to check
        self.suspicious_files = [
            "/lib/libfsnldev.so",
            "/tmp/wttwe",
            "/lib/libgcwrap.so",
            "/lib/libpprocps.so",
            "/tmp/kubeupd",
            "/bin/kkbush",
            "/bin/perfcc",
            "/tmp/.perf.c"
        ]
        
        self.suspicious_processes = [
            "perfctl",
            "perfcc",
            "kubeupd",
            "kkbush",
            "xmrig"  # Common cryptominer
        ]

    def direct_directory_check(self, path):
        """Try to detect directory using direct syscalls via find command"""
        try:
            # Use find command which might bypass userspace hooks
            cmd = f"find {path.rstrip('/')} -maxdepth 0 2>/dev/null"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.returncode == 0 and result.stdout.strip() != ""
        except:
            return False

    def check_with_find(self, path):
        """Use find command which might bypass some rootkit hooks"""
        try:
            cmd = f"find {path} -maxdepth 0 2>/dev/null"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.returncode == 0 and result.stdout.strip() != ""
        except:
            return False

    def check_with_ls(self, path):
        """Use ls command which might use different syscalls"""
        try:
            cmd = f"ls -la {path} 2>/dev/null"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.returncode == 0 and result.stdout.strip() != ""
        except:
            return False

    def check_with_dir(self, path):
        """Try to open directory directly"""
        try:
            if os.path.isdir(path):
                os.listdir(path)
                return True
        except:
            return False
        return False

    def check_suspicious_files(self):
        """Check for known malicious files and directories using multiple methods"""
        # Check directories
        for path in self.suspicious_dirs:
            path = path.rstrip('/')  # Remove trailing slash for exists check
            print(f"[DEBUG] Checking directory: {path}")
            
            # Try multiple detection methods
            methods = {
                'direct': self.direct_directory_check(path),
                'find': self.check_with_find(path),
                'ls': self.check_with_ls(path),
                'dir': self.check_with_dir(path)
            }
            
            print(f"[DEBUG] Detection methods results: {methods}")
            
            if any(methods.values()):
                self.findings.append({
                    "type": "suspicious_directory",
                    "severity": "HIGH",
                    "details": f"Found suspicious directory: {path}/ (detected by: {[k for k,v in methods.items() if v]})",
                    "timestamp": datetime.now().isoformat()
                })

        # Check files using multiple methods
        for path in self.suspicious_files:
            if self.check_with_find(path) or self.check_with_ls(path):
                self.findings.append({
                    "type": "suspicious_file",
                    "severity": "HIGH",
                    "details": f"Found suspicious file: {path}",
                    "timestamp": datetime.now().isoformat()
                })

    def check_for_rootkit(self):
        """Check for signs of rootkit presence"""
        # Check for LD_PRELOAD
        try:
            env = subprocess.check_output(["env"], text=True)
            if "LD_PRELOAD" in env:
                self.findings.append({
                    "type": "rootkit_indicator",
                    "severity": "CRITICAL",
                    "details": "LD_PRELOAD environment variable detected",
                    "timestamp": datetime.now().isoformat()
                })
        except:
            pass

        # Check for hidden processes using different ps commands
        try:
            ps_aux = subprocess.check_output(["ps", "aux"], text=True)
            ps_ef = subprocess.check_output(["ps", "-ef"], text=True)
            
            if len(ps_aux.splitlines()) != len(ps_ef.splitlines()):
                self.findings.append({
                    "type": "rootkit_indicator",
                    "severity": "CRITICAL",
                    "details": "Process hiding detected (different process counts between ps commands)",
                    "timestamp": datetime.now().isoformat()
                })
        except:
            pass

        # Check for common rootkit files
        rootkit_libs = [
            "/lib/libgcwrap.so",
            "/lib/libprocesshider.so",
            "/lib/libnss_files.so.2",
        ]
        
        for lib in rootkit_libs:
            if self.check_with_find(lib) or self.check_with_ls(lib):
                self.findings.append({
                    "type": "rootkit_indicator",
                    "severity": "CRITICAL",
                    "details": f"Potential rootkit library found: {lib}",
                    "timestamp": datetime.now().isoformat()
                })

    def check_processes(self):
        """Check for suspicious running processes"""
        try:
            ps_output = subprocess.check_output(["ps", "aux"], text=True)
            for proc in self.suspicious_processes:
                if proc in ps_output:
                    self.findings.append({
                        "type": "suspicious_process",
                        "severity": "HIGH",
                        "details": f"Found suspicious process: {proc}",
                        "timestamp": datetime.now().isoformat()
                    })
        except subprocess.SubProcessError:
            self.findings.append({
                "type": "error",
                "severity": "MEDIUM",
                "details": "Unable to check processes",
                "timestamp": datetime.now().isoformat()
            })

    def check_crontabs(self):
        """Check for suspicious cron jobs"""
        try:
            crontab_output = subprocess.check_output(["crontab", "-l"], text=True)
            suspicious_patterns = [
                r"/tmp/",
                r"curl.*wget",
                r"bash.*-c",
                r"exec.*3<>/dev/tcp"
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, crontab_output):
                    self.findings.append({
                        "type": "suspicious_crontab",
                        "severity": "HIGH",
                        "details": f"Found suspicious crontab entry matching: {pattern}",
                        "timestamp": datetime.now().isoformat()
                    })
        except subprocess.SubProcessError:
            pass  # Ignore if no crontab exists

    def check_systemd_services(self):
        """Check for suspicious systemd services"""
        try:
            services = subprocess.check_output(["systemctl", "list-units", "--type=service", "--all"], text=True)
            suspicious_patterns = [
                "KubeUpdate",
                "ExecStart=/tmp",
                "perfctl"
            ]
            
            for pattern in suspicious_patterns:
                if pattern in services:
                    self.findings.append({
                        "type": "suspicious_service",
                        "severity": "HIGH",
                        "details": f"Found suspicious systemd service matching: {pattern}",
                        "timestamp": datetime.now().isoformat()
                    })
        except subprocess.SubProcessError:
            self.findings.append({
                "type": "error",
                "severity": "MEDIUM",
                "details": "Unable to check systemd services",
                "timestamp": datetime.now().isoformat()
            })

    def check_docker_containers(self):
        """Check for suspicious Docker containers"""
        try:
            containers = subprocess.check_output(["docker", "ps", "-a"], text=True)
            suspicious_patterns = [
                "xmrig",
                "monero",
                "crypto",
                "proxy"
            ]
            
            for pattern in suspicious_patterns:
                if pattern in containers.lower():
                    self.findings.append({
                        "type": "suspicious_container",
                        "severity": "HIGH",
                        "details": f"Found suspicious Docker container matching: {pattern}",
                        "timestamp": datetime.now().isoformat()
                    })
        except (subprocess.SubProcessError, FileNotFoundError):
            pass  # Docker might not be installed

    def check_portainer_exposure(self):
        """Check if Portainer agent is exposed"""
        try:
            netstat = subprocess.check_output(["netstat", "-tulpn"], text=True)
            if ":9001" in netstat:
                self.findings.append({
                    "type": "exposed_service",
                    "severity": "HIGH",
                    "details": "Portainer agent port (9001) is exposed",
                    "timestamp": datetime.now().isoformat()
                })
        except subprocess.SubProcessError:
            self.findings.append({
                "type": "error",
                "severity": "MEDIUM",
                "details": "Unable to check network ports",
                "timestamp": datetime.now().isoformat()
            })

    def check_ssh_backdoors(self):
        """Check for potential SSH backdoors"""
        ssh_paths = [
            os.path.expanduser("~/.ssh/authorized_keys"),
            "/root/.ssh/authorized_keys"
        ]
        
        for path in ssh_paths:
            if os.path.exists(path):
                try:
                    with open(path, 'r') as f:
                        content = f.read()
                        if len(content.splitlines()) > 10:  # Arbitrary threshold
                            self.findings.append({
                                "type": "suspicious_ssh",
                                "severity": "MEDIUM",
                                "details": f"Large number of SSH keys in {path}",
                                "timestamp": datetime.now().isoformat()
                            })
                except PermissionError:
                    pass

    def check_ld_preload(self):
        """Check for LD_PRELOAD hijacking"""
        try:
            env = subprocess.check_output(["env"], text=True)
            if "LD_PRELOAD" in env:
                self.findings.append({
                    "type": "suspicious_env",
                    "severity": "HIGH",
                    "details": "LD_PRELOAD environment variable is set",
                    "timestamp": datetime.now().isoformat()
                })
        except subprocess.SubProcessError:
            pass

    def run_all_checks(self):
        """Run all available checks"""
        checks = [
            self.check_suspicious_files,
            self.check_for_rootkit,  # Add rootkit detection
            self.check_processes,
            self.check_crontabs,
            self.check_systemd_services,
            self.check_docker_containers,
            self.check_portainer_exposure,
            self.check_ssh_backdoors,
            self.check_ld_preload
        ]
        
        for check in checks:
            try:
                check()
            except Exception as e:
                self.findings.append({
                    "type": "error",
                    "severity": "LOW",
                    "details": f"Error running {check.__name__}: {str(e)}",
                    "timestamp": datetime.now().isoformat()
                })

    def generate_report(self):
        """Generate a JSON report of findings"""
        report = {
            "scan_time": datetime.now().isoformat(),
            "findings": self.findings,
            "total_findings": len(self.findings)
        }
        
        # Generate JSON report
        json_report = json.dumps(report, indent=2)
        
        # Generate ASCII table summary
        summary = self._generate_summary_table()
        
        return f"{json_report}\n\nSummary:\n{summary}"
        
    def _generate_summary_table(self):
        """Generate ASCII table with findings summary"""
        # Count findings by type and severity
        summary = {}
        for finding in self.findings:
            type_sev = (finding['type'], finding['severity'])
            summary[type_sev] = summary.get(type_sev, 0) + 1
        
        if not summary:
            return "No findings."
            
        # Get unique types and severities
        types = sorted(set(t for t, _ in summary.keys()))
        severities = sorted(set(s for _, s in summary.keys()))
        
        # Calculate column widths
        type_width = max(len("Type"), max(len(t) for t in types))
        sev_widths = {sev: len(sev) for sev in severities}
        
        # Generate header
        header = "+" + "-" * (type_width + 2)
        for sev in severities:
            header += "+" + "-" * (sev_widths[sev] + 2)
        header += "+\n"
        
        # Generate title row
        row = f"| {'Type':<{type_width}} "
        for sev in severities:
            row += f"| {sev:<{sev_widths[sev]}} "
        row += "|\n"
        
        # Generate separator
        separator = header
        
        # Generate data rows
        table = header + row + separator
        for type_ in types:
            row = f"| {type_:<{type_width}} "
            for sev in severities:
                count = summary.get((type_, sev), 0)
                row += f"| {str(count):<{sev_widths[sev]}} "
            row += "|\n"
            table += row
        
        # Add bottom border
        table += header
        
        return table

def main():
    print("[*] Starting Linux compromise detection...")
    detector = CompromiseDetector()
    detector.run_all_checks()
    print(detector.generate_report())

if __name__ == "__main__":
    main() 