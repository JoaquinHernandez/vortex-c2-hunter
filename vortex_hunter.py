import os
import sys
import json
import math
import statistics
import time

# ANSI Terminal Styling
RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RED     = "\033[38;5;196m"
GREEN   = "\033[38;5;48m"
CYAN    = "\033[38;5;51m"
AMBER   = "\033[38;5;214m"
MAGENTA = "\033[38;5;201m"
GRAY    = "\033[38;5;242m"

BANNER = f"""{CYAN}{BOLD}
 ██╗   ██╗ ██████╗ ██████╗ ████████╗███████╗██╗  ██╗
 ██║   ██║██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝╚██╗██╔╝
 ██║   ██║██║   ██║██████╔╝   ██║   █████╗   ╚███╔╝ 
 ╚██╗ ██╔╝██║   ██║██╔══██╗   ██║   ██╔══╝   ██╔██╗ 
  ╚████╔╝ ╚██████╔╝██║  ██║   ██║   ███████╗██╔╝ ██╗
   ╚═══╝   ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{RESET}{AMBER} » ACTIVE C2 BEACONING & COVERT CHANNEL THREAT HUNTING RADAR «{RESET}
"""

class VortexC2Hunter:
    def __init__(self, config_file="detection_config.json", traffic_file="network_traffic.json"):
        if not os.path.exists(config_file) or not os.path.exists(traffic_file):
            print(f"{RED}[-] Error: Missing configuration or network traffic file.{RESET}")
            sys.exit(1)

        with open(config_file, "r") as f:
            self.config = json.load(f)

        with open(traffic_file, "r") as f:
            self.traffic = json.load(f).get("connections", [])

        self.min_conns = self.config.get("min_connection_threshold", 4)
        self.max_jitter = self.config.get("max_jitter_coefficient", 0.25)
        self.dns_entropy_limit = self.config.get("dns_entropy_threshold", 3.8)
        self.suspicious_ports = self.config.get("suspicious_ports", [])
        self.mitre = self.config.get("mitre_mappings", {})

    def calculate_entropy(self, text):
        """Calculates Shannon Entropy on DNS subdomains to detect data exfiltration."""
        if not text:
            return 0.0
        entropy = 0.0
        length = len(text)
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        for count in freq.values():
            p_x = count / length
            entropy -= p_x * math.log2(p_x)
        return entropy

    def analyze_beaconing(self, timestamps):
        """Calculates intervals and Jitter Coefficient of Variation (CV = std_dev / mean)."""
        if len(timestamps) < self.min_conns:
            return None, None, False

        # Calculate deltas (inter-arrival times)
        intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
        mean_interval = statistics.mean(intervals)
        
        if mean_interval == 0:
            return 0, 0, True
            
        std_dev = statistics.stdev(intervals) if len(intervals) > 1 else 0
        jitter_coefficient = std_dev / mean_interval

        # Low jitter coefficient indicates strict programmatic beaconing (malware loop)
        is_beacon = jitter_coefficient <= self.max_jitter
        return round(mean_interval, 1), round(jitter_coefficient, 3), is_beacon

    def run_hunt(self):
        print(BANNER)
        print(f"{BOLD}Initializing Deep Threat Hunting Radar...{RESET}\n")
        
        radar_steps = [
            "Parsing connection flows and inter-arrival intervals",
            "Evaluating Jitter Coefficients across session clusters",
            "Executing Shannon Entropy audit on DNS queries",
            "Cross-referencing destination ports against C2 staging lists"
        ]
        for step in radar_steps:
            time.sleep(0.25)
            print(f"  {CYAN}▸{RESET} {step}...")
        
        print("\n" + "=" * 85 + "\n")
        print(f"{BOLD}{'SRC IP':<14} {'DST ENDPOINT':<22} {'METRIC':<18} {'THREAT TYPE':<20} {'MITRE ID'}{RESET}")
        print("-" * 85)

        threats_found = 0

        for flow in self.traffic:
            src = flow["src_ip"]
            dst = f"{flow['dst_ip']}:{flow['dst_port']}"
            timestamps = flow.get("timestamps", [])
            dns_query = flow.get("dns_query")

            # Check 1: DNS Tunneling Exfiltration Check
            if dns_query:
                subdomain = dns_query.split(".")[0]
                entropy = self.calculate_entropy(subdomain)
                if entropy >= self.dns_entropy_limit:
                    threats_found += 1
                    metric_str = f"Entropy: {entropy:.2f}"
                    print(f"{src:<14} {dst:<22} {metric_str:<18} {RED}{'DNS Exfiltration':<20}{RESET} {CYAN}{self.mitre.get('DNS_TUNNELING')}{RESET}")
                    continue

            # Check 2: Statistical C2 Beaconing Check
            mean_int, cv, is_beacon = self.analyze_beaconing(timestamps)
            if is_beacon:
                threats_found += 1
                metric_str = f"Interval: ~{mean_int}s (CV: {cv})"
                threat_label = "C2 Heartbeat Beacon"
                mitre_tag = self.mitre.get("BEACONING")
                
                # Check for suspicious non-standard port
                if flow["dst_port"] in self.suspicious_ports:
                    threat_label += " [Port!]"

                print(f"{src:<14} {dst:<22} {metric_str:<18} {RED}{threat_label:<20}{RESET} {CYAN}{mitre_tag}{RESET}")
            else:
                # Legitimate / irregular traffic
                metric_str = f"Irregular (CV: {cv})" if cv is not None else "Low Flow Volume"
                print(f"{GRAY}{src:<14} {dst:<22} {metric_str:<18} {'Clean / Normal':<20} {'N/A'}{RESET}")

        print("=" * 85)
        print(f"\n{BOLD}Threat Hunting Summary:{RESET} Flagged {RED}{threats_found}{RESET} active high-risk Command-and-Control indicators.")
        print(f"{AMBER}{BOLD}[⚡ RECOMMENDED ACTION]{RESET} Extract memory dumps on flagged source IPs and black-hole destination endpoints at the perimeter firewall.\n")

if __name__ == "__main__":
    hunter = VortexC2Hunter()
    hunter.run_hunt()
