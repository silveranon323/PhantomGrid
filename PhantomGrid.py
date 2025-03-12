import re
import json
import csv
import logging
import asyncio
import aiohttp
import folium
import argparse
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
from aiohttp import ClientSession
from collections import defaultdict, Counter
from folium.plugins import HeatMap, MarkerCluster, TimestampedGeoJson
from geopy.distance import geodesic
from sklearn.cluster import DBSCAN
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import smtplib
import os
import socket
import hashlib
from typing import Dict, List, Set, Tuple, Any, Optional

LOG_FILE = "cowrie/log/cowrie.log"
OUTPUT_DIR = "attack_analysis"
IPINFO_API = "https://ipinfo.io/{}/json"
ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_API = "https://www.virustotal.com/api/v3/ip_addresses/{}"
SHODAN_API = "https://api.shodan.io/shodan/host/{}?key={}"

os.makedirs(OUTPUT_DIR, exist_ok=True)

logging.basicConfig(
    filename=f"{OUTPUT_DIR}/attacker_analysis.log", 
    level=logging.INFO, 
    format="%(asctime)s - %(levelname)s - %(message)s"
)

class HoneypotAnalyzer:
    def __init__(self, config_file="config.json"):
        self.load_config(config_file)
        self.session = None
        self.results = {}
        self.attack_patterns = defaultdict(list)
        self.login_attempts = defaultdict(list)
        self.commands_executed = defaultdict(list)
        self.files_downloaded = defaultdict(list)
        self.timestamps = defaultdict(list)
        self.attack_types = defaultdict(int)
        self.command_categories = {
            "reconnaissance": ["ls", "dir", "pwd", "whoami", "id", "uname", "cat /etc/passwd"],
            "persistence": ["crontab", "ssh-keygen", "useradd", "adduser"],
            "lateral_movement": ["ssh", "scp", "rsync"],
            "data_exfiltration": ["wget", "curl", "scp", "ftp", "sftp"],
            "privilege_escalation": ["sudo", "su", "chmod +s", "pkexec"],
            "malware_deployment": ["wget", "curl", "tftp", ".sh", ".py", ".pl", ".bin"]
        }
        
    def load_config(self, config_file):
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            self.abuseipdb_key = config.get("ABUSEIPDB_KEY", "")
            self.virustotal_key = config.get("VIRUSTOTAL_KEY", "")
            self.shodan_key = config.get("SHODAN_KEY", "")
            self.ipinfo_token = config.get("IPINFO_TOKEN", "")
            self.email_config = config.get("EMAIL", {})
            self.log_files = config.get("LOG_FILES", [LOG_FILE])
            self.alert_threshold = config.get("ALERT_THRESHOLD", 70)
            self.blacklist_ips = set(config.get("BLACKLIST_IPS", []))
        except Exception as e:
            logging.error(f"Error loading config file: {e}")
            self.abuseipdb_key = ""
            self.virustotal_key = ""
            self.shodan_key = ""
            self.ipinfo_token = ""
            self.email_config = {}
            self.log_files = [LOG_FILE]
            self.alert_threshold = 70
            self.blacklist_ips = set()
    
    async def initialize_session(self):
        self.session = ClientSession()
        
    async def close_session(self):
        if self.session:
            await self.session.close()
            
    def parse_logs(self):
        all_logs = []
        ip_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+)')
        login_pattern = re.compile(r'login attempt \[(.+?)/(.+?)\] failed')
        command_pattern = re.compile(r'Command found: (.+)')
        download_pattern = re.compile(r'Downloaded URL \((.+?)\) to: (.+)')
        timestamp_pattern = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})')
        
        for log_file in self.log_files:
            try:
                with open(log_file, "r") as f:
                    all_logs.extend(f.readlines())
            except Exception as e:
                logging.error(f"Error reading log file {log_file}: {e}")
        
        attacker_ips = set()
        for line in all_logs:
            try:
                timestamp_match = timestamp_pattern.search(line)
                if not timestamp_match:
                    continue
                    
                timestamp = datetime.fromisoformat(timestamp_match.group(1))
                
                ip_match = ip_pattern.search(line)
                if not ip_match:
                    continue
                    
                ip = ip_match.group(1)
                attacker_ips.add(ip)
                self.timestamps[ip].append(timestamp)
                
                login_match = login_pattern.search(line)
                if login_match:
                    username, password = login_match.group(1), login_match.group(2)
                    self.login_attempts[ip].append((username, password))
                    self.attack_types["credential_bruteforce"] += 1
                
                command_match = command_pattern.search(line)
                if command_match:
                    command = command_match.group(1)
                    self.commands_executed[ip].append(command)
                    
                    for category, patterns in self.command_categories.items():
                        if any(pattern in command for pattern in patterns):
                            self.attack_types[category] += 1
                
                download_match = download_pattern.search(line)
                if download_match:
                    url, path = download_match.group(1), download_match.group(2)
                    self.files_downloaded[ip].append((url, path))
                    self.attack_types["malware_download"] += 1
            except Exception as e:
                logging.error(f"Error processing log line: {e}")
                
        return attacker_ips
    
    async def get_geolocation(self, ip: str) -> Dict[str, Any]:
        try:
            headers = {}
            if self.ipinfo_token:
                headers["Authorization"] = f"Bearer {self.ipinfo_token}"
                
            async with self.session.get(IPINFO_API.format(ip), headers=headers, timeout=10) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    logging.warning(f"Failed to get geolocation for {ip}: Status {response.status}")
                    return {}
        except Exception as e:
            logging.error(f"Error getting geolocation for {ip}: {e}")
            return {}
    
    async def check_abuseipdb(self, ip: str) -> Dict[str, Any]:
        if not self.abuseipdb_key:
            return {"abuseConfidenceScore": 0}
            
        headers = {"Key": self.abuseipdb_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": "true"}
        try:
            async with self.session.get(ABUSEIPDB_API, headers=headers, params=params, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get("data", {"abuseConfidenceScore": 0})
                else:
                    logging.warning(f"Failed to check AbuseIPDB for {ip}: Status {response.status}")
                    return {"abuseConfidenceScore": 0}
        except Exception as e:
            logging.error(f"Error checking AbuseIPDB for {ip}: {e}")
            return {"abuseConfidenceScore": 0}
    
    async def check_virustotal(self, ip: str) -> Dict[str, Any]:
        if not self.virustotal_key:
            return {"malicious": 0, "suspicious": 0}
            
        headers = {"x-apikey": self.virustotal_key}
        try:
            async with self.session.get(VIRUSTOTAL_API.format(ip), headers=headers, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    analysis = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    return {
                        "malicious": analysis.get("malicious", 0),
                        "suspicious": analysis.get("suspicious", 0)
                    }
                else:
                    logging.warning(f"Failed to check VirusTotal for {ip}: Status {response.status}")
                    return {"malicious": 0, "suspicious": 0}
        except Exception as e:
            logging.error(f"Error checking VirusTotal for {ip}: {e}")
            return {"malicious": 0, "suspicious": 0}
    
    async def check_shodan(self, ip: str) -> Dict[str, Any]:
        if not self.shodan_key:
            return {}
            
        try:
            async with self.session.get(SHODAN_API.format(ip, self.shodan_key), timeout=10) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    logging.warning(f"Failed to check Shodan for {ip}: Status {response.status}")
                    return {}
        except Exception as e:
            logging.error(f"Error checking Shodan for {ip}: {e}")
            return {}
    
    async def process_ip(self, ip: str):
        if ip in self.blacklist_ips:
            return
            
        geo_data = await self.get_geolocation(ip)
        abuse_data = await self.check_abuseipdb(ip)
        vt_data = await self.check_virustotal(ip)
        shodan_data = await self.check_shodan(ip)
        
        city = geo_data.get("city", "Unknown")
        country = geo_data.get("country", "Unknown")
        org = geo_data.get("org", "Unknown")
        asn = geo_data.get("asn", "Unknown")
        isp = geo_data.get("isp", "Unknown")
        
        location = geo_data.get("loc", "0,0")
        try:
            lat, lon = map(float, location.split(","))
        except ValueError:
            lat, lon = 0.0, 0.0
        
        threat_score = abuse_data.get("abuseConfidenceScore", 0) * 0.6
        threat_score += min(vt_data.get("malicious", 0) * 10, 40) * 0.4
        
        open_ports = []
        services = []
        if shodan_data:
            open_ports = [p.get("port") for p in shodan_data.get("data", [])]
            services = [p.get("_shodan", {}).get("module") for p in shodan_data.get("data", [])]
        
        login_count = len(self.login_attempts.get(ip, []))
        command_count = len(self.commands_executed.get(ip, []))
        download_count = len(self.files_downloaded.get(ip, []))
        
        timestamps = self.timestamps.get(ip, [])
        first_seen = min(timestamps) if timestamps else None
        last_seen = max(timestamps) if timestamps else None
        attack_duration = (last_seen - first_seen).total_seconds() if first_seen and last_seen else 0
        
        sophistication = self._calculate_sophistication(ip)
        
        self.results[ip] = {
            "city": city,
            "country": country,
            "org": org,
            "asn": asn,
            "isp": isp,
            "lat": lat,
            "lon": lon,
            "threat_score": threat_score,
            "abuse_confidence": abuse_data.get("abuseConfidenceScore", 0),
            "vt_malicious": vt_data.get("malicious", 0),
            "vt_suspicious": vt_data.get("suspicious", 0),
            "open_ports": open_ports,
            "services": services,
            "login_attempts": self.login_attempts.get(ip, []),
            "unique_usernames": len(set(u for u, _ in self.login_attempts.get(ip, []))),
            "unique_passwords": len(set(p for _, p in self.login_attempts.get(ip, []))),
            "commands": self.commands_executed.get(ip, []),
            "downloads": self.files_downloaded.get(ip, []),
            "login_count": login_count,
            "command_count": command_count,
            "download_count": download_count,
            "first_seen": first_seen.isoformat() if first_seen else None,
            "last_seen": last_seen.isoformat() if last_seen else None,
            "attack_duration": attack_duration,
            "sophistication": sophistication
        }
        
        if threat_score > self.alert_threshold:
            logging.warning(f"⚠️ High threat attacker detected: {ip} (Score: {threat_score:.1f}) from {city}, {country}")
        else:
            logging.info(f"Processed {ip}: {city}, {country}, Threat: {threat_score:.1f}")
            
    def _calculate_sophistication(self, ip: str) -> int:
        score = 0
        
        usernames = set(u for u, _ in self.login_attempts.get(ip, []))
        passwords = set(p for _, p in self.login_attempts.get(ip, []))
        if len(usernames) > 10 or len(passwords) > 10:
            score += 2
        elif len(usernames) > 3 or len(passwords) > 3:
            score += 1
            
        commands = self.commands_executed.get(ip, [])
        unique_commands = set(commands)
        if len(unique_commands) > 15:
            score += 3
        elif len(unique_commands) > 5:
            score += 2
        elif len(unique_commands) > 0:
            score += 1
            
        categories_used = set()
        for cmd in commands:
            for category, patterns in self.command_categories.items():
                if any(pattern in cmd for pattern in patterns):
                    categories_used.add(category)
                    
        if "privilege_escalation" in categories_used:
            score += 2
        if "lateral_movement" in categories_used:
            score += 1
        if "persistence" in categories_used:
            score += 2
            
        if len(self.files_downloaded.get(ip, [])) > 0:
            score += 2
            
        return min(score, 10)
            
    async def analyze_ips(self, ips: Set[str]):
        tasks = [self.process_ip(ip) for ip in ips]
        await asyncio.gather(*tasks)
        
    def save_to_csv(self):
        csv_file = f"{OUTPUT_DIR}/attackers.csv"
        with open(csv_file, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([
                "IP Address", "City", "Country", "Organization", "ASN", "ISP",
                "Latitude", "Longitude", "Threat Score", "AbuseIPDB Score",
                "VT Malicious", "VT Suspicious", "Open Ports", "Services",
                "Login Attempts", "Unique Usernames", "Unique Passwords",
                "Command Count", "Download Count", "First Seen", "Last Seen",
                "Attack Duration (s)", "Sophistication (1-10)"
            ])
            
            for ip, data in self.results.items():
                writer.writerow([
                    ip, data["city"], data["country"], data["org"], data["asn"], data["isp"],
                    data["lat"], data["lon"], f"{data['threat_score']:.1f}", data["abuse_confidence"],
                    data["vt_malicious"], data["vt_suspicious"], 
                    ", ".join(str(p) for p in data["open_ports"]),
                    ", ".join(str(s) for s in data["services"]),
                    data["login_count"], data["unique_usernames"], data["unique_passwords"],
                    data["command_count"], data["download_count"], data["first_seen"], data["last_seen"],
                    data["attack_duration"], data["sophistication"]
                ])
        logging.info(f"Results saved to CSV: {csv_file}")
        return csv_file
        
    def save_to_json(self):
        json_file = f"{OUTPUT_DIR}/attackers.json"
        with open(json_file, "w") as jsonfile:
            json.dump(self.results, jsonfile, indent=4)
        logging.info(f"Results saved to JSON: {json_file}")
        return json_file
        
    def generate_basic_map(self):
        attacker_map = folium.Map(location=[20, 0], zoom_start=2)
        
        marker_cluster = MarkerCluster().add_to(attacker_map)
        
        for ip, data in self.results.items():
            if data["lat"] and data["lon"]:
                if data["threat_score"] > 80:
                    color = "darkred"
                elif data["threat_score"] > 50:
                    color = "red"
                elif data["threat_score"] > 20:
                    color = "orange"
                else:
                    color = "blue"
                    
                popup_html = f"""
                <b>IP:</b> {ip}<br>
                <b>Location:</b> {data['city']}, {data['country']}<br>
                <b>Organization:</b> {data['org']}<br>
                <b>Threat Score:</b> {data['threat_score']:.1f}<br>
                <b>First Seen:</b> {data['first_seen']}<br>
                <b>Last Seen:</b> {data['last_seen']}<br>
                <b>Login Attempts:</b> {data['login_count']}<br>
                <b>Commands Executed:</b> {data['command_count']}<br>
                <b>Files Downloaded:</b> {data['download_count']}<br>
                <b>Sophistication:</b> {data['sophistication']}/10
                """
                
                folium.Marker(
                    location=[data["lat"], data["lon"]],
                    popup=folium.Popup(popup_html, max_width=300),
                    icon=folium.Icon(color=color),
                    tooltip=f"{ip} - Threat: {data['threat_score']:.1f}"
                ).add_to(marker_cluster)
        
        heat_data = [[data["lat"], data["lon"], data["threat_score"]] 
                    for ip, data in self.results.items() 
                    if data["lat"] != 0 and data["lon"] != 0]
                    
        HeatMap(heat_data).add_to(attacker_map)
        
        map_file = f"{OUTPUT_DIR}/attackers_map.html"
        attacker_map.save(map_file)
        logging.info(f"Basic map saved to: {map_file}")
        return map_file
        
    def generate_advanced_report(self):
        df = pd.DataFrame.from_dict(self.results, orient='index')
        
        plots_dir = f"{OUTPUT_DIR}/plots"
        os.makedirs(plots_dir, exist_ok=True)
        
        self._plot_threat_distribution(df, plots_dir)
        self._plot_attack_timeline(df, plots_dir)
        self._plot_attack_types(plots_dir)
        self._plot_geographic_distribution(df, plots_dir)
        self._analyze_credential_patterns(plots_dir)
        self._analyze_command_patterns(plots_dir)
        
        report_file = f"{OUTPUT_DIR}/advanced_report.html"
        with open(report_file, "w") as f:
            f.write(self._generate_html_report(plots_dir))
            
        logging.info(f"Advanced report saved to: {report_file}")
        return report_file
        
    def _plot_threat_distribution(self, df, plots_dir):
        plt.figure(figsize=(10, 6))
        plt.hist(df['threat_score'], bins=20, color='red', alpha=0.7)
        plt.title('Distribution of Threat Scores')
        plt.xlabel('Threat Score')
        plt.ylabel('Number of Attackers')
        plt.grid(True, alpha=0.3)
        plt.savefig(f"{plots_dir}/threat_distribution.png")
        plt.close()
        
    def _plot_attack_timeline(self, df, plots_dir):
        timestamps = []
        for ip in self.results:
            for ts in self.timestamps.get(ip, []):
                timestamps.append(ts)
                
        if not timestamps:
            return
            
        timestamps.sort()
        df_time = pd.DataFrame({'timestamp': timestamps})
        df_time['date'] = df_time['timestamp'].dt.date
        df_time['hour'] = df_time['timestamp'].dt.hour
        
        daily_attacks = df_time.groupby('date').size()
        
        plt.figure(figsize=(12, 6))
        daily_attacks.plot(kind='line', marker='o')
        plt.title('Daily Attack Frequency')
        plt.xlabel('Date')
        plt.ylabel('Number of Events')
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig(f"{plots_dir}/daily_attacks.png")
        plt.close()
        
        hourly_attacks = df_time.groupby('hour').size()
        
        plt.figure(figsize=(10, 6))
        hourly_attacks.plot(kind='bar', color='navy', alpha=0.7)
        plt.title('Attacks by Hour of Day')
        plt.xlabel('Hour')
        plt.ylabel('Number of Events')
        plt.grid(True, alpha=0.3, axis='y')
        plt.tight_layout()
        plt.savefig(f"{plots_dir}/hourly_attacks.png")
        plt.close()
        
    def _plot_attack_types(self, plots_dir):
        if not self.attack_types:
            return
            
        sorted_types = dict(sorted(self.attack_types.items(), key=lambda x: x[1], reverse=True))
        
        plt.figure(figsize=(12, 7))
        bars = plt.barh(list(sorted_types.keys()), list(sorted_types.values()), color='darkgreen', alpha=0.7)
        plt.xlabel('Number of Events')
        plt.title('Attack Types Frequency')
        plt.grid(True, alpha=0.3, axis='x')
        
        for bar in bars:
            width = bar.get_width()
            plt.text(width + 0.5, bar.get_y() + bar.get_height()/2, f'{width}', ha='left', va='center')
            
        plt.tight_layout()
        plt.savefig(f"{plots_dir}/attack_types.png")
        plt.close()
        
    def _plot_geographic_distribution(self, df, plots_dir):
        if 'country' not in df.columns:
            return
            
        country_counts = df['country'].value_counts().head(15)
        
        plt.figure(figsize=(12, 7))
        bars = plt.barh(country_counts.index, country_counts.values, color='darkblue', alpha=0.7)
        plt.xlabel('Number of Attackers')
        plt.title('Top 15 Attacker Countries')
        plt.grid(True, alpha=0.3, axis='x')
        
        for bar in bars:
            width = bar.get_width()
            plt.text(width + 0.1, bar.get_y() + bar.get_height()/2, f'{width}', ha='left', va='center')
            
        plt.tight_layout()
        plt.savefig(f"{plots_dir}/country_distribution.png")
        plt.close()
        
    def _analyze_credential_patterns(self, plots_dir):
        all_usernames = []
        all_passwords = []
        
        for ip in self.results:
            for username, password in self.login_attempts.get(ip, []):
                all_usernames.append(username)
                all_passwords.append(password)
                
        if not all_usernames:
            return
            
        username_counts = Counter(all_usernames).most_common(10)
        usernames, username_freq = zip(*username_counts) if username_counts else ([], [])
        
        plt.figure(figsize=(12, 7))
        bars = plt.barh(usernames, username_freq, color='purple', alpha=0.7)
        plt.xlabel('Frequency')
        plt.title('Top 10 Attempted Usernames')
        plt.grid(True, alpha=0.3, axis='x')
        
        for bar in bars:
            width = bar.get_width()
            plt.text(width + 0.1, bar.get_y() + bar.get_height()/2, f'{width}', ha='left', va='center')
            
        plt.tight_layout()
        plt.savefig(f"{plots_dir}/top_usernames.png")
        plt.close()
        
        password_counts = Counter(all_passwords).most_common(10)
        passwords, password_freq = zip(*password_counts) if password_counts else ([], [])
        
        plt.figure(figsize=(12, 7))
        bars = plt.barh(passwords, password_freq, color='darkred', alpha=0.7)
        plt.xlabel('Frequency')
        plt.title('Top 10 Attempted Passwords')
        plt.grid(True, alpha=0.3, axis='x')
        
        for bar in bars:
            width = bar.get_width()
            plt.text(width + 0.1, bar.get_y() + bar.get_height()/2, f'{width}', ha='left', va='center')
            
        plt.tight_layout()
        plt.savefig(f"{plots_dir}/top_passwords.png")
        plt.close()
        
    def _analyze_command_patterns(self, plots_dir):
        all_commands = []
        
        for ip in self.results:
            all_commands.extend(self.commands_executed.get(ip, []))
                
        if not all_commands:
            return
            
        command_counts = Counter(all_commands).most_common(15)
        commands, cmd_freq = zip(*command_counts) if command_counts else ([], [])
        
        plt.figure(figsize=(12, 8))
        bars = plt.barh(commands, cmd_freq, color='teal', alpha=0.7)
        plt.xlabel('Frequency')
        plt.title('Top 15 Executed Commands')
        plt.grid(True, alpha=0.3, axis='x')
        
        for bar in bars:
            width = bar.get_width()
            plt.text(width + 0.1, bar.get_y() + bar.get_height()/2, f'{width}', ha='left', va='center')
            
        plt.tight_layout()
        plt.savefig(f"{plots_dir}/top_commands.png")
        plt.close()
        
    def _generate_html_report(self, plots_dir):
        total_attackers = len(self.results)
        high_threat_attackers = sum(1 for ip, data in self.results.items() if data["threat_score"] > self.alert_threshold)
        countries = Counter([data["country"] for ip, data in self.results.items() if data["country"] != "Unknown"])
        top_countries = countries.most_common(5)
        
        total_login_attempts = sum(data["login_count"] for ip, data in self.results.items())
        total_commands = sum(data["command_count"] for ip, data in self.results.items())
        total_downloads = sum(data["download_count"] for ip, data in self.results.items())
        
        all_timestamps = []
        for ip in self.results:
            all_timestamps.extend(self.timestamps.get(ip, []))
            
        first_attack = min(all_timestamps).strftime("%Y-%m-%d %H:%M:%S") if all_timestamps else "N/A"
        last_attack = max(all_timestamps).strftime("%Y-%m-%d %H:%M:%S") if all_timestamps else "N/A"
        
        avg_sophistication = sum(data["sophistication"] for ip, data in self.results.items()) / total_attackers if total_attackers > 0 else 0
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Honeypot Attack Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }}
                h1, h2, h3 {{ color: #2c3e50; }}
                .container {{ max-width: 1200px; margin: 0 auto; }}
                .header {{ background-color: #34495e; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
                .summary {{ display: flex; flex-wrap: wrap; gap: 20px; margin-bottom: 30px; }}
                .summary-box {{ flex: 1; min-width: 200px; background-color: #f9f9f9; border-radius: 5px; padding: 15px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
                .metric {{ font-size: 24px; font-weight: bold; color: #e74c3c; }}
                .section {{ margin-bottom: 30px; background-color: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
                th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f2f2f2; }}
                .threat-high {{ color: #c0392b; }}
                .threat-medium {{ color: #e67e22; }}
                .threat-low {{ color: #2980b9; }}"""
