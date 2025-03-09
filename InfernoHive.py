import re
import json
import csv
import logging
import asyncio
import aiohttp
import folium
from aiohttp import ClientSession
from collections import defaultdict

LOG_FILE = "cowrie/log/cowrie.log"
OUTPUT_CSV = "attackers.csv"
OUTPUT_JSON = "attackers.json"
HTML_REPORT = "attackers_map.html"
IPINFO_API = "https://ipinfo.io/{}/json"
ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_KEY = "YOUR_ABUSEIPDB_API_KEY"

logging.basicConfig(filename="attacker_analysis.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def extract_ips():
    try:
        with open(LOG_FILE, "r") as f:
            logs = f.readlines()
        return set(re.findall(r'(\d+\.\d+\.\d+\.\d+)', " ".join(logs)))
    except Exception as e:
        logging.error(f"Error reading log file: {e}")
        return set()

async def get_geolocation(ip, session):
    try:
        async with session.get(IPINFO_API.format(ip), timeout=5) as response:
            return await response.json() if response.status == 200 else {}
    except:
        return {}

async def check_threat_level(ip, session):
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "30"}
    try:
        async with session.get(ABUSEIPDB_API, headers=headers, params=params, timeout=5) as response:
            return (await response.json()).get("data", {}).get("abuseConfidenceScore", 0) if response.status == 200 else 0
    except:
        return 0

async def process_ip(ip, session, results):
    geo_data = await get_geolocation(ip, session)
    threat_score = await check_threat_level(ip, session)
    city, country, org = geo_data.get("city", "Unknown"), geo_data.get("country", "Unknown"), geo_data.get("org", "Unknown")
    lat, lon = map(float, geo_data.get("loc", "0,0").split(","))
    results[ip] = {"city": city, "country": country, "org": org, "lat": lat, "lon": lon, "threat_score": threat_score}
    logging.info(f"Processed {ip}: {city}, {country}, Threat: {threat_score}")

async def analyze_ips():
    attacker_ips = extract_ips()
    results = {}
    async with ClientSession() as session:
        await asyncio.gather(*[process_ip(ip, session, results) for ip in attacker_ips])
    return results

def save_to_csv(results):
    with open(OUTPUT_CSV, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IP Address", "City", "Country", "Organization", "Latitude", "Longitude", "Threat Score"])
        for ip, data in results.items():
            writer.writerow([ip, data["city"], data["country"], data["org"], data["lat"], data["lon"], data["threat_score"]])

def save_to_json(results):
    with open(OUTPUT_JSON, "w") as jsonfile:
        json.dump(results, jsonfile, indent=4)

def generate_map(results):
    attacker_map = folium.Map(location=[20.5937, 78.9629], zoom_start=3)
    for ip, data in results.items():
        if data["lat"] and data["lon"]:
            color = "red" if data["threat_score"] > 50 else "blue"
            folium.Marker([data["lat"], data["lon"]], popup=f"IP: {ip}\n{data['city']}, {data['country']}\nThreat: {data['threat_score']}", icon=folium.Icon(color=color)).add_to(attacker_map)
    attacker_map.save(HTML_REPORT)

if __name__ == "__main__":
    results = asyncio.run(analyze_ips())
    save_to_csv(results)
    save_to_json(results)
    generate_map(results)
    print(f"✅ Analysis complete! Results saved in `{OUTPUT_CSV}` and `{OUTPUT_JSON}`. Open `{HTML_REPORT}` for the attack map.")
