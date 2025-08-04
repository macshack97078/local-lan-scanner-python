import subprocess
import socket
import re
from concurrent.futures import ThreadPoolExecutor

# Funktion zum Scannen einer einzelnen IP-Adresse
def scan_ip(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = "Unbekannt"

    # Prüfen, ob Host online
    ping_result = subprocess.run(["ping", "-c", "1", "-W", "100", ip], stdout=subprocess.DEVNULL)
    if ping_result.returncode == 0:
        device_info = identify_device(ip)
        return f"{ip}\t{hostname}\t{device_info}\n"
    return None

# Funktion zum Erkennen des Gerätetyps anhand MAC-Adresse
def identify_device(ip):
    try:
        arp_result = subprocess.check_output(["arp", "-n", ip]).decode()
        mac_match = re.search(r'(([0-9a-f]{1,2}:){5}[0-9a-f]{1,2})', arp_result, re.I)
        if mac_match:
            mac = mac_match.group(0)
            oui = mac[:8].upper()
            # Einfache OUI-basierte Identifikation
            oui_db = {
                "F0:27:65": "Apple, Inc.",
                "00:1A:2B": "Cisco Systems",
                "3C:5A:B4": "Google, Inc.",
                # Weitere OUIs hier hinzufügen
            }
            return oui_db.get(oui, f"Unbekanntes Gerät ({mac})")
        else:
            return "MAC unbekannt"
    except subprocess.CalledProcessError:
        return "Gerät nicht identifizierbar"

# Netzwerkbereich festlegen (Beispiel für typisches Heimnetz)
network_prefix = "192.168.100."
ip_range = [f"{network_prefix}{i}" for i in range(1, 255)]

# Ergebnisse speichern
with ThreadPoolExecutor(max_workers=50) as executor:
    results = executor.map(scan_ip, ip_range)

    with open("lan_scan_ergebnis.txt", "w") as file:
        file.write("IP-Adresse\tHostname\tGerätetyp\n")
        file.write("-" * 50 + "\n")
        for result in results:
            if result:
                file.write(result)

print("Scan abgeschlossen. Ergebnisse in 'lan_scan_ergebnis.txt' gespeichert.")
