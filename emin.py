import re
import json
import csv
from collections import defaultdict

# Log faylını oxumaq üçün fayl adı
log_file = "server_logs.txt"

# Regex modeli
log_pattern = r'(\d+\.\d+\.\d+\.\d+) - - \[([^\]]+)\] \"(GET|POST|PUT|DELETE) .*?\" (\d+)'

def parse_logs(log_file, log_pattern):
    """Log faylını oxuyur və məlumatları analiz edir."""
    failed_attempts = defaultdict(int)
    log_entries = []
    with open(log_file, "r") as file:
        for line in file:
            match = re.search(log_pattern, line)
            if match:
                ip, date, method, status = match.groups()
                log_entries.append({"ip": ip, "date": date, "method": method, "status": status})
                if status == "401":
                    failed_attempts[ip] += 1
    return log_entries, failed_attempts

def filter_high_risk_ips(failed_attempts, threshold=5):
    """5-dən çox uğursuz giriş edən IP-ləri seçir."""
    return {ip: count for ip, count in failed_attempts.items() if count > threshold}

def save_to_json(data, filename):
    """Məlumatları JSON faylına yazır."""
    with open(filename, "w") as json_file:
        json.dump(data, json_file, indent=4)

def save_to_txt(data, filename):
    """Məlumatları TXT faylına yazır."""
    with open(filename, "w") as txt_file:
        for ip, count in data.items():
            txt_file.write(f"{ip} - {count} failed attempts\n")

def save_to_csv(log_entries, failed_attempts, filename):
    """Məlumatları CSV faylına yazır."""
    with open(filename, "w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["IP Address", "Date", "HTTP Method", "Failed Attempts"])
        for entry in log_entries:
            ip = entry["ip"]
            failed_count = failed_attempts[ip]
            writer.writerow([entry["ip"], entry["date"], entry["method"], failed_count])

def match_threat_ips(failed_attempts, threat_intelligence):
    """Təhdid siyahısına uyğun IP-ləri seçir."""
    return {ip: failed_attempts[ip] for ip in threat_intelligence if ip in failed_attempts}

def combine_security_data(high_risk_ips, threat_match):
    """Məlumatları birləşdirir."""
    return {
        "failed_logins": high_risk_ips,
        "threat_ips": threat_match,
    }

def main():
    # Logları analiz etmək
    log_entries, failed_attempts = parse_logs(log_file, log_pattern)

    # 5-dən çox uğursuz giriş edən IP-ləri tapmaq
    high_risk_ips = filter_high_risk_ips(failed_attempts)

    # Faylları yaratmaq
    save_to_json(high_risk_ips, "failed_logins.json")
    save_to_txt(failed_attempts, "log_analysis.txt")
    save_to_csv(log_entries, failed_attempts, "log_analysis.csv")

    # Təhdid siyahısına uyğunluq
    threat_intelligence = ["192.168.1.11", "10.0.0.15"]  # Təhdid siyahısı
    threat_match = match_threat_ips(failed_attempts, threat_intelligence)
    save_to_json(threat_match, "threat_ips.json")

    # Birləşdirilmiş məlumatları saxla
    combined_data = combine_security_data(high_risk_ips, threat_match)
    save_to_json(combined_data, "combined_security_data.json")

    print("Analiz tamamlandı və fayllar yaradıldı.")

if __name__ == "__main__":
    main()
