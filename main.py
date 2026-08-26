import time
import os
import csv
import yaml
import logging
from datetime import datetime
from adguard_client import AdGuardClient
from dga_detector import DGADetector
from anomaly_detector import ClientAnomalyDetector
from traffic_analyzer import DNSTrafficAnalyzer

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

def init_csv(filepath):
    if not os.path.exists(filepath):
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "client", "domain", "entropy", "confidence", "reasons", "action"])

def log_detection(filepath, client, domain, entropy, confidence, reasons, action):
    with open(filepath, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            client,
            domain,
            entropy,
            confidence,
            "; ".join(reasons),
            action
        ])

def run_loop():
    config = load_config()
    adguard_cfg = config["adguard"]
    detect_cfg = config["detection"]
    log_cfg = config["logging"]

    init_csv(log_cfg["results_file"])

    client = AdGuardClient(
        base_url=adguard_cfg["base_url"],
        username=adguard_cfg["username"],
        password=adguard_cfg["password"]
    )

    dga_detector = DGADetector(
        entropy_threshold=detect_cfg["entropy_threshold"],
        min_length=detect_cfg["min_length"]
    )
    anomaly_detector = ClientAnomalyDetector(
        contamination=detect_cfg["anomaly_contamination"]
    )

    # รัน Scapy Sniffer
    sniffer = DNSTrafficAnalyzer()
    sniffer.start()

    logging.info("🚀 Smart Gateway AI Engine แบบครบวงจรเริ่มทำงาน...")
    processed_queries = set()

    while True:
        try:
            logs = client.get_query_log(limit=adguard_cfg["query_limit"])
            if not logs:
                time.sleep(adguard_cfg["poll_interval_seconds"])
                continue

            new_malicious_domains = []

            for entry in logs:
                query_time = entry.get("time", "")
                domain = entry.get("question", {}).get("name", "")
                client_ip = entry.get("client", "")
                query_key = f"{query_time}_{client_ip}_{domain}"

                if query_key in processed_queries:
                    continue
                processed_queries.add(query_key)

                if len(processed_queries) > 5000:
                    processed_queries.clear()

                analysis = dga_detector.analyze(domain)
                if analysis["is_dga"] and analysis["confidence"] >= detect_cfg["auto_block_confidence"]:
                    logging.warning(f"🚨 ตรวจพบ DGA: {domain} จาก {client_ip} (Conf: {analysis['confidence']}, Entropy: {analysis['entropy']})")
                    new_malicious_domains.append(domain)
                    log_detection(
                        log_cfg["results_file"],
                        client_ip,
                        domain,
                        analysis["entropy"],
                        analysis["confidence"],
                        analysis["reasons"],
                        "AUTO_BLOCKED"
                    )

            if new_malicious_domains:
                unique_to_block = list(set(new_malicious_domains))[:detect_cfg["max_block_per_round"]]
                logging.info(f"🛡️ สั่งบล็อก {len(unique_to_block)} โดเมนเข้า AdGuard...")
                client.block_domains(unique_to_block)

            features_df = anomaly_detector.extract_features(logs)
            if len(features_df) >= 2:
                result_df = anomaly_detector.train_and_predict(features_df)
                anomalies = result_df[result_df["is_anomaly"] == True]
                for _, row in anomalies.iterrows():
                    logging.warning(f"⚠️ Anomaly Client: {row['client']} (Total: {row['total_queries']}, DGA: {row['dga_suspect_count']})")

        except Exception as e:
            logging.error(f"Error in Main Loop: {e}")

        time.sleep(adguard_cfg["poll_interval_seconds"])

if __name__ == "__main__":
    run_loop()
