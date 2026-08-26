import requests
import json

class AdGuardClient:
    def __init__(self, base_url, username, password):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.is_logged_in = False

    def login(self):
        url = f"{self.base_url}/control/login"
        payload = {"name": self.username, "password": self.password}
        try:
            res = self.session.post(url, json=payload, timeout=5)
            if res.status_code == 200:
                self.is_logged_in = True
                print("[+] เข้าสู่ระบบ AdGuard API สำเร็จ")
                return True
            print(f"[-] ล็อกอินไม่สำเร็จ: HTTP {res.status_code}")
            return False
        except Exception as e:
            print(f"[-] เกิดข้อผิดพลาดในการเชื่อมต่อ: {e}")
            return False

    def get_query_log(self, limit=50):
        if not self.is_logged_in and not self.login():
            return []
        url = f"{self.base_url}/control/querylog"
        res = self.session.get(url, params={"limit": limit})
        if res.status_code == 200:
            return res.json().get("data", [])
        return []

    def get_custom_rules(self):
        if not self.is_logged_in and not self.login():
            return []
        url = f"{self.base_url}/control/filtering/status"
        res = self.session.get(url)
        if res.status_code == 200:
            return res.json().get("user_rules", [])
        return []

    def block_domains(self, new_domains):
        if not self.is_logged_in and not self.login():
            return False
        current_rules = self.get_custom_rules()
        added_count = 0

        for domain in new_domains:
            rule = f"||{domain}^"
            if rule not in current_rules:
                current_rules.append(rule)
                added_count += 1

        if added_count == 0:
            print("[i] ไม่มีโดเมนใหม่ที่ต้องเพิ่มเข้า Blacklist")
            return True

        url = f"{self.base_url}/control/filtering/set_rules"
        payload = {"rules": current_rules}
        res = self.session.post(url, json=payload)
        if res.status_code == 200:
            print(f"[+] บล็อกสำเร็จ: เพิ่ม {added_count} โดเมนใหม่เข้า Custom Rules แล้ว")
            return True
        return False

if __name__ == "__main__":
    # เชื่อมต่อ API ด้วยรหัสผ่านที่ระบุ
    client = AdGuardClient(base_url="http://127.0.0.1", username="project", password="12345678")
    
    # 1. ทดสอบดึง Query Log
    logs = client.get_query_log(limit=5)
    print(f"\n--- รายการ Query Log ล่าสุด ({len(logs)} รายการ) ---")
    for log in logs:
        domain = log.get("question", {}).get("name")
        client_ip = log.get("client")
        reason = log.get("reason", "NotFiltered")
        print(f"Client: {client_ip:<15} | Domain: {domain:<30} | Reason: {reason}")

    # 2. ทดสอบสั่งบล็อกโดเมนผ่านโค้ด
    print("\n--- ทดสอบสั่งบล็อกผ่าน Python ---")
    client.block_domains(["test-ai-blocked-domain.com"])
