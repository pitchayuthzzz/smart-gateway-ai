import time
import socket
import random

# รายชื่อโดเมนปกติ (Benign)
NORMAL_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "github.com",
    "wikipedia.org", "chula.ac.th", "ku.ac.th", "sanook.com",
    "pantip.com", "cloudflare.com", "microsoft.com", "netflix.com"
]

# สุ่มสร้างโดเมน DGA หลากหลายตระกูล
def generate_dga_domain():
    tlds = [".net", ".org", ".ru", ".biz", ".info", ".cc"]
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    name_len = random.randint(14, 22)
    name = "".join(random.choices(chars, k=name_len))
    return f"{name}{random.choice(tlds)}"

DNS_SERVER = "127.0.0.1"

def send_query(domain):
    try:
        # ใช้ socket จำลองการยิง DNS query
        addr = socket.gethostbyname(domain)
    except Exception:
        pass

print("🚀 เริ่มต้นส่ง Traffic จำลอง (ปกติ 30 ครั้ง / DGA 20 ครั้ง)...")

for i in range(1, 31):
    d = random.choice(NORMAL_DOMAINS)
    send_query(d)
    print(f"[{i}/30] Normal Query: {d}")
    time.sleep(0.3)

for i in range(1, 21):
    dga = generate_dga_domain()
    send_query(dga)
    print(f"[{i}/20] DGA Query: {dga}")
    time.sleep(0.5)

print("\n✅ ส่งชุดทดสอบเรียบร้อยแล้ว!")
