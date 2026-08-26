import time
import socket
import random

NORMAL_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "github.com",
    "wikipedia.org", "chula.ac.th", "ku.ac.th", "sanook.com",
    "pantip.com", "cloudflare.com", "microsoft.com", "netflix.com",
    "apple.com", "amazon.com", "twitter.com", "instagram.com"
]

def generate_dga_domain():
    tlds = [".net", ".org", ".ru", ".biz", ".info", ".cc", ".xyz"]
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    name_len = random.randint(14, 24)
    name = "".join(random.choices(chars, k=name_len))
    return f"{name}{random.choice(tlds)}"

print("🔥 เริ่มต้นยิงชุดทดสอบเต็มรูปแบบ 100 รายการ...")

# 1. ยิงคำขอปกติ (Benign) 60 รายการ
for i in range(1, 61):
    d = random.choice(NORMAL_DOMAINS)
    try:
        socket.gethostbyname(d)
    except Exception:
        pass
    time.sleep(0.1)

# 2. ยิงคำขอ DGA 40 รายการ
for i in range(1, 41):
    dga = generate_dga_domain()
    try:
        socket.gethostbyname(dga)
    except Exception:
        pass
    time.sleep(0.2)

print("✅ ส่งชุดทดสอบครบ 100 รายการเรียบร้อย!")
