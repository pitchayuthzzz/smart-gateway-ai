import math
from collections import Counter

class DGADetector:
    def __init__(self, entropy_threshold=3.6, min_length=13):
        self.entropy_threshold = entropy_threshold
        self.min_length = min_length
        # รายชื่อ Whitelist โดเมนและบริการมาตรฐานที่พบบ่อย
        self.whitelist_keywords = [
            "google", "youtube", "facebook", "github", "microsoft", 
            "apple", "cloudflare", "captcha-delivery", "datadome",
            "recaptcha", "akamai", "live", "office"
        ]

    def _extract_core_domain(self, domain: str) -> str:
        parts = domain.strip().lower().split(".")
        if len(parts) >= 2:
            # ดึงเฉพาะชื่อหลัก เช่น "captcha-delivery" จาก "geo.captcha-delivery.com"
            return parts[-2]
        return parts[0]

    def calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        length = len(text)
        counts = Counter(text)
        return -sum((c / length) * math.log2(c / length) for c in counts.values())

    def analyze(self, domain: str) -> dict:
        domain = domain.strip().lower()
        
        # 1. ข้ามถ้าอยู่ใน Whitelist Keywords
        for kw in self.whitelist_keywords:
            if kw in domain:
                return {
                    "domain": domain,
                    "is_dga": False,
                    "confidence": 0.0,
                    "entropy": 0.0,
                    "reasons": ["Whitelisted Service"]
                }

        core_name = self._extract_core_domain(domain)
        entropy = self.calculate_entropy(core_name)
        length = len(core_name)

        reasons = []
        score = 0.0

        # เงื่อนไขการตรวจจับ
        if entropy >= self.entropy_threshold and length >= self.min_length:
            score += 0.5
            reasons.append(f"High Entropy ({entropy:.2f})")

        digit_count = sum(c.isdigit() for c in core_name)
        if length > 0 and (digit_count / length) > 0.35:
            score += 0.25
            reasons.append(f"High Digit Ratio ({digit_count}/{length})")

        is_dga = score >= 0.5

        return {
            "domain": domain,
            "core_name": core_name,
            "is_dga": is_dga,
            "confidence": min(score, 1.0),
            "entropy": round(entropy, 2),
            "reasons": reasons
        }
