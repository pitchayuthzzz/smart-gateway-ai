import math
import re
from collections import Counter

class DGADetector:
    def __init__(self, entropy_threshold=3.5, min_length=12):
        self.entropy_threshold = entropy_threshold
        self.min_length = min_length
        self.whitelist = {"google", "youtube", "facebook", "github", "microsoft", "cloudflare", "apple"}

    def calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        counts = Counter(text)
        length = len(text)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())

    def extract_main_domain(self, domain: str) -> str:
        parts = domain.lower().strip().split(".")
        if len(parts) >= 2:
            return parts[-2]
        return parts[0]

    def analyze(self, domain: str) -> dict:
        main_name = self.extract_main_domain(domain)
        
        # 1. ตรวจสอบ Whitelist
        if any(w in domain.lower() for w in self.whitelist):
            return {
                "domain": domain,
                "main_name": main_name,
                "entropy": 0.0,
                "length": len(main_name),
                "is_dga": False,
                "confidence": 0.0,
                "reasons": ["Whitelisted"]
            }

        # คำนวณ Features
        entropy = self.calculate_entropy(main_name)
        length = len(main_name)
        digits = sum(c.isdigit() for c in main_name)
        digit_ratio = digits / length if length > 0 else 0
        
        # ตรวจสอบพยัญชนะติดกัน
        consonant_matches = re.findall(r'[bcdfghjklmnpqrstvwxyz]+', main_name)
        consonant_streak = max([len(m) for m in consonant_matches]) if consonant_matches else 0

        signals = 0
        reasons = []

        if entropy >= self.entropy_threshold:
            signals += 1
            reasons.append(f"High Entropy ({entropy:.2f})")

        if length >= self.min_length:
            signals += 1
            reasons.append(f"Long Name ({length})")

        if digit_ratio > 0.30:
            signals += 1
            reasons.append(f"High Digits ({digit_ratio:.0%})")

        if consonant_streak >= 5:
            signals += 1
            reasons.append(f"Consonants ({consonant_streak})")

        confidence = round(signals / 4.0, 2)
        is_dga = signals >= 2

        return {
            "domain": domain,
            "main_name": main_name,
            "entropy": round(entropy, 2),
            "length": length,
            "is_dga": is_dga,
            "confidence": confidence,
            "reasons": reasons
        }

if __name__ == "__main__":
    detector = DGADetector()
    
    test_domains = [
        "google.com",
        "youtube.com",
        "facebook.com",
        "gemini.google.com",
        "chulalongkorn.ac.th",
        "xk4j9qzplwe2f.com",
        "a9f8b7c6d5e4f3.net",
        "qwrtsdfgzxcv1234.org",
        "vznxkwperuqlamzo198.ru"
    ]

    print(f"\n{'Domain':<26} | {'Status':<10} | {'Entropy':<8} | {'Conf.':<6} | Reasons")
    print("-" * 75)
    for d in test_domains:
        res = detector.analyze(d)
        status = "MALICIOUS" if res["is_dga"] else "SAFE"
        reasons_str = ", ".join(res["reasons"]) if res["reasons"] else "Normal"
        print(f"{res['domain']:<26} | {status:<10} | {res['entropy']:<8} | {res['confidence']:<6} | {reasons_str}")
