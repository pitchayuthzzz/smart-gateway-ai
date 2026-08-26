import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from dga_detector import DGADetector

class ClientAnomalyDetector:
    def __init__(self, contamination=0.1):
        """
        contamination: สัดส่วนคาดการณ์ของพฤติกรรมผิดปกติ (เช่น 10%)
        """
        self.contamination = contamination
        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100
        )
        self.dga_detector = DGADetector()
        self.is_fitted = False

    def extract_features(self, query_logs: list) -> pd.DataFrame:
        """
        สกัด Feature เชิงพฤติกรรมต่อ 1 Client จาก Query Logs:
        1. total_queries: ปริมาณการยิงคำขอทั้งหมด
        2. unique_domains: จำนวนโดเมนที่ไม่ซ้ำ
        3. blocked_ratio: สัดส่วนที่ติด Blacklist
        4. avg_entropy: ค่า Entropy เฉลี่ยของโดเมนที่เรียก
        5. dga_suspect_count: จำนวนโดเมนที่เข้าข่าย DGA
        """
        if not query_logs:
            return pd.DataFrame()

        rows = []
        for entry in query_logs:
            client = entry.get("client", "unknown")
            domain = entry.get("question", {}).get("name", "")
            reason = entry.get("reason", "NotFiltered")
            is_blocked = 1 if reason != "NotFilteredNotFound" else 0
            
            dga_res = self.dga_detector.analyze(domain)
            
            rows.append({
                "client": client,
                "domain": domain,
                "is_blocked": is_blocked,
                "entropy": dga_res["entropy"],
                "is_dga": 1 if dga_res["is_dga"] else 0
            })

        df_raw = pd.DataFrame(rows)
        
        # จัดกลุ่มคำนวณตาม Client IP
        features = df_raw.groupby("client").agg(
            total_queries=("domain", "count"),
            unique_domains=("domain", "nunique"),
            blocked_ratio=("is_blocked", "mean"),
            avg_entropy=("entropy", "mean"),
            dga_suspect_count=("is_dga", "sum")
        ).reset_index()

        return features

    def train_and_predict(self, features_df: pd.DataFrame) -> pd.DataFrame:
        """ฝึกโมเดล Unsupervised และทำนายผล (-1 = ผิดปกติ, 1 = ปกติ)"""
        if features_df.empty or len(features_df) < 2:
            features_df["is_anomaly"] = False
            return features_df

        feature_cols = ["total_queries", "unique_domains", "blocked_ratio", "avg_entropy", "dga_suspect_count"]
        X = features_df[feature_cols]

        self.model.fit(X)
        self.is_fitted = True

        predictions = self.model.predict(X)
        # Isolation Forest คืนค่า -1 สำหรับ Anomaly และ 1 สำหรับข้อมูลปกติ
        features_df["is_anomaly"] = [True if p == -1 else False for p in predictions]
        
        # คำนวณ Anomaly Score ยิ่งติดลบมาก = ยิ่งผิดปกติมาก
        features_df["anomaly_score"] = self.model.decision_function(X)
        return features_df

if __name__ == "__main__":
    print("\n--- เริ่มต้นจำลองข้อมูลพฤติกรรม Client เพื่อทดสอบ ML ---")
    
    mock_logs = []
    
    # 1. จำลอง Client ทั่วไป 9 เครื่อง (ใช้งานเว็บปกติ 10-20 ครั้งต่อเครื่อง)
    for c_id in range(1, 10):
        client_ip = f"172.20.76.10{c_id}"
        normal_domains = ["google.com", "youtube.com", "facebook.com", "github.com", "wikipedia.org"]
        for _ in range(15):
            d = np.random.choice(normal_domains)
            mock_logs.append({
                "client": client_ip,
                "question": {"name": d},
                "reason": "NotFilteredNotFound"
            })

    # 2. จำลอง Client มุ่งร้าย 1 เครื่อง (172.20.76.200) ยิงโดเมนสุ่ม DGA ถี่ผิดปกติ 80 ครั้ง
    attacker_ip = "172.20.76.200"
    for _ in range(80):
        random_dga = f"malicious-{np.random.randint(10000, 99999)}-xypq{np.random.randint(10, 99)}.net"
        mock_logs.append({
            "client": attacker_ip,
            "question": {"name": random_dga},
            "reason": "NotFilteredNotFound"
        })

    detector = ClientAnomalyDetector(contamination=0.1)
    features_df = detector.extract_features(mock_logs)
    result_df = detector.train_and_predict(features_df)

    print(f"\n{'Client IP':<16} | {'Total':<6} | {'Unique':<6} | {'Avg Entropy':<11} | {'DGA Count':<9} | {'Verdict'}")
    print("-" * 75)
    for _, row in result_df.iterrows():
        verdict = "⚠️ ATTACKER / ANOMALY" if row["is_anomaly"] else "✅ NORMAL"
        print(f"{row['client']:<16} | {row['total_queries']:<6} | {row['unique_domains']:<6} | {row['avg_entropy']:<11.2f} | {row['dga_suspect_count']:<9} | {verdict}")
