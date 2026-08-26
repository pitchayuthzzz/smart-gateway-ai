import pandas as pd

try:
    df = pd.read_csv("results.csv")
    if df.empty:
        print("[-] ยังไม่มีข้อมูลใน results.csv")
    else:
        total_blocked = len(df)
        avg_entropy = df["entropy"].mean()
        avg_confidence = df["confidence"].mean()

        print("\n==============================================")
        print("       สรุปผลการประเมินประสิทธิภาพ (AI Gateway)     ")
        print("==============================================")
        print(f"จำนวนโดเมน DGA ที่ตรวจจับและบล็อกอัตโนมัติ : {total_blocked} รายการ")
        print(f"ค่าเฉลี่ย Entropy ของโดเมนอันตราย          : {avg_entropy:.2f}")
        print(f"ค่าเฉลี่ย Confidence Score                  : {avg_confidence:.2f}")
        print("----------------------------------------------")
        print("ตัวอย่างโดเมนที่ถูกสกัดกั้นล่าสุด:")
        print(df[["timestamp", "client", "domain", "entropy", "confidence"]].tail(5).to_string(index=False))
        print("==============================================\n")
except Exception as e:
    print(f"[-] เกิดข้อผิดพลาด: {e}")
