import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

os.makedirs("evaluation_plots", exist_ok=True)

try:
    df = pd.read_csv("results.csv")
    if df.empty:
        print("[-] results.csv ไม่มีข้อมูล")
        exit()

    # ตั้งค่าสไตล์กราฟ
    plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')

    # กราฟที่ 1: การกระจายตัวของค่า Entropy โดเมนอันตรายที่ตรวจจับได้
    plt.figure(figsize=(8, 5))
    sns.histplot(df["entropy"], kde=True, color="crimson", bins=15)
    plt.axvline(x=3.5, color='black', linestyle='--', label='Threshold (3.5)')
    plt.title("Distribution of Shannon Entropy in Detected Threats", fontsize=14, pad=15)
    plt.xlabel("Shannon Entropy Score", fontsize=12)
    plt.ylabel("Threat Count", fontsize=12)
    plt.legend()
    plt.tight_layout()
    plt.savefig("evaluation_plots/entropy_distribution.png", dpi=300)
    plt.close()

    # กราฟที่ 2: ระดับความมั่นใจของโมเดล (Confidence Score Distribution)
    plt.figure(figsize=(8, 5))
    sns.countplot(data=df, x="confidence", hue="confidence", palette="Blues_r", legend=False)
    plt.title("Model Confidence Score on Detected Malicious Domains", fontsize=14, pad=15)
    plt.xlabel("Confidence Score", fontsize=12)
    plt.ylabel("Number of Detections", fontsize=12)
    plt.tight_layout()
    plt.savefig("evaluation_plots/confidence_distribution.png", dpi=300)
    plt.close()

    print("📊 สร้างกราฟสรุปผลการทดลองสำเร็จ:")
    print(" 1. evaluation_plots/entropy_distribution.png")
    print(" 2. evaluation_plots/confidence_distribution.png")

except Exception as e:
    print(f"[-] เกิดข้อผิดพลาด: {e}")
