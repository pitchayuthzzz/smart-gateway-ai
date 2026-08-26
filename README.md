# Smart Gateway: AI-Driven DNS Threat Prevention Engine

ระบบเกตเวย์อัจฉริยะสำหรับตรวจจับและป้องกันภัยคุกคามทางไซเบอร์ โดยการผสานรวมปัญญาประดิษฐ์ (AI) และการวิเคราะห์ทางสถิติเข้ากับ AdGuard Home เพื่อทำหน้าที่เป็น Local DNS Sinkhole อัตโนมัติ

## System Architecture
- **Core DNS Sinkhole:** AdGuard Home (Local DNS Resolver & Rules Filtering)
- **AI & Statistical Analysis:** Shannon Entropy, Heuristic Domain Feature Extraction และ Isolation Forest (Unsupervised Client Anomaly Detection)
- **Real-time Sniffing & Monitoring:** Scapy Packet Analyzer สำหรับดักจับ DNS Flooding
- **Dynamic Feedback Loop:** สั่งอัปเดต Custom Filtering Rules ผ่าน AdGuard Home REST API ภายในระดับวินาที

## Core Modules
- `adguard_client.py`: ตัวจัดการ AdGuard REST API สำหรับดึง Query Log และอัปเดต Blacklist
- `dga_detector.py`: โมดูลคำนวณ Shannon Entropy และวิเคราะห์ลักษณะ DGA พร้อมระบบ Whitelist
- `anomaly_detector.py`: โมเดล Isolation Forest สำหรับตรวจจับพฤติกรรมผิดปกติของ Client ในเครือข่าย
- `traffic_analyzer.py`: โมดูล Scapy ดักจับ Packet และตรวจจับการโจมตีแบบ DNS Flood
- `main.py`: ลูปการทำงานหลัก (Automation Loop) ที่รันเป็น Systemd Daemon Service
- `generate_graphs.py`: สคริปต์ประเมินผลและสร้างกราฟสถิติการตรวจจับ (Entropy & Confidence Score)
- `config.yaml`: ไฟล์ตั้งค่า Credential, Threshold และ Polling Interval ของระบบ

## Installation & Deployment
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
sudo systemctl enable --now ai-gateway.service
