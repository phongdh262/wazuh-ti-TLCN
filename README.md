# Wazuh TI Enrichment

Project demo tích hợp Wazuh với các nguồn Threat Intelligence. Cảnh báo từ Wazuh được gửi tới Flask API, tra cứu IoC rồi chấm điểm rủi ro và gửi thông báo qua Telegram.

```text
Wazuh -> custom-ti-enrichment -> Flask -> VirusTotal/AbuseIPDB/OTX -> Telegram
```

## Cách hoạt động

- Wazuh gọi `custom-ti-enrichment` khi cảnh báo khớp level và group trong `ossec.conf`.
- Script gửi file JSON của cảnh báo tới `http://127.0.0.1:8080/alert`.
- Ứng dụng lấy IP public, URL hoặc hash file để tra cứu TI.
- Kết quả được chấm điểm, phân loại và gửi Telegram nếu cần.
- Active Response do Wazuh xử lý riêng; Flask không trực tiếp chặn IP.

## Cài đặt

Yêu cầu Python 3.9 trở lên, `pip`, `venv`, `curl` và kết nối Internet.

```bash
git clone https://github.com/phongdh262/wazuh-ti-TLCN.git
cd wazuh-ti-TLCN

python3 -m venv .venv
.venv/bin/pip install Flask requests urllib3

cp .env.example .env
chmod 600 .env
```

Mở `.env` và điền API key của VirusTotal, AbuseIPDB, OTX cùng thông tin Telegram bot. Không đưa file `.env` hoặc API key thật lên Git.

Ứng dụng không tự đọc `.env`, nên cần nạp biến môi trường trước khi chạy:

```bash
set -a
. ./.env
set +a
.venv/bin/python app.py
```

Mặc định Flask chạy tại `127.0.0.1:8080`. Tài khoản chạy ứng dụng phải có quyền ghi vào `/var/ossec/logs/ti_enrichment.log`. Nếu chạy thử bằng tài khoản thường, có thể đặt `LOG_FILE=./ti_enrichment.log` trong `.env`.

## Kết nối với Wazuh

Cài integration script:

```bash
sudo install -o root -g wazuh -m 0750 \
  custom-ti-enrichment \
  /var/ossec/integrations/custom-ti-enrichment
```

Repo có sẵn hai file cấu hình:

- `ossec.conf`: cấu hình integration, FIM và Active Response.
- `local_rules.xml`: các rule tùy chỉnh.

Đây là cấu hình dùng cho máy lab. Nếu Wazuh đang có cấu hình riêng, hãy backup và merge phần cần thiết thay vì chép đè toàn bộ file.

Script đang dùng cố định địa chỉ `127.0.0.1:8080`, vì vậy Wazuh Manager và Flask cần chạy cùng máy.

Sau khi cập nhật cấu hình:

```bash
sudo systemctl restart wazuh-manager
sudo systemctl status --no-pager wazuh-manager
```

## Kiểm tra

```bash
bash -n custom-ti-enrichment
xmllint --noout ossec.conf local_rules.xml
curl http://127.0.0.1:8080/health
```

Các log cần xem khi có lỗi:

```text
/var/ossec/logs/integrations.log
/var/ossec/logs/ti_enrichment.log
/var/ossec/logs/active-responses.log
/var/ossec/logs/ossec.log
```

Theo dõi hai log chính:

```bash
sudo tail -F \
  /var/ossec/logs/integrations.log \
  /var/ossec/logs/ti_enrichment.log
```

## File chính

- `app.py`: Flask API nhận cảnh báo.
- `ti_enrichment.py`: tra cứu VirusTotal, AbuseIPDB và OTX.
- `risk_score.py`: tính điểm rủi ro.
- `alert_router.py`: phân loại và gửi Telegram.
- `config.py`: đọc biến môi trường.
- `custom-ti-enrichment`: chuyển alert từ Wazuh sang Flask.