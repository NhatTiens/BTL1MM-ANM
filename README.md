# BTL 1.1 | E2EE Chat & Encrypted File Transfer

**Môn học:** Mật mã và An ninh mạng | **Nhóm:** 4 thành viên | **Ngôn ngữ:** Python 3.10+

Repository khởi động cho đề **1.1. Xây dựng hệ thống Chat và truyền tệp mã hóa đầu cuối**. Mục đích là giúp 4 thành viên làm việc qua Git và Pull Request, mỗi người có module riêng. **Đây là bản chạy mẫu tối thiểu, chưa phải sản phẩm cuối cùng đạt mọi tiêu chí bảo mật.**

## 1. Tính năng có sẵn (để bắt đầu)

- TCP Server chuyển tiếp gói tin giữa hai Client; Server không nắm giữ private key hay giải mã tin nhắn.
- Phân khung gói tin JSON có length prefix, kiểm tra tên, định danh người gửi và phiên bản giao thức.
- Handshake đăng ký bắt đầu bằng `Hello, We are MSSV_1, MSSV_2, ...`.
- KDF sử dụng `SHA256(MSSV_1 || MSSV_2 || ...)` làm **salt**, kết hợp bí mật ngẫu nhiên trong HKDF (MSSV không phải secret).
- Khởi tạo khóa phiên AES-256 bằng RSA-OAEP; ký gói khởi tạo bằng RSA-PSS; xác thực khóa công khai qua file trusted peer đã kiểm tra ngoài băng.
- Chat dùng AES-256-GCM và chống phát lại bằng bộ đếm thứ tự tăng dần.
- Truyền file theo chunk đã mã hóa, xác minh SHA256 sau khi nhận (mặc định giới hạn 20 MiB cho demo).
- 113 trường hợp kiểm thử trên Linux sau cập nhật Người 1; GitHub Actions chạy test khi tạo Pull Request. Chi tiết phạm vi, kết quả và giới hạn trong `docs/OWNER1_NETWORK.md`.

**Chưa hoàn thiện:** gia hạn khóa và dọn phiên cũ, tự động khôi phục kết nối, ACK và retry khi mất mạng, cải thiện giao diện, kiểm thử tấn công trong môi trường phòng lab, tài liệu báo cáo cuối cùng. Xem `docs/PROJECT_STATUS.md`.

## 2. Khởi động trong 5 phút

Đứng tại thư mục gốc repo, mở terminal:

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS / Linux: source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest -q
```

Nếu dùng Windows CMD thì thay câu lệnh cài bằng `python -m pip install -e .[dev]`.

**Chỉ chạy một lần để tạo hai danh tính thử nghiệm** (private keys nằm trong `.local/`, đã bị chặn bởi `.gitignore`):

```bash
securechat-demo-setup
```

Nếu `securechat-*` chưa có trong PATH, dùng `python -m securechat.demo_setup` và `python -m securechat.server/client` thay thế.

Thay `2312345,2312346,2312347,2312348` trong các lệnh dưới đây bằng **MSSV thật của cả nhóm, cùng một thứ tự**. Giá trị demo chỉ là ví dụ, không được nộp nguyên.

**Terminal 1: Server**

```bash
securechat-server --host 127.0.0.1 --port 9009
```

**Terminal 2: Alice**

```bash
securechat-client --name alice --mssvs 2312345,2312346,2312347,2312348
```

**Terminal 3: Bob**

```bash
securechat-client --name bob --mssvs 2312345,2312346,2312347,2312348
```

Tại Alice nhập:

```text
/peers
/connect bob
/msg bob Xin chao, day la thong diep AES-GCM
/file bob sample_data/hello.txt
```

Tại Bob nhập:

```text
/connect alice
/msg alice Bob da nhan duoc tin nhan
```

Khi gửi file xong, Bob sẽ nhận tệp trong `.local/received/bob/`. Dùng `/quit` để thoát. `/connect` chỉ thiết lập **khóa gửi từ phía Client đang gọi**: Alice `/connect bob` thì Bob đọc được Alice; Bob `/connect alice` để gửi tin nhắn phản hồi.

**Quan trọng:** Script tạo demo tự động sao chép các khóa công khai để tiện chạy trên localhost. Khi triển khai thực tế, nhóm phải kiểm tra fingerprint SHA256 bằng kênh tin cậy độc lập trước khi đưa khóa công khai vào `trusted/<client>.pem`. Việc tự động tin mọi khóa qua Server sẽ tạo lỗ hổng MitM.

## 3. Cấu trúc repo và phân công

```text
e2ee-chat-btl1/
├── srcs/securechat/
│   ├── protocol.py         # NGƯỜI 1 - đóng gói dữ liệu, framing
│   ├── server.py           # NGƯỜI 1 - TCP relay, client registry
│   ├── crypto.py           # NGƯỜI 2 - RSA, AES, SHA256, HKDF, chữ ký
│   ├── session.py          # NGƯỜI 2 - handshake, quản lý khóa, chống replay
│   ├── client.py           # NGƯỜI 3 - giao diện lệnh, chat TCP
│   ├── transfer.py         # NGƯỜI 3 - gửi nhận file mã hóa
│   └── demo_setup.py       # tạo RSA test key local
├── tests/                  # NGƯỜI 4 - unit, integration, security tests
├── docs/                   # NGƯỜI 4 chủ trì, 3 người cùng góp nội dung
│   ├── TEAM_TASKS.md
│   ├── ARCHITECTURE.md
│   ├── PROTOCOL.md
│   ├── SECURITY.md
│   ├── TEST_PLAN.md
│   ├── REPORT_OUTLINE.md
│   ├── PROJECT_STATUS.md
│   └── REQUIREMENTS_CHECKLIST.md
├── refs/                   # nguồn tham khảo và giấy phép liên quan
├── sample_data/            # dữ liệu thử không nhạy cảm
├── .github/workflows/ci.yml
├── .github/pull_request_template.md
├── .gitignore
├── README.doc              # hướng dẫn Word theo yêu cầu đề bài
├── README.md
├── pyproject.toml
└── requirements.txt
```

Chi tiết nhiệm vụ và tiêu chí nghiệm thu: **`docs/TEAM_TASKS.md`**. Một file có một người chịu trách nhiệm chính; sửa module của người khác chỉ qua Pull Request có review.

## 4. Quy trình Git cho 4 người

Người đại diện tạo repo **private**, đẩy khung lên nhánh `main`, thêm 3 thành viên vào quyền truy cập. Nhớ không đưa `.local/`, private key hoặc file `.env` lên GitHub.

```bash
git init
git add .
git commit -m "chore: bootstrap E2EE chat group project"
git branch -M main
git remote add origin https://github.com/USERNAME/REPO.git
git push -u origin main
```

Mỗi thành viên tạo nhánh riêng sau khi clone. Ví dụ Người 2:

```bash
git clone https://github.com/USERNAME/REPO.git
cd REPO
git switch -c feature/owner2-crypto
```

Sau khi sửa `srcs/securechat/crypto.py` và `session.py`, chạy test:

```bash
python -m pytest -q
git add srcs/securechat/crypto.py srcs/securechat/session.py tests/
git commit -m "feat: improve session key handling"
git push -u origin feature/owner2-crypto
```

Trên GitHub bấm **Compare & pull request**, đề nghị tối thiểu một thành viên khác review và chỉ Merge khi CI xanh. Nhánh gợi ý: `feature/owner1-server`, `feature/owner2-crypto`, `feature/owner3-client-file`, `feature/owner4-tests-docs`.

## 5. Lưu ý bảo mật

Không commit key bí mật, không dùng MSSV làm khóa AES duy nhất, không tự động chấp nhận public key nhận từ Internet, không log nội dung tin nhắn/file ở Server, không bỏ xác thực RSA-PSS hay AES-GCM. Xem `docs/SECURITY.md` để hiểu mô hình đe dọa và các giới hạn hiện tại. **Chỉ chạy thử tấn công trên các Client/Server do nhóm tự dựng và được phép thử nghiệm.**

## 6. Trước khi nộp

Theo đề, nộp source/hướng dẫn sử dụng (`README.doc`, `srcs`, `refs`), báo cáo kỹ thuật 20–30 trang gồm Chương 1 đến Chương 4 và tài liệu tham khảo; đóng gói thành `Assigment1.zip`. *Bản ZIP này là khung repository để phát triển, không phải gói nộp cuối cùng.*

**Mọi thay đổi về format packet cần cập nhật `docs/PROTOCOL.md` và test tương ứng trước khi Merge.**

## Bàn giao Người 1

Xem `docs/OWNER1_NETWORK.md` để biết thay đổi TCP Server, Protocol, kết quả tích hợp Alice và Bob, hướng dẫn áp dụng patch và các giới hạn còn tồn tại. Server mặc định tối đa 64 kết nối, handshake timeout 10 giây và I/O timeout 60 giây; có thể cấu hình qua `--max-connections`, `--handshake-timeout`, `--idle-timeout`. Dùng `--debug` để xem sự kiện định tuyến, không ghi nội dung packet.
