# Phân công công việc cho nhóm 4 thành viên

## Quy ước

Trên mỗi nhánh, giữ public API giữa các module theo `docs/PROTOCOL.md`. Người phụ trách có quyền chỉnh sửa file mình quản lý, nhưng không đổi giao diện hàm của người khác mà chưa thống nhất. Mọi công việc được nghiệm thu bằng Pull Request, review và test. `TODO[OWNER-N]` là các phần phát triển tiếp theo được đánh dấu sẵn trong code.

| Vai trò | Nhánh | Các file phụ trách | Nhiệm vụ cần hoàn thiện và minh chứng |
|---|---|---|---|
| Người 1: Mạng và tích hợp | `feature/owner1-server` | `protocol.py`, `server.py` | Nâng cấp lỗi kết nối/timeout, xử lý nhiều Client, kiểm thử relay, viết sơ đồ TCP và gói tin; bổ sung log không chứa plaintext |
| Người 2: Mật mã và giao thức | `feature/owner2-crypto` | `crypto.py`, `session.py` | Bảo vệ private key, xây dựng vòng đời khóa, kiểm thử sai chữ ký, replay, giả mạo khóa và giải thích HKDF từ MSSV |
| Người 3: Client và file transfer | `feature/owner3-client-file` | `client.py`, `transfer.py` | Thêm trải nghiệm CLI, ACK/trạng thái truyền file, xử lý lỗi giữa chừng, kiểm tra file sau khi nhận và demo hai chiều |
| Người 4: Kiểm thử và tài liệu | `feature/owner4-tests-docs` | `tests/`, `docs/`, `.github/`, `refs/` | Thực nghiệm chức năng & tấn công trong lab, chạy CI, viết kịch bản demo, tổng hợp báo cáo 20–30 trang và đóng gói cuối |

## Lịch làm việc trong 10 tuần đầu học kỳ

| Thời điểm | Việc chung | Mốc kiểm tra |
|---|---|---|
| Tuần 1 | Thống nhất MSSV, sơ đồ, Git rules, chạy thử khung | 4 máy/4 account clone và pytest thành công |
| Tuần 2 | Người 1 cải thiện server; Người 2 rà soát giao thức; Người 3 hoàn thiện CLI | Đăng ký handshake và relay ổn định |
| Tuần 3 | Người 1 kiểm thử nhiều kết nối; Người 2 hoàn thiện xác thực khóa | Demo trao đổi session key RSA-PSS |
| Tuần 4 | Người 2 đánh giá chống replay, giả mạo; Người 3 chat mã hóa | Chat hai chiều qua relay, plaintext không xuất hiện trong gói chat |
| Tuần 5–6 | Người 3 hoàn thiện file; Người 1 xử lý lỗi và tích hợp | Tệp thử nghiệm khớp SHA256 ở phía nhận |
| Tuần 7 | Người 4 chạy bộ test thường và test phá hỏng dữ liệu; cả nhóm sửa lỗi | CI xanh, bảng kết quả kiểm thử |
| Tuần 8 | Thử nghiệm MitM trong lab, phân tích giới hạn bảo mật | Có minh chứng khóa giả bị từ chối và lý giải điều kiện pinned keys |
| Tuần 9 | Hoàn thiện báo cáo Chương 1–4, sơ đồ, đánh giá, tham khảo | Bản nháp Word/PDF 20–30 trang |
| Tuần 10 | Code freeze, review, video demo, nén gói nộp | Source, README.doc, refs, báo cáo, `Assigment1.zip` |

Lịch trên là đề xuất; kiểm tra ngày giảng viên công bố chính thức. Đề bài ghi Bài tập lớn 1 nộp sau **10 tuần học**.

## Tiêu chí nghiệm thu riêng

**Người 1.** Server nhận tối thiểu hai client và định tuyến đúng, không có private key, không hiển thị nội dung tin nhắn, chặn sender không khớp kết nối. Bổ sung ít nhất hai test mới cho ngắt kết nối và tên trùng; có tài liệu luồng dữ liệu.

**Người 2.** Chứng minh RSA-OAEP dùng để chuyển khóa, RSA-PSS xác thực peer đã pin và AES-GCM bảo vệ dữ liệu; đáp ứng `SHA256(MSSV1||...)` theo đề nhưng không dùng MSSV công khai như secret. Thêm test khóa giả, chỉnh sửa chữ ký, phát lại và hết hạn phiên; tài liệu hóa điểm chưa bảo vệ được.

**Người 3.** Chat hai chiều bằng AES-GCM, gửi file ít nhất 0 KiB, 1 KiB và hơn 32 KiB, kiểm SHA256, lưu tệp đúng vị trí, lỗi truyền được báo rõ. Hỗ trợ tên file và dữ liệu Unicode ở phần demo.

**Người 4.** Ghi lại môi trường thử nghiệm, đầu vào, bước thực hiện, kết quả, ảnh/video demo, các test fail/pass và bảng đối chiếu yêu cầu. Các chương chuyên môn phải do người phụ trách kỹ thuật tự viết/kiểm tra rồi giao cho Người 4 tổng hợp.

## Phụ thuộc và giao tiếp

Người 1 và Người 2 thống nhất packet thông qua `protocol.py`/`docs/PROTOCOL.md`. Người 2 cung cấp `SessionManager.create_session_init`, `accept_session_init`, `encrypt_payload`, `decrypt_payload`. Người 3 chỉ gọi các API này, không tự chế AES/RSA. Người 4 tạo test dựa trên hợp đồng giao tiếp và mở Issue khi phát hiện lỗi, không tự ý sửa mã nguồn của 3 người khác mà thiếu review.

**Chạy kiểm thử trước mọi PR:** `python -m pytest -q`. CI tự chạy lại sau khi mở PR. Mỗi PR nên có ảnh/log có thể tái hiện; tuyệt đối không đưa private key vào ảnh chụp hoặc commit.
