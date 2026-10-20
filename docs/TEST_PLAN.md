# Kế hoạch kiểm thử - Người 4 chủ trì

## Tự động hóa

Chạy `python -m pytest -q` trước mỗi Pull Request. Các bài test hiện có: framing, kích thước packet, SHA256 từ MSSV, AES-GCM, RSA-OAEP/PSS, signed handshake, pinned key giả, phát lại, integrity AAD, relay server, gửi file encrypted/empty/tamper. Đưa hình kết quả CI và log không chứa secret vào báo cáo.

## Kịch bản kiểm thử thủ công cần ghi kết quả

| Mã | Điều kiện và thao tác | Kết quả mong đợi | Phụ trách |
|---|---|---|---|
| FT01 | Khởi động 1 Server, 2 Client, `/peers` | Server hiện đúng cả hai tên | 1 và 4 |
| FT02 | Alice `/connect bob`, gửi `/msg bob Hello` | Bob giải mã đúng, Server chỉ thấy ciphertext | 2 và 4 |
| FT03 | Bob `/connect alice`, gửi phản hồi | Chat hai chiều bằng hai khóa gửi độc lập | 2 và 3 |
| FT04 | Alice gửi file 0 byte và file nhiều hơn 32 KiB | Bob nhận file, SHA256 khớp | 3 và 4 |
| SEC01 | Replay lại encrypted packet vào Bob | Client từ chối vì seq cũ | 2 và 4 |
| SEC02 | Sửa AAD/ciphertext trong packet | AES-GCM xác thực thất bại | 2 và 4 |
| SEC03 | Đổi pinned public key thành key Mallory | RSA-PSS signature không hợp lệ | 2 và 4 |
| SEC04 | Chưa có public key Bob trong thư mục trusted | Alice không được khởi tạo session | 2 và 4 |
| ERR01 | Bob offline, Alice chuyển tin | Server báo offline, không lưu plaintext | 1 và 4 |
| ERR02 | Trùng username khi đăng nhập Server | Server từ chối Client thứ hai | 1 và 4 |
| ERR03 | Ngắt kết nối giữa chừng lúc truyền file | Có thông báo lỗi, xử lý phần `.part` | 3 và 4 |

Mọi kết quả phải ghi ngày, môi trường Python, mã commit, từng bước tái hiện, kết quả thực tế và ảnh minh chứng. Một test có trong danh sách chưa được coi là đạt nếu chưa thực hiện và ghi log.
