# Đối chiếu yêu cầu gốc của đề 1.1

| Yêu cầu trong đề | File/Minh chứng | Mức hiện tại | Cần làm trước khi nộp |
|---|---|---|---|
| Demo Client Server chat | `server.py`, `client.py` | Baseline | Kiểm thử hai máy khác nhau và quay demo |
| Truyền tệp mã hóa | `transfer.py` | Baseline | Test file và tình huống mất kết nối, ảnh minh họa |
| RSA hoặc DH trao đổi khóa phiên | `crypto.py`, `session.py` | RSA-OAEP | Viết giải thích và phân tích hệ quả thiếu forward secrecy |
| AES bảo mật dữ liệu | `crypto.py` | AES-GCM | Chụp packet ví dụ, diễn giải nonce/AAD |
| HMAC/chữ ký số xác thực | `crypto.py` | RSA-PSS ký handshake | Thêm ảnh kiểm thử giả mạo và nêu phạm vi xác thực |
| Phân tích an toàn trước nghe lén/MitM | `SECURITY.md`, tests | Bước đầu | Thí nghiệm, báo cáo chi tiết cả giới hạn và giả định pinned keys |
| Hello handshake có MSSV | `client.py`, `crypto.py` | Có | Thay MSSV mẫu bằng MSSV thật, kiểm tra thứ tự |
| KDF SHA256(MSSV_1 || MSSV_2...) | `crypto.group_seed` | Có | Giải thích không dùng MSSV như secret duy nhất |
| README.doc, srcs, refs | Gốc repository | Đã tạo | Cập nhật README.doc theo phiên bản cuối |
| Báo cáo kỹ thuật Chương 1–4, 20–30 trang | `REPORT_OUTLINE.md` | Chưa viết | Viết Word/PDF, kiểm tra số trang |
| Đóng gói `Assigment1.zip` | Chưa tạo | Chưa nộp | Nén source, README.doc, refs và báo cáo bản cuối |

**Yêu cầu không xuất hiện trong đề thì là đề xuất kỹ thuật** để giúp nhóm làm rõ hơn, không phải bắt buộc do giảng viên quy định. Đọc file đề gốc trước khi bảo vệ.
