# Tình trạng thực tế của skeleton (ngày tạo)

| Hạng mục | Tình trạng | Ghi chú |
|---|---|---|
| Server TCP relay | **Có baseline chạy được** | Không có lưu trữ, rate-limit và nhận biết phiên offline hoàn chỉnh |
| Handshake `Hello, We are MSSV...` | **Có baseline** | Không phải xác thực người dùng lên Server |
| SHA256 MSSV trong KDF | **Có baseline** | Dùng làm HKDF salt với random secret, không phải khóa bí mật duy nhất |
| RSA-OAEP, RSA-PSS, AES-GCM | **Có baseline và test** | Chưa có forward secrecy, rotation hay protected key store |
| Xác thực pinned public key | **Có baseline và test** | Đòi hỏi người dùng kiểm chứng fingerprint ngoài băng |
| Chat mã hóa hai chiều | **Có baseline** | Hai phía phải lần lượt `/connect` để có khóa gửi |
| File transfer mã hóa | **Có baseline và test** | Giới hạn 20 MiB, chưa hỗ trợ resume/ACK |
| Kiểm thử chống MitM | **Có bài unit test** | Cần diễn tập có ảnh và phân tích threat model thực nghiệm |
| Video/kịch bản demo và báo cáo | **Chưa có** | Cần cả nhóm hoàn thiện trước khi nộp |
| README.doc, srcs, refs | **Đã tạo khung** | Nộp kèm bản cập nhật sau khi code hoàn thiện |

**Không dùng dấu 'baseline' để tuyên bố đã an toàn hoàn toàn.** Phải bổ sung test và minh chứng trước khi nộp; ghi trung thực về các hạn chế trong báo cáo.
