# Khung báo cáo kỹ thuật 20–30 trang

**Theo bố cục giảng viên:** Chương 1 Giới thiệu, Chương 2 Phân tích và thiết kế hệ thống, Chương 3 Hiện thực và đánh giá hệ thống, Chương 4 Kết luận, Tài liệu tham khảo và Phụ lục. Phần trọng tâm là Chương 2 và Chương 3.

| Phần | Trang gợi ý | Người đóng góp |
|---|---:|---|
| Trang bìa + Mục lục | 2 | Người 4 |
| Chương 1. Giới thiệu | 2–3 | Người 4 tổng hợp, mọi người duyệt |
| Chương 2. Phân tích và thiết kế hệ thống | 7–9 | Người 1 kiến trúc, Người 2 giao thức/crypto, Người 3 quy trình client/file |
| Chương 3. Hiện thực và đánh giá hệ thống | 9–11 | Người 1–3 viết hiện thực; Người 4 tổng hợp test, kết quả, ảnh demo |
| Chương 4. Kết luận | 2 | Cả nhóm thống nhất |
| Tài liệu tham khảo + Phụ lục | 2–3 | Người 4 chủ trì, mọi người cung cấp nguồn |

Phân trang tùy thực tế, đảm bảo **tổng nội dung cuối đúng 20–30 trang** theo hướng dẫn của giảng viên. Có thể dịch chuyển mục lục/phụ lục nếu giảng viên tính khác; không cần lặp văn bản hướng dẫn này trong báo cáo.

## Điểm cần có trong Chương 2

Mô tả yêu cầu, đối tượng và phạm vi; thiết kế kiến trúc Client Server; giao thức đăng ký, `session_init`, gói chat và file; cơ sở RSA-OAEP, RSA-PSS, AES-GCM, HKDF có salt SHA256 từ MSSV; phương pháp xác minh fingerprint; thiết kế threat model và kịch bản MitM. Phân biệt thực tế hệ thống làm được với mong muốn thiết kế.

## Điểm cần có trong Chương 3

Môi trường chạy và phiên bản thư viện; đoạn mã trọng tâm và hình minh họa; cách tạo khóa cục bộ; dữ liệu demo có MSSV; kết quả thử đúng/sai; đánh giá gửi file bằng hash SHA256; phân tích vai trò pinned key trong phòng MitM; bảng test với thực tế pass/fail; ưu/nhược điểm và các giới hạn còn tồn tại.

## Tham khảo và phụ lục

Chỉ trích dẫn tài liệu đã dùng. Ghi rõ tác giả/tổ chức, năm, tiêu đề, link theo APA khi cần. Phụ lục ghi cách cài đặt, lệnh chạy, công cụ mã nguồn mở, sơ đồ file và phần hỗ trợ demo. Không dán secret vào tài liệu.
