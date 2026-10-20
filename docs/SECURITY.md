# An toàn, điều kiện giả định và phạm vi tấn công

## Tài sản cần bảo vệ

Tin nhắn, nội dung file, khóa bí mật RSA, khóa phiên AES. Server chỉ vận chuyển packet, không lưu private key. Thông tin người gửi, người nhận, loại gói, kích thước và thời điểm không được ẩn trong mẫu demo.

## Cơ chế hiện có

MSSV nối liền theo thứ tự nhóm, băm SHA256 để tạo `group_seed`, đúng định dạng bắt buộc của đề. Vì MSSV là thông tin dự đoán được, kết quả SHA256 **không thể tự bảo vệ** như bí mật. Triển khai dùng `group_seed` làm salt HKDF và bổ sung 32 byte CSPRNG secret trước khi bọc bằng RSA-OAEP. Cần trình bày rõ cách hiểu này trong báo cáo để tránh kết luận sai rằng SHA256 của MSSV đủ an toàn.

Khóa RSA 3072 bit được tạo tại Client, trao đổi public key ngoài băng. Gói khởi tạo khóa phiên ký bằng RSA-PSS và có session ID ngẫu nhiên. AES-256-GCM bảo mật và xác thực tin nhắn, tệp và các header được đưa vào AAD. Seq tăng được dùng để phát hiện phát lại trong phiên (session replay). Đầu ra tệp được xác minh SHA256 sau khi nhận.

## Kịch bản thử nghiệm hợp lệ trong lab

Thử nghiệm nghe lén: quan sát packet ở relay hoặc Wireshark, thấy `ciphertext` nhưng không thấy đoạn text thông điệp. Đây chỉ là kiểm tra minh họa, không chứng minh an toàn cho mọi trường hợp.

Thử nghiệm giả mạo: thay public key của Alice trong trust store Bob bằng public key Mallory; khi nhận `session_init` có chữ ký của Alice, Bob phải từ chối vì xác minh sai. Thử nghiệm này có trong `tests/test_session.py`, nhưng cần mô tả rủi ro bước phân phối khóa ban đầu.

Thử nghiệm toàn vẹn: chỉnh `seq` trong AAD hoặc ciphertext, AES-GCM từ chối vì tag không hợp lệ. Thử nghiệm replay: gửi lại packet đã được chấp nhận phải bị từ chối. Thử nghiệm file: sửa index của chunk dẫn đến từ chối.

## Những gì bản mẫu chưa bảo đảm

Không có cơ chế chứng thư số CA hoặc PKI để phân phối public key từ xa. Người sử dụng **phải tự xác minh** fingerprint đúng đối tượng qua kênh ngoài băng. Không có forward secrecy vì RSA-OAEP truyền khóa phiên: khi private key bị lộ về sau, kẻ đã ghi lại gói khởi tạo phiên có thể giải mã khóa phiên cũ. Có thể đề xuất X25519 kết hợp chứng thực để cải thiện trong tương lai nhưng không tự ý thay yêu cầu của đề.

Chưa có ratchet, timeout/rotation/cleanup khóa hoàn chỉnh, bảo vệ private key bằng mật khẩu, chống DoS/rate limit, replay persist qua restart, cơ chế khôi phục khi nhận file bị ngắt, xử lý nhiều phiên/thiết bị, hay xác thực tài khoản lên Server. Client chỉ từ chối tin nhắn giả mạo theo pinned key; tên đăng ký trên Server không phải là danh tính đã xác thực. Khóa bí mật demo đang lưu trên đĩa bằng PEM không mã hóa và chỉ phù hợp môi trường phát triển cục bộ (chmod 600 ở POSIX). Không nên dùng hệ thống với dữ liệu thật nhạy cảm.

Thử nghiệm chỉ được thực hiện trên môi trường riêng do nhóm sở hữu hoặc có quyền kiểm thử. Không thực hiện scan/tấn công vào hệ thống ngoài phạm vi lab.
