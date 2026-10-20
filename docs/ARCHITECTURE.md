# Kiến trúc hệ thống

```text
                 Kênh xác thực fingerprint ngoài băng
           +---------------------------------------------+
           |                                             |
   +----------------+                          +----------------+
   | Client Alice   |                          | Client Bob     |
   | RSA private A  |                          | RSA private B  |
   | Pinned pub B   |                          | Pinned pub A   |
   | AES-GCM keys   |                          | AES-GCM keys   |
   +--------+-------+                          +--------+-------+
            |                                           |
            |   Packet (ciphertext, signed handshake)   |
            |           +-------------------+           |
            +-----------|  TCP Relay Server |-----------+
                        | No private keys   |
                        | Forward only      |
                        +-------------------+
```

## Luồng kết nối

Client gửi `hello` chứa chuỗi `Hello, We are MSSV_1, MSSV_2, ...`, phiên bản và hash SHA256 của MSSV nối liền. Server đăng ký username và trả `welcome`. `hello` là **thông điệp khởi tạo đăng ký không chứa dữ liệu người dùng riêng tư**, không phải bằng chứng xác thực của người gửi.

Alice đã lưu khóa công khai của Bob trong thư mục tin cậy sau khi đối chiếu fingerprint qua một kênh khác. Alice sinh bí mật ngẫu nhiên và sử dụng `SHA256(MSSV_1 || ...)` làm salt để dẫn xuất khóa phiên bằng HKDF. Alice bọc khóa AES bằng RSA-OAEP dưới khóa công khai của Bob, ký gói `session_init` bằng RSA-PSS và gửi qua Server. Bob xác minh chữ ký nhờ khóa công khai của Alice đã được pin và dùng private key để mở khóa phiên.

Alice có thể gửi chat/file cho Bob ngay sau `/connect bob`. Muốn Bob gửi lại, Bob tạo khóa phiên chiều Bob → Alice qua `/connect alice`. Thiết kế khóa theo từng chiều giúp cô lập counter và khóa mã hóa của mỗi phía.

Mỗi gói dữ liệu được bảo vệ bằng AES-GCM. Header gồm người gửi, người nhận, session ID, sequence number, loại packet và thông tin chuyển file được xác thực dưới dạng AAD. Server chuyển tiếp packet, không có key để giải mã nội dung. Gói có `seq` cũ, AAD bị sửa, hoặc session không được xác minh sẽ bị Client từ chối.

## Các lớp và giao diện

`protocol.py`: `send_packet(sock, dict)`, `recv_packet(sock) -> dict`, `canonical_json(dict) -> bytes`.

`crypto.py`: `group_seed`, `handshake_text`, `make_session_key`, `wrap_key`, `unwrap_key`, `sign_object`, `verify_object`, `encrypt`, `decrypt`.

`session.py`: `SessionManager.create_session_init(peer) -> dict`, `accept_session_init(packet) -> peer`, `encrypt_payload(kind, peer, data, **metadata) -> dict`, `decrypt_payload(packet) -> bytes`.

`transfer.py`: `send_file(session, peer, path, send_fn) -> transfer_id` và `FileReceiver.handle(packet, session) -> saved_path | None`.

`server.py`: `RelayServer`, `RelayHandler` chỉ định tuyến. `client.py`: `ChatClient` nhận lệnh và hiển thị thông tin.

## Lưu ý khi tích hợp

Kích thước khung tối đa 512 KiB; mỗi chunk file 32 KiB. Server được phép biết tên tài khoản, người nhận, loại bản tin, thời điểm và lưu lượng, nhưng không được có private key hay log plaintext. Bản mẫu không che giấu metadata giao thông và không cung cấp tính sẵn sàng khi Server ngắt kết nối.
