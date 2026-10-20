# Hợp đồng giao tiếp (không đổi nếu chưa đồng thuận cả nhóm)

**Transport:** TCP, mỗi frame gồm 4 byte unsigned big-endian chỉ độ dài và một JSON object UTF-8. Bản 1 có giới hạn 512 KiB/frame, `type` bắt buộc. Client gọi `send_packet`, `recv_packet`; không gọi `.recv()` trực tiếp để đoán ranh giới packet.

## Đăng ký và quản lý peer

```json
{"type":"hello","version":1,"name":"alice","mssvs":["2312345","2312346"],"handshake":"Hello, We are 2312345, 2312346","group_seed_hash":"<sha256-hex>"}
{"type":"welcome","name":"alice","peers":["alice","bob"]}
{"type":"list_peers"}
{"type":"peers","names":["alice","bob"]}
{"type":"error","message":"Peer offline"}
```

Lưu ý `mssvs` gửi như chuỗi để không làm mất số 0 đầu (nếu có), và mọi Client phải thống nhất thứ tự MSSV. Không dùng `group_seed_hash` để xác thực danh tính.

## Khởi tạo phiên bảo mật

```json
{
  "type":"session_init",
  "sender":"alice",
  "recipient":"bob",
  "session_id":"<32 hexadecimal digits>",
  "group_seed_hash":"<sha256-hex>",
  "wrapped_key":"<base64 RSA-OAEP ciphertext>",
  "signature":"<base64 RSA-PSS signature>"
}
```

Phần được ký là toàn bộ object trước khi thêm trường `signature`, được serialize bằng JSON canonical sorted keys, UTF-8, separators `,` và `:`. Chữ ký được xác minh bằng khóa công khai đã pin, không lấy từ Server thiếu tin cậy. RSA-OAEP bọc khóa AES-256, không mã hóa trực tiếp nội dung chat hoặc file.

## Chat và truyền file

```json
{"type":"chat","sender":"alice","recipient":"bob","session_id":"<id>","seq":1,"nonce":"<base64>","ciphertext":"<base64 of ciphertext+tag>"}
{"type":"file_meta","sender":"alice","recipient":"bob","session_id":"<id>","seq":2,"transfer_id":"<uuid32>","nonce":"<base64>","ciphertext":"<base64>"}
{"type":"file_chunk","sender":"alice","recipient":"bob","session_id":"<id>","seq":3,"transfer_id":"<uuid32>","index":0,"nonce":"<base64>","ciphertext":"<base64>"}
{"type":"file_done","sender":"alice","recipient":"bob","session_id":"<id>","seq":4,"transfer_id":"<uuid32>","nonce":"<base64>","ciphertext":"<base64>"}
```

Mọi trường ngoài `nonce` và `ciphertext` trong encrypted packet đều nằm trong Additional Authenticated Data (AAD) khi mã hóa/giải mã. Không được thêm trường `message`, `plaintext`, `filename`, `size` hay nội dung file ở dạng rõ trong packet gửi qua Server. Metadata file (`name`, `size`, `sha256`, `total_chunks`) nằm **bên trong ciphertext** `file_meta`.

**Cơ chế thứ tự:** Seq tăng liên tục theo một session gửi. Phía nhận giữ số seq cuối cùng của mỗi `(sender, session_id)` và từ chối seq cũ; không có cơ chế nhận packet không đúng thứ tự hoặc xác nhận lại trong bản demo.

**Chống MitM:** Nếu khóa công khai được đưa vào thư mục tin cậy sau khi xác thực fingerprint ngoài băng, việc thay thế chữ ký/khóa phiên trên relay sẽ bị phát hiện. Nếu người dùng tải khóa giả từ Server rồi tự động tin, sự bảo đảm này không còn.
