# Chạy lại số liệu của bài báo

Bài báo là nghiên cứu phỏng vấn: không có thực nghiệm máy tính, và bản ghi phỏng vấn không được
công bố. Vì vậy, phần tái lập số liệu là **tính lại mọi con số mà bài báo ghi trong văn bản, từ chính
các bảng dữ liệu của bài**: Table 1 (thông tin 13 người tham gia) và Table B1 (người tham gia nào
nhắc tới hoạt động học nào). Dữ liệu được nhập tay từ bản PDF và kiểm tra hai lần. Toàn bộ phép
tính nằm trong script `scripts/reproduce_paper_stats.py` của đề tài, chạy lại được bất cứ lúc nào.

## 1. Đối chiếu con số bài báo ghi với con số tính lại

| Mục trong bài báo | Con số | Bài báo ghi | Tính lại | Kết quả |
|---|---|---|---|---|
| Thiết kế nghiên cứu | Số người tham gia | 13 | 13 | Khớp |
| Thiết kế nghiên cứu | Phỏng vấn trực tiếp | 3 | 3 | Khớp (không có dữ liệu từng người) |
| Thiết kế nghiên cứu | Phỏng vấn từ xa | 10 | 10 | Khớp (không có dữ liệu từng người) |
| Đặc điểm người tham gia | Kinh nghiệm trung bình (năm) | 9,35 | 9,38 | **Lệch** |
| Đặc điểm người tham gia | Kinh nghiệm trung vị (năm) | 8 | 8 | Khớp |
| Học chính thức | Số người dự đào tạo bắt buộc | 3 | 3 | Khớp |

Số năm kinh nghiệm trong Table 1, xếp tăng dần: 1, 3, 3, 4, 5, 5, 8, 10, 12, 15, 15, 20, 21.
Tổng là 122, chia cho 13 người được **9,3846**. Làm tròn hay cắt bớt đều ra 9,38, nên con số 9,35
trong bài **không thể suy ra từ Table 1 như đã in**. Nhiều khả năng đây là lỗi đánh máy, hoặc một
giá trị trong Table 1 khác với dữ liệu tác giả dùng khi viết. Trung vị (8) thì khớp.

## 2. Thống kê mô tả tính lại từ Table 1

| Biến | Giá trị |
|---|---|
| Giới tính | 3 nữ (P1, P6, P13), 10 nam |
| Tuổi | 26–38, trung bình 32,5 |
| Số năm kinh nghiệm | 1–21, trung bình 9,38, trung vị 8, độ lệch chuẩn 6,70 |
| Tự đánh giá kiến thức bảo mật (1–5) | 2–5, trung vị 4, trung bình 3,62 |
| Quy mô công ty | 7 doanh nghiệp lớn, 6 doanh nghiệp vừa và nhỏ |
| Quy mô nhóm | 3–20 người, trung vị 8 |

## 3. Table B1 tính lại: số người nhắc tới từng hoạt động học

| Loại học | Bên khởi xướng | Hoạt động | Người tham gia | Số người |
|---|---|---|---|---|
| Chính thức | Nhà tuyển dụng | Dự đào tạo bắt buộc | P1, P2, P5 | 3 |
| Bán chính thức | Nhà tuyển dụng | Nhận hỗ trợ tại chỗ | P1, P4, P6, P7, P9, P10 | 6 |
| Bán chính thức | Nhà tuyển dụng | Dùng code review để học | P1, P4, P6, P9 | 4 |
| Không chính thức | Nhà tuyển dụng | Tiếp xúc xã hội có điều phối | P2, P6, P7, P9, P10, P11 (bài báo ghi P11 hai lần) | 6 |
| Chính thức | Cả hai | Nghe buổi nói chuyện do công ty tổ chức | P2, P3 | 2 |
| Chính thức | Cả hai | Đọc tài liệu tham khảo tuỳ chọn | P1, P3, P9 | 3 |
| Bán chính thức | Cả hai | Dự hội thảo | P2, P3, P5, P9 | 4 |
| Không chính thức | Cả hai | Cộng tác trong công việc | P1, P2, P3, P5, P6, P7, P9 | 7 |
| Chính thức | Lập trình viên | Theo học khoá học | P4, P6, P9 | 3 |
| Bán chính thức | Lập trình viên | Tìm kiếm trực tuyến | P3, P8, P9 | 3 |
| Bán chính thức | Lập trình viên | Đọc trang tin và diễn đàn | P4, P7, P9, P10 | 4 |
| Không chính thức | Lập trình viên | Nhờ đồng nghiệp giúp | P1, P2, P4, P7, P8, P9, P10 | 7 |

## 4. Kiểm chứng nhận định chính của bài báo bằng Table B1

Bài báo kết luận rằng lập trình viên **ưa học tại chỗ** (bán chính thức và không chính thức).

| Loại học | Số hoạt động | Lượt nhắc | Tỉ lệ | Số người khác nhau |
|---|---|---|---|---|
| Chính thức | 4 | 11 | 21% | 7 |
| Bán chính thức | 5 | 21 | 40% | 10 |
| Không chính thức | 3 | 20 | 38% | 11 |

Học tại chỗ chiếm **41/52 lượt nhắc (79%)**, còn học chính thức chỉ 11/52. Như vậy dữ liệu của chính
bài báo **ủng hộ** nhận định này. Lưu ý là Table B1 đếm *số lượt nhắc tới*, chưa phải mức độ *ưa thích*.

Các điểm bất thường phát hiện khi đối chiếu:
- Ô "tiếp xúc xã hội có điều phối" ghi **P11 hai lần**.
- **P12 và P13 không xuất hiện** ở bất kỳ ô nào của Table B1, nên chỉ 11/13 người có dữ liệu.
- **P9 có mặt ở 10/12 hoạt động**, tức một người chiếm phần lớn bảng.

## 5. Phân tích bổ sung (khám phá, n = 13)

- Tương quan hạng Spearman giữa số năm kinh nghiệm và tự đánh giá kiến thức bảo mật: **ρ = 0,40**.
- Tương quan giữa tự đánh giá kiến thức bảo mật và số hoạt động học được nhắc tới: **ρ = 0,19**.
- Với 13 người, các con số này chỉ mang tính mô tả, không kết luận ý nghĩa thống kê.

## 6. Phần không tái lập được

- Quá trình mã hoá định tính (170 mã từ 600 trích đoạn) và các chủ đề rút ra: bản ghi phỏng vấn
  không được công bố.
- Table C1 (các mã động lực) chỉ có định nghĩa và trích dẫn, không có số đếm.
- Vì vậy đề tài DT074 tái lập bài báo **có chọn lọc**: các phát hiện của bài được chuyển thành yêu cầu
  thiết kế và giả thuyết đo được, rồi kiểm chứng bằng thực nghiệm trên NIST SARD.
