# Tóm tắt bài báo nền tảng (tiếng Việt)

**Bài báo:** Hala Assal, Srivathsan G. Morkonda, Muhammad Zaid Arif, Sonia Chiasson.
*Software security in practice: knowledge and motivation.* **Journal of Cybersecurity**,
Tập 11, Số 1, mã bài tyaf005, 2025. DOI: [10.1093/cybsec/tyaf005](https://doi.org/10.1093/cybsec/tyaf005)

> Tài liệu này là **bản tóm tắt và diễn giải** bằng lời của sinh viên, phục vụ học tập. Đây
> **không phải bản dịch nguyên văn**. Các cụm từ trong ngoặc kép là trích ngắn từ bài báo để
> giữ đúng thuật ngữ. Bản quyền: © The Author(s) 2025, Oxford University Press (open access).
> Trước khi dịch toàn văn, cần kiểm tra điều khoản giấy phép ghi trên bản PDF.

---

## 0. Tóm tắt một đoạn

Dù đã có nhiều tài liệu và công cụ hỗ trợ, lập trình viên vẫn gặp khó khi viết phần mềm an
toàn. Nhóm tác giả phỏng vấn 13 lập trình viên chuyên nghiệp (15 công ty, Bắc Mỹ) để trả lời
hai câu hỏi: *họ học kiến thức bảo mật bằng cách nào* và *điều gì thúc đẩy hoặc cản trở họ áp
dụng thực hành bảo mật*. Kết quả:

1. Có một **phân loại (taxonomy) các hoạt động học bảo mật** theo mức độ chính thức
   (formal / semi-formal / informal) và theo ai khởi xướng. Lập trình viên **ưa học "tại chỗ"
   (in-context)**, tức là học ngay trong công việc hằng ngày.
2. Áp dụng **Lý thuyết Tự quyết (Self-Determination Theory, SDT)** để phân loại động lực, từ
   *vô động lực* (amotivation), qua *động lực ngoại sinh*, đến *động lực nội sinh*. Kết quả bảo mật
   tốt hơn khi lập trình viên **tự thấy bảo mật là giá trị của mình** (internalization), thay vì
   bị ép từ bên ngoài.
3. **Kiến thức và động lực gắn chặt với nhau** ("intertwined"): có kiến thức mà không có
   động lực thì không đủ, và ngược lại.
4. Đề xuất **mô hình "nội hoá bảo mật"** (internalizing software security) dựa trên hai đòn bẩy
   là **năng lực (cảm nhận)** và **sự gắn kết với nhóm**.

---

## 1. Giới thiệu

- **Vấn đề:** phần mềm thiếu an toàn không chỉ do thiếu công cụ. Nó còn do nhận thức và các
  lý do đằng sau quyết định của lập trình viên.
- **Câu hỏi nghiên cứu:**
  - **RQ1**: Lập trình viên trong tổ chức tiếp thu kiến thức bảo mật như thế nào?
  - **RQ2**: Yếu tố nào thúc đẩy hoặc cản trở họ áp dụng thực hành bảo mật?
- **Đóng góp:** (i) bản đồ các con đường học bảo mật, cho thấy hoạt động học tại chỗ được ưa
  thích; (ii) chỉ ra kiến thức và động lực là hai mặt đan xen; (iii) động lực nội sinh cho kết quả
  tốt hơn áp lực bên ngoài; (iv) mô hình giúp lập trình viên nội hoá bảo mật.

## 2. Cơ sở lý thuyết và nghiên cứu liên quan

- **Activity Theory (thế hệ 3):** dùng để phân tích tương tác giữa nhiều nhóm, ví dụ nhóm
  phát triển và nhóm kiểm thử bảo mật. Mỗi nhóm có mục tiêu khác nhau (chức năng hay an toàn),
  nên dễ phát sinh "đa tiếng nói" (multi-voicedness) và xung đột.
- **Self-Determination Theory (SDT):** con người có ba nhu cầu tâm lý cơ bản là *tự chủ*
  (autonomy), *năng lực* (competence) và *gắn kết* (relatedness). Động lực được xếp trên một
  thang liên tục:
  - *Vô động lực* (amotivation): không có ý định hành động.
  - *Ngoại sinh*, sắp từ kém tự chủ đến tự chủ hơn: điều chỉnh từ bên ngoài (thưởng/phạt), điều
    chỉnh "nhập nội" (áp lực tự thân, giữ thể diện), điều chỉnh "đồng nhất" (thấy việc đó quan
    trọng), điều chỉnh "tích hợp" (hoàn toàn chấp nhận như giá trị của mình).
  - *Nội sinh*: làm vì bản thân việc đó thú vị và thoả mãn.
  - Động lực càng tự chủ thì càng gắn với mức độ tham gia, hiệu quả công việc và khả năng học
    tốt hơn.
- **Nghiên cứu liên quan:** bảo mật trong vòng đời phát triển phần mềm (SDLC), các yếu tố ảnh
  hưởng tới việc áp dụng công cụ và giải pháp bảo mật, nguồn kiến thức bảo mật, nhận thức của
  lập trình viên, các thách thức và các biện pháp can thiệp để tạo động lực.

## 3. Thiết kế nghiên cứu

| Hạng mục | Chi tiết |
|---|---|
| Phương pháp | Phỏng vấn bán cấu trúc, khoảng 1 giờ, ghi âm và chép lời |
| Chủ đề phỏng vấn | Công việc phát triển; thái độ với bảo mật; kiến thức bảo mật; quy trình bảo mật; hoạt động kiểm thử |
| Người tham gia | 13 lập trình viên chuyên nghiệp, phản ánh 15 công ty (2 người kể cả nơi làm cũ) |
| Đặc điểm | Kinh nghiệm trung bình 9,35 năm (trung vị 8); 26–38 tuổi; 4 nữ, 9 nam; đều có bằng đại học; tự đánh giá kiến thức bảo mật 2–5/5; doanh nghiệp lớn và vừa/nhỏ; nhóm 3–20 người |
| Tuyển chọn | Diễn đàn, mạng xã hội, quan hệ nghề nghiệp; quà tặng 20 USD |
| Thu thập | 3 đợt, phân tích sơ bộ giữa các đợt, dừng khi bão hoà dữ liệu |
| Phân tích | Grounded Theory (Strauss & Corbin): mã hoá mở (170 mã / 600 trích đoạn, Atlas.ti) → mã hoá trục (nhóm mã bằng Post-It) → mã hoá chọn lọc, với phạm trù lõi là **"nội hoá bảo mật"** |

## 4. Phân loại hoạt động học kiến thức bảo mật (RQ1)

Mỗi hoạt động được mô tả theo hai chiều: **loại học** và **ai khởi xướng** (nhà tuyển dụng bắt
buộc, nhà tuyển dụng đề nghị và lập trình viên tự chọn, hoặc lập trình viên tự làm). Ngoài ra
còn 5 đặc điểm: chi phí, có phải mục tiêu học rõ ràng hay chỉ là "sản phẩm phụ" của việc khác,
trình độ của nguồn kiến thức, có nằm trong SDLC không, và nguồn nằm trong hay ngoài công ty.

| Loại học | Hoạt động | Ý chính |
|---|---|---|
| **Chính thức (formal)** | Đào tạo bắt buộc | Thường là bảo mật chung (mật khẩu, phishing), quy định công ty; ít khi đi sâu vào phát triển phần mềm an toàn |
| | Buổi nói chuyện do công ty tổ chức | Chủ đề kỹ thuật cụ thể, ví dụ API bảo mật mới |
| | Tài liệu tham khảo tuỳ chọn | Slide, video nội bộ, có thể kèm bài tự kiểm tra |
| | Khoá học / bằng cấp | Do lập trình viên tự theo học, kiến thức từ bên ngoài |
| **Bán chính thức (semi-formal)** | Hỗ trợ tại chỗ (in-context support) | Tester hướng dẫn tái hiện và sửa lỗi; ghép cặp junior với senior; "hội đồng bảo mật" nội bộ |
| | Code review như công cụ học | Người review chỉ ra và giải thích lỗi bảo mật |
| | Hội thảo | Có mục tiêu học rõ, chuyên gia trình bày |
| | Tìm kiếm trực tuyến | Tra NVD, CVE, Stack Overflow khi cần sửa lỗi; ưu tiên nguồn chính thống |
| | Đọc trang tin và diễn đàn | Chủ động cập nhật lỗ hổng, ngoài giờ phát triển |
| **Không chính thức (informal)** | Tiếp xúc xã hội có điều phối | Họp nhóm, văn phòng mở, thảo luận tự nhiên |
| | Cộng tác trong công việc | Dev và tester làm việc cùng nhau thì hiểu nhau hơn; giao tiếp kém gây căng thẳng |
| | Nhờ đồng nghiệp giúp | Ngẫu nhiên, khi gặp vấn đề |

**Phát hiện chính:** lập trình viên **ưa các hoạt động học bán chính thức và không chính thức**
vì chúng nằm ngay trong mục tiêu công việc, không đòi thời gian riêng.

## 5. Động lực với bảo mật phần mềm (RQ2)

### 5.1 Vô động lực (amotivation)
1. **Cảm thấy thiếu năng lực:** thiếu nguồn lực (ngân sách, thời gian, nhân sự, chuyên môn) và
   thiếu hỗ trợ (không có kế hoạch bảo mật, **công cụ bảo mật không có hoặc kém**, không biết có
   công cụ). Một người tham gia ước có công cụ nhưng không biết công cụ nào. Bài báo cũng nhắc
   rằng cảnh báo của công cụ phân tích tĩnh bị xem là "unuseful" khi không hợp quy trình làm
   việc, và lập trình viên "receptive" hơn khi cảnh báo có ví dụ code (dẫn theo Danilova et al.).
2. **Thiếu quan tâm, liên quan, giá trị:** "không phải việc của tôi"; "đã có nhóm khác lo";
   *thụ động lây lan* (cả nhóm thờ ơ thì người có ý thức cũng nản); *không thấy rủi ro* (lạc quan
   rằng không ai tấn công mình); *không thấy thiệt hại* (không bị quy trách nhiệm thì ưu tiên việc
   khác). Bảo mật thường bị **hy sinh cho yêu cầu chức năng**.
3. **Chống đối / cứng nhắc (defiance):** bỏ qua bảo mật không phải vì khó, mà vì nó mâu thuẫn
   với quan niệm "code đúng cách" của bản thân.

### 5.2 Động lực ngoại sinh, xuất phát từ bên ngoài (kém bền vững)
Uy tín và danh hiệu; **sợ kiểm toán**; sợ mất doanh thu khi bị tấn công; **áp lực từ quản lý**;
thăng tiến.

### 5.3 Động lực ngoại sinh nhưng đã "nội hoá" một phần (tốt hơn)
Trách nhiệm nghề nghiệp; quan tâm tới người dùng; **hiểu hậu quả thực tế** qua ví dụ;
uy tín công ty; **trách nhiệm chung của cả nhóm** (thấy đồng nghiệp đầu tư cho bảo mật thì mình
cũng làm theo).

### 5.4 Động lực nội sinh (tốt nhất)
Tự hoàn thiện: thích thú với bảo mật, tự đặt thử thách nộp code không bị reviewer bắt lỗi.

## 6. Mô hình "nội hoá bảo mật phần mềm"

- Hai đòn bẩy tâm lý:
  - **Năng lực (cảm nhận):** tăng nhờ mọi hoạt động học ở mục 4.
  - **Gắn kết (relatedness):** tăng nhờ các hoạt động học có cộng tác nhóm.
- Hai vòng phản hồi:
  1. *Học → năng lực tăng → làm tốt hơn → thấy giá trị của bảo mật → có động lực học tiếp.*
  2. *Cộng tác → gắn kết → trách nhiệm chung → văn hoá bảo mật của nhóm → cộng tác nhiều hơn.*
- Áp dụng cho mọi điểm trên thang động lực. Với người đang vô động lực, nên bắt đầu bằng hoạt
  động do công ty khởi xướng để xây năng lực, rồi chuyển dần sang hoạt động do họ tự chủ.

## 7. Hạn chế (tác giả nêu và suy ra từ thiết kế)

1. Mẫu nhỏ: 13 người, chỉ ở Bắc Mỹ, nên khả năng khái quát hoá hạn chế.
2. Tất cả người tham gia có bằng đại học, chưa đại diện cho người học theo con đường khác.
3. Mỗi công ty chỉ có một góc nhìn, khó phân tích ở cấp tổ chức.
4. Dữ liệu tự khai báo, người tình nguyện tham gia có thể quan tâm bảo mật hơn mức trung bình.
5. Không báo cáo độ tin cậy giữa nhiều người mã hoá (inter-rater reliability).
6. Nghiên cứu định tính, không có chỉ số định lượng hay đo kết quả bảo mật thực tế.

## 8. Thảo luận và kết luận

- Kiến thức và động lực **phải được nuôi dưỡng cùng lúc**.
- **Tự chủ và nội hoá** quan trọng hơn tuân thủ do bị ép. Áp lực bên ngoài (kiểm toán, quản lý)
  chỉ tạo tuân thủ tạm thời.
- Nên **đưa việc học bảo mật vào ngay trong quy trình** (code review, ghép cặp, hỗ trợ tại chỗ).
  Đào tạo chính thức vẫn hữu ích nhưng nên điều chỉnh tần suất theo kết quả.
- **Tăng gắn kết giữa các nhóm** (dev với tester bảo mật), biến bảo mật thành trách nhiệm chung.
- Giúp lập trình viên **biết có công cụ gì và dùng thế nào**, kèm ví dụ hậu quả cụ thể.
- Bảo mật phần mềm là **bài toán con người**, không chỉ là bài toán kỹ thuật.

---

## 9. Liên hệ với đề tài DT074

| Phát hiện của bài báo | Thiết kế tương ứng trong Adaptive Security Gate |
|---|---|
| Công cụ thiếu hoặc kém dẫn tới cảm giác thiếu năng lực; cảnh báo bị xem là "unuseful" | Gate đóng gói sẵn (reusable action), chỉ chặn khi rủi ro cao, gộp cảnh báo trùng |
| Dev "receptive" khi cảnh báo có ví dụ code | `SECURITY_GATE_FEEDBACK.md`: dòng lỗi, CWE, đoạn code sửa mẫu |
| Ưa học tại chỗ (in-context) | Comment ngay trong Pull Request, kèm link CWE và OWASP Cheat Sheet |
| Chống đối quy tắc cứng nhắc | Ngưỡng theo rủi ro OWASP, override khẩn cấp có audit |
| Bảo mật bị hy sinh cho chức năng | Không bắt dev trả giá cho nợ bảo mật cũ (chỉ chặn lỗi do PR đưa vào) |
| Dev và tester đứt gãy | Cùng một gate chạy ở máy dev và trong CI, ai cũng thấy kết quả |

Vì bài báo **không có dữ liệu định lượng**, đề tài tái lập **có chọn lọc**: biến các phát hiện
trên thành giả thuyết đo được. Chi tiết xem `docs/PAPER_MAPPING.md` và kết quả trong `results/`.
