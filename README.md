# Railway VPN Panel — Full Edition

این پروژه یک پنل مدیریت Xray برای Railway است. پنل با FastAPI، SQLite، Nginx و Xray Core اجرا می‌شود.

## قابلیت‌ها

- VLESS / VMess / Trojan
- TCP / WebSocket / gRPC / XHTTP / HTTPUpgrade
- Security: None / TLS / Reality
- Reality key pair و Short ID
- UUID خودکار
- SNI و Fingerprint و Flow
- چندین Inbound
- User و Group
- Enable / Disable
- ویرایش Inbound
- تاریخ انقضا، quota و IP-limit field
- QR Code
- لینک مستقیم
- Subscription Base64
- Clash/Mihomo YAML
- Sing-box JSON
- سازگار با V2RayNG / NekoBox / Hiddify از طریق لینک/Subscription سازگار
- Backup/Restore
- تغییر رمز
- Railway Domain / Custom Domain
- Xray raw config
- Xray logs
- CPU/load و وضعیت
- traffic query از Xray API (best effort، وابسته به نسخه Xray)
- رابط فارسی و responsive

## Railway deployment

1. Repository بساز و تمام فایل‌ها را در root قرار بده.
2. Railway -> New Project -> Deploy from GitHub Repo.
3. Volume بساز و Mount Path را `/data` قرار بده.
4. Variables:
   - `ADMIN_USER=admin`
   - `ADMIN_PASSWORD=یک رمز قوی`
   - `SESSION_SECRET=یک رشته تصادفی طولانی`
   - `PORT=8080`
5. Deploy.
6. Settings -> Networking -> Generate Domain.
7. پنل را با `https://DOMAIN/` باز کن.

## TCP Proxy

برای TCP/Reality که مستقیماً توسط Xray گوش می‌دهد، Railway TCP Proxy بساز و پورت داخلی همان Inbound را Publish کن. External Host و External Port را در فرم Inbound وارد کن.

مثال:
- Internal port: 10000
- Railway TCP Proxy: `abc.proxy.rlwy.net:12345`
- در پنل: External Host=`abc.proxy.rlwy.net`, External Port=`12345`

## HTTPS transports

برای WebSocket/gRPC/XHTTP/HTTPUpgrade می‌توان از Railway HTTPS Domain و Nginx استفاده کرد. در این حالت TLS عمومی توسط Railway terminate می‌شود و Xray پشت Nginx بدون TLS کار می‌کند. اگر Security را TLS یا Reality بگذاری، باید External Host/Port مربوط به TCP Proxy را برای اتصال مستقیم به Xray استفاده کنی؛ TLS دوبل روی Nginx فعال نیست.

## XHTTP / HTTPUpgrade

XHTTP و HTTPUpgrade به نسخه Xray وابسته‌اند. پنل قبل از اعمال تغییر، `xray run -test` را اجرا می‌کند. اگر نسخه Xray انتخاب‌شده یک ترکیب خاص از protocol/transport/security را نپذیرد، تغییر اعمال نمی‌شود.

## محدودیت مهم

Railway VPS با IP عمومی آزاد نیست. برای TCP باید TCP Proxy استفاده شود. UDP-based protocols و سرویس‌هایی که به UDP عمومی یا پورت 53 نیاز دارند در این معماری هدف این پنل نیستند.

Quota و expiry در سطح پنل مدیریت می‌شوند؛ enforce کردن hard quota به آمار Xray وابسته است. IP-limit در این نسخه به‌عنوان metadata نگهداری می‌شود و برای همه transportها enforcement سخت‌گیرانه ندارد؛ این مورد را نباید به‌عنوان firewall-level IP limit در نظر گرفت.
