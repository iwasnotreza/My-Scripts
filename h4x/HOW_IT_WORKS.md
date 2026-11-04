# این لودر چطور کار می‌کند؟

توضیح ساده و کامل از `https://h4xscripts.xyz/loader` — هم لایه‌های محافظت، هم منطق خود برنامه.
همه‌چیز از تحلیل **استاتیک / mock** به‌دست آمده؛ هیچ‌چیز روی Roblox یا executor واقعی اجرا نشده است.

---

## ۱) لایه‌های محافظت (از بیرون به داخل)

فایل خام `raw_loader.lua` حدود ۳۹۶ کیلوبایت است و در واقع چهار لایه تودرتو دارد:

| لایه | فایل خروجی | چیست |
|---|---|---|
| ۰ | `out/stage1.lua` | پوستهٔ بیرونی: یک blob رمزگذاری‌شده با **ChaCha20** + یک decryptor کوچک |
| ۱ | `out/stage2.bin` | ماشین مجازی (VM) + جدول کلیدها + ۸۱ «پروتوتایپ» رمزگذاری‌شده |
| ۲ | `out/prototypes/proto01..81.json` | بایت‌کد سفارشی هر تابع، بعد از رمزگشایی کامل |
| ۳ | `out/loader_deobfuscated.lua` | خودِ منطق لودر، بازسازی‌شده به Lua خوانا |

### زنجیرهٔ کلید
رمزگشایی هر لایه به کلید لایهٔ قبل وابسته است و همه از **HMAC-SHA256** با یک پیشوند ثابت (`DS_I5K1`) مشتق می‌شوند:

```
key2 ──HMAC──► D3 ──HMAC(iPq)──► …
D3 ──HMAC(gate)──► CBfl          (کلید پروتوتایپ ۱۸)
کلید والد ──HMAC("prototype-route-v1" .. مسیر)──► کلید هر تابع فرزند
```

- `gate` خودش یک مقدار ثابت نیست؛ پروتوتایپ‌های ۱ تا ۱۷ یک **برنامهٔ دروازه‌ای** هستند که باید داخل VM اجرا شوند تا کلید دروازه تولید شود. ما این کار را در یک ماک Roblox شبیه‌سازی‌شده انجام دادیم و کلید به‌دست‌آمده با SHA-256ِ مورد انتظار (`FHMt`) مطابقت دادیم.
- هر پروتوتایپ با ChaCha20 (counter = 1) رمز می‌شود؛ بعد از رمزگشایی، بایت‌کد با یک **range coder** و ماسک‌های دستوری فشرده/مبهم شده بود که آن‌ها هم باز شدند.
- نتیجه: **۸۱ از ۸۱ پروتوتایپ** کامل رمزگشایی شد.

### ماشین مجازی
بایت‌کد، Lua استاندارد نیست؛ یک VM سفارشی با ~۴۹ opcode است:
- opcodeهای «fus» که دو عملیات را در یک اسلات جا می‌دهند (مثلاً `MOVE+LOADK`).
- پرش‌های شرطی که اسلات بعدی را به‌عنوان offset مصرف می‌کنند.
- حلقه‌های `for` که بدنه‌شان توسط کامپایلر «چرخانده» (rotated) شده و جای header/back-edge عوض شده است.

فایل `decompile.py` این‌ها را به Lua ساخت‌یافته برمی‌گرداند. نام متغیرها در بایت‌کد وجود ندارد، بنابراین نام‌های جدید ساخته می‌شوند: `a1` پارامتر، `v12` متغیر محلی، `u3` upvalue، `f18` تابع تودرتو.

---

## ۲) خود لودر چه کار می‌کند؟

پروتوتایپ‌های ۱۸ تا ۸۱ (۶۴ تابع، ~۵۴۰۰ دستور) یک **لودر GUI با سیستم کلید** برای کانال H4xScripts هستند.

### الف) پیکربندی
```lua
HubName     = "H4xScripts"
Logo        = "rbxassetid://80426684728669"
DiscordUrl  = "https://discord.gg/H4xScripts"
ApiUrl      = "https://keysystem.pro/v1/loader.lua"
Owner       = "h4xscripts"
RegistryUrl = "https://cdn.keysystem.pro/h4xscripts/sciprts-list"
KeyLength   = 32
KeyFile     = "h4xscripts/keys.txt"
```

### ب) رجیستری بازی‌ها
یک جدول `PlaceId → {name, scriptId}` برای ۱۲ بازی:
Murder Mystery 2، Demonology، Slime RNG، Fling Things and People، 99 Nights in the Forest،
Steal an Egg، Animal Hospital، Build a Ring Farm، Violence District، Fish It، AOT Revolution، Sailor Piece.

لودر `game.PlaceId` را با این جدول تطبیق می‌دهد؛ اگر بازی پشتیبانی نشود پیام
`"H4xScripts does not support this game yet."` نشان می‌دهد.

### ج) رابط کاربری
یک `ScreenGui` تمام‌عیار ساخته می‌شود: پنجرهٔ اصلی، لوگو، دکمهٔ هر بازی، کادر ورود کلید،
Toast برای پیام‌ها، و انیمیشن‌های `TweenService`. helperهایی مثل `create(class, props)`،
`corner(parent, radius)`، `stroke(...)` و `tween(...)` کد UI را جمع‌وجور کرده‌اند.

### د) سیستم کلید (مهم‌ترین بخش)
۱. **بارگذاری API**:
```lua
api = loadstring(game:HttpGet("https://keysystem.pro/v1/loader.lua"))()
api.owner     = "h4xscripts"
api.script_id = <scriptId بازی جاری>
api.script_key = ""
```
۲. **کلید ذخیره‌شده**: اگر فایل `h4xscripts/keys.txt` وجود دارد، خوانده می‌شود،
فاصله‌هایش حذف می‌شود و اگر طولش ۳۲ بود استفاده می‌شود.
۳. **مسیر تست (`script_tester`)**: یک گلوبال به نام `script_tester` اگر رشته باشد،
به‌عنوان کلید تستی به `api.check_key` فرستاده می‌شود؛ اگر پاسخ `KEY_VALID` بود و
`data.note` شامل `"test"` بود، `script_id` به `"test-" .. scriptId` تغییر می‌کند و اسکریپت بارگذاری می‌شود.
۴. **بررسی نیاز به کلید**: `api.scripthaskey()` صدا زده می‌شود.
۵. **اعتبارسنجی کلید**: `api.check_key(key)` → اگر `code == "KEY_VALID"`:
   - کلید در فایل ذخیره می‌شود (`makefolder` + `writefile`).
   - پیام `KEY ACCEPTED` نشان داده می‌شود.
   - `api.load_script(scriptId)` اسکریپت اصلی را می‌گیرد و اجرا می‌کند.
   - `_G.H4xScriptKey.Loaded = true` و GUI بسته می‌شود.
۶. **گرفتن کلید**: سه ارائه‌دهنده معرفی می‌شوند — **LootLabs**، **Linkvertise**، **Work.ink** —
که کاربر از طریق آن‌ها کلید ۳۲ کاراکتری را دریافت می‌کند.
۷. **خطاها**: `INVALID KEY`، `KEY MUST BE 32 CHARACTERS`، `GAME NOT SUPPORTED`، `SERVICE UNAVAILABLE`.

### ه) نکتهٔ امنیتی
لودر در نهایت `loadstring(game:HttpGet(...))()` اجرا می‌کند — یعنی کد از راه دور دریافت و
اجرا می‌شود. خودِ لودر فقط یک واسط است؛ اسکریپت اصلیِ هر بازی جداگانه از API گرفته می‌شود
و در این فایل نیست.

---

## ۳) فایل‌های تحویلی

| فایل | توضیح |
|---|---|
| `out/loader_deobfuscated.lua` | بازسازی خوانای کل لودر (~۱۵۰۰ خط) |
| `out/prototypes/proto*.json` | بایت‌کد رمزگشایی‌شدهٔ هر ۸۱ تابع |
| `out/stage2_keys.json` | کلیدهای D3 / CBfl / iPq / gate |
| `out/stage1.lua`, `out/stage2.bin` | لایه‌های میانی |
| `decode_loader.py` | رمزگشای لایهٔ بیرونی |
| `decode_stage2.py` | رمزگشای کامل مرحلهٔ ۲ (۸۱ پروتوتایپ) |
| `decompile.py` | بازساز Lua از بایت‌کد |
| `vm_stage2.py` | VM + ماک Roblox (فقط برای تولید کلید دروازه) |

### محدودیت‌های بازسازی
- نام متغیرها اصلی نیستند (بایت‌کد نام ندارد).
- چند حلقه که کامپایلر آن‌ها را rotated کرده، به‌صورت خطی با کامنتِ `generic-for header / back-edge` نشان داده شده‌اند؛ منطق کامل است ولی ساختار `for` بازسازی نشده.
- چند `if` به‌صورت `while … do … return end` درآمده‌اند که از نظر رفتاری معادل `if … then … return end` هستند.
