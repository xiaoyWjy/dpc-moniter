# -*- coding: utf-8 -*-
"""
浙大宁波理工学院安全保卫部 —— 公示/通知 关键词监控
=================================================
只用 Python 标准库，无第三方依赖。

用法:
    python monitor.py              # 正常检查一次（首次运行只建立基线，不通知）
    python monitor.py --test       # 给所有已配置的通知渠道发一条测试消息
    python monitor.py --list 10    # 打印最新 10 条公告（不改变状态）
    python monitor.py --reset      # 清空已读记录（下次运行会重新建立基线）
    python monitor.py --verbose    # 打印未命中关键词的新公告

退出码: 0=无命中/正常, 1=抓取出错, 2=发现新的命中公告
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import smtplib
import ssl
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime
from email.message import EmailMessage
from html import unescape
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONFIG_FILE = HERE / "config.json"

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

DEFAULTS = {
    "sites": [
        {
            "name": "通知公告",
            "url": "https://bwc.nbt.edu.cn/list.jsp?urltype=tree.TreeTempUrl&wbtreeid=1175",
            "pages": 2,
        },
        {
            "name": "新闻动态",
            "url": "https://bwc.nbt.edu.cn/list.jsp?urltype=tree.TreeTempUrl&wbtreeid=1179",
            "pages": 1,
        },
    ],
    "keywords": ["公示", "招标", "采购", "中标", "询价", "招聘", "录用", "职称", "评优"],
    "exclude": [],
    "match_mode": "any",       # any=命中任一关键词; all=必须全部命中
    "match_body": False,       # True 时连正文一起匹配（更慢，每次多抓 N 个页面）
    "state_file": "state.json",
    "log_file": "hits.log",
    "digest_file": "latest.html",
    "windows_toast": True,     # 桌面气泡提醒
    "notify": {
        "pushplus_token": "",
        "serverchan_key": "",
        "bark_url": "",
        "feishu_webhook": "",
        "wecom_webhook": "",
        "dingtalk_webhook": "",
        "telegram": {"bot_token": "", "chat_id": ""},
        "generic_webhook": "",
        "smtp": {
            "host": "", "port": 465, "ssl": True,
            "user": "", "password": "",
            "to": [],
        },
    },
}

ITEM_RE = re.compile(r"<li[^>]*>([\s\S]{0,1500}?)</li>", re.I)
LINK_RE = re.compile(
    r'<a[^>]+href="(content\.jsp[^"]*?wbnewsid=(\d+)[^"]*)"[^>]*>([\s\S]*?)</a>', re.I)
TITLE_ATTR_RE = re.compile(r'title="([^"]*)"', re.I)
DATE_RE = re.compile(r"(\d{4})-(\d{1,2})-(\d{1,2})")
TAG_RE = re.compile(r"<[^>]+>")


# --------------------------------------------------------------------------- 工具
def log(msg: str) -> None:
    print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}", flush=True)


def strip_tags(s: str) -> str:
    return unescape(re.sub(r"\s+", " ", TAG_RE.sub(" ", s))).strip()


def http_get(url: str, timeout: int = 25, retries: int = 3) -> str:
    last = None
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": UA,
                "Accept-Language": "zh-CN,zh;q=0.9",
                "Accept": "text/html,application/xhtml+xml",
            })
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
            for enc in ("utf-8", "gb18030"):
                try:
                    return raw.decode(enc)
                except UnicodeDecodeError:
                    continue
            return raw.decode("utf-8", "ignore")
        except Exception as e:  # noqa: BLE001
            last = e
            if i < retries - 1:
                time.sleep(2 * (i + 1))
    raise RuntimeError(f"抓取失败 {url}: {last}")


def http_post(url: str, payload: dict | bytes, headers: dict | None = None,
              timeout: int = 20) -> str:
    if isinstance(payload, dict):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json; charset=utf-8", **(headers or {})}
    else:
        body = payload
    req = urllib.request.Request(url, data=body, headers={"User-Agent": UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "ignore")


# --------------------------------------------------------------------------- 抓取
def parse_list(html: str, page_url: str) -> list[dict]:
    items, seen = [], set()
    for block in ITEM_RE.findall(html):
        m = LINK_RE.search(block)
        if not m:
            continue
        href, news_id, inner = m.group(1), m.group(2), m.group(3)
        if news_id in seen:
            continue
        seen.add(news_id)
        tattr = TITLE_ATTR_RE.search(m.group(0))
        title = strip_tags(tattr.group(1)) if tattr else strip_tags(inner)
        if not title:
            title = strip_tags(inner)
        dm = DATE_RE.search(strip_tags(block))
        date = f"{dm.group(1)}-{int(dm.group(2)):02d}-{int(dm.group(3)):02d}" if dm else ""
        items.append({
            "id": news_id,
            "title": title,
            "url": urllib.parse.urljoin(page_url, unescape(href)),
            "date": date,
            "site": "",
        })
    return items


def fetch_site(site: dict) -> list[dict]:
    url = site["url"]
    out: list[dict] = []
    for page in range(1, int(site.get("pages", 1)) + 1):
        page_url = url if page == 1 else f"{url}&PAGENUM={page}"
        html = http_get(page_url)
        got = parse_list(html, page_url)
        if not got:
            break
        for it in got:
            it["site"] = site["name"]
        out.extend(got)
        if page < int(site.get("pages", 1)):
            time.sleep(0.5)
    # 站内可能重复出现同一条，按 id 去重并保持顺序
    uniq, seen = [], set()
    for it in out:
        if it["id"] in seen:
            continue
        seen.add(it["id"])
        uniq.append(it)
    return uniq


def fetch_body(url: str, max_chars: int = 4000) -> str:
    try:
        html = http_get(url)
    except Exception:  # noqa: BLE001
        return ""
    html = re.sub(r"<script[\s\S]*?</script>|<style[\s\S]*?</style>", " ", html, flags=re.I)
    return strip_tags(html)[:max_chars]


# --------------------------------------------------------------------------- 匹配
def compile_patterns(words: list[str]) -> list[re.Pattern]:
    pats = []
    for w in words:
        w = str(w).strip()
        if not w:
            continue
        pats.append(re.compile(w[3:], re.I) if w.startswith("re:") else re.compile(re.escape(w), re.I))
    return pats


def matched(text: str, pats: list[re.Pattern], mode: str) -> bool:
    if not pats:
        return True
    hits = [p.search(text) for p in pats]
    return all(hits) if mode == "all" else any(hits)


# --------------------------------------------------------------------------- 通知
def notify_windows_toast(title: str, body: str) -> bool:
    """用 PowerShell + NotifyIcon 弹桌面气泡（无需安装模块）。"""
    ps = f"""
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$ni = New-Object System.Windows.Forms.NotifyIcon
$ni.Icon = [System.Drawing.SystemIcons]::Information
$ni.Visible = $true
$ni.BalloonTipTitle = '{title.replace("'", "''")}'
$ni.BalloonTipText  = '{body.replace("'", "''")}'
$ni.BalloonTipIcon  = [System.Windows.Forms.ToolTipIcon]::Info
$ni.ShowBalloonTip(5000)
Start-Sleep -Seconds 5
$ni.Dispose()
"""
    try:
        import subprocess
        exe = "powershell.exe"
        enc = base64.b64encode(ps.encode("utf-16-le")).decode("ascii")
        subprocess.run([exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                        "-EncodedCommand", enc], check=True,
                       capture_output=True, timeout=30,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return True
    except Exception as e:  # noqa: BLE001
        log(f"  [warn] 桌面气泡失败: {e}")
        return False


def pushplus_send(token: str, title: str, html: str) -> None:
    """PushPlus 失败时 HTTP 仍是 200，必须看返回体里的 code。"""
    raw = http_post("https://www.pushplus.plus/send", {
        "token": token, "title": title, "content": html, "template": "html"})
    try:
        resp = json.loads(raw)
    except json.JSONDecodeError:
        raise RuntimeError(f"返回无法解析: {raw[:120]}")
    code = resp.get("code")
    if code != 200:
        hint = ""
        if code == 905:
            hint = "（需先在 https://verify.pushplus.plus 完成实名认证）"
        elif code in (401, 903):
            hint = "（token 无效，或没关注「PushPlus 推送加」公众号）"
        raise RuntimeError(f"code={code} {resp.get('msg', '')}{hint}")


def _post_checked(url: str, payload: dict) -> None:
    """企业微信 / 钉钉 / 飞书失败时 HTTP 仍可能是 200，必须看返回体。"""
    raw = http_post(url, payload)
    try:
        resp = json.loads(raw)
    except json.JSONDecodeError:
        return
    if not isinstance(resp, dict):
        return
    code = resp.get("errcode", resp.get("code"))
    if code not in (0, None):
        raise RuntimeError(f"code={code} {resp.get('errmsg') or resp.get('msg') or ''}")


def _dingtalk_url(cfg: dict) -> str:
    """钉钉机器人若用「加签」安全设置，需要补 timestamp + sign。"""
    url = cfg["dingtalk_webhook"]
    secret = cfg.get("dingtalk_secret") or ""
    if not secret:
        return url
    ts = str(round(time.time() * 1000))
    digest = hmac.new(secret.encode("utf-8"), f"{ts}\n{secret}".encode("utf-8"),
                      hashlib.sha256).digest()
    sign = urllib.parse.quote_plus(base64.b64encode(digest))
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}timestamp={ts}&sign={sign}"


def notify_webhooks(cfg: dict, title: str, text: str, html: str) -> None:
    def safe(name, fn):
        try:
            fn()
            log(f"  [ok] {name} 已推送")
        except Exception as e:  # noqa: BLE001
            log(f"  [warn] {name} 推送失败: {e}")

    if cfg.get("pushplus_token"):
        safe("PushPlus", lambda: pushplus_send(cfg["pushplus_token"], title, html))

    if cfg.get("serverchan_key"):
        safe("ServerChan", lambda: http_post(
            f"https://sctapi.ftqq.com/{cfg['serverchan_key']}.send",
            urllib.parse.urlencode({"title": title, "desp": html}).encode("utf-8"),
            {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"}))

    if cfg.get("bark_url"):
        base = cfg["bark_url"].rstrip("/")
        safe("Bark", lambda: http_get(
            f"{base}/{urllib.parse.quote(title)}/{urllib.parse.quote(text[:900])}?group=bwc"))

    if cfg.get("feishu_webhook"):
        safe("飞书", lambda: http_post(cfg["feishu_webhook"], {
            "msg_type": "text", "content": {"text": f"{title}\n{text}"}}))

    if cfg.get("wecom_webhook"):
        safe("企业微信", lambda: _post_checked(cfg["wecom_webhook"], {
            "msgtype": "text", "text": {"content": f"{title}\n{text}"}}))

    if cfg.get("dingtalk_webhook"):
        safe("钉钉", lambda: _post_checked(_dingtalk_url(cfg), {
            "msgtype": "text", "text": {"content": f"{title}\n{text}"}}))

    tg = cfg.get("telegram") or {}
    if tg.get("bot_token") and tg.get("chat_id"):
        safe("Telegram", lambda: http_post(
            f"https://api.telegram.org/bot{tg['bot_token']}/sendMessage",
            {"chat_id": tg["chat_id"], "text": f"<b>{title}</b>\n{text}",
             "parse_mode": "HTML", "disable_web_page_preview": True}))

    if cfg.get("generic_webhook"):
        safe("自定义 webhook", lambda: http_post(cfg["generic_webhook"], {
            "title": title, "content": text, "html": html}))


def notify_email(cfg: dict, title: str, text: str, html: str | None = None) -> None:
    smtp = cfg.get("smtp") or {}
    if not (smtp.get("host") and smtp.get("user") and smtp.get("to")):
        return
    if "你的" in str(smtp.get("user")) + str(smtp.get("password")) + str(smtp.get("to")):
        return  # 还是模板占位符，视为未配置
    try:
        msg = EmailMessage()
        msg["Subject"] = title
        msg["From"] = smtp["user"]
        msg["To"] = ", ".join(smtp["to"])
        msg.set_content(text)
        if html:
            msg.add_alternative(html, subtype="html")
        ctx = ssl.create_default_context()
        if smtp.get("ssl", True):
            with smtplib.SMTP_SSL(smtp["host"], int(smtp.get("port", 465)), context=ctx, timeout=25) as s:
                s.login(smtp["user"], smtp["password"])
                s.send_message(msg)
        else:
            with smtplib.SMTP(smtp["host"], int(smtp.get("port", 587)), timeout=25) as s:
                s.starttls(context=ctx)
                s.login(smtp["user"], smtp["password"])
                s.send_message(msg)
        log("  [ok] 邮件已发送")
    except Exception as e:  # noqa: BLE001
        log(f"  [warn] 邮件发送失败: {e}")


# --------------------------------------------------------------------------- 输出
def build_text(items: list[dict]) -> str:
    return "\n".join(f"[{it['date']}] {it['title']}\n    {it['url']}" for it in items)


def build_html(items: list[dict], when: datetime) -> str:
    rows = "\n".join(
        f'<li><span class="d">{it["date"]}</span>'
        f'<span class="s">{it["site"]}</span>'
        f'<a href="{it["url"]}" target="_blank">{it["title"]}</a></li>'
        for it in items)
    return f"""<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<title>安全保卫部监控 {when:%Y-%m-%d %H:%M}</title>
<style>
 body{{font:15px/1.7 -apple-system,"Microsoft YaHei",sans-serif;max-width:900px;margin:32px auto;padding:0 16px;color:#222}}
 h1{{font-size:19px}} .meta{{color:#888;font-size:13px;margin-bottom:18px}}
 li{{margin:10px 0;padding-left:4px}} a{{color:#0b62c4;text-decoration:none}} a:hover{{text-decoration:underline}}
 .d{{color:#888;font-variant-numeric:tabular-nums;margin-right:10px;font-size:13px}}
 .s{{display:inline-block;background:#eef3fb;color:#3a6ea5;border-radius:3px;padding:0 6px;font-size:12px;margin-right:8px}}
 .empty{{color:#999}}
</style>
<h1>浙大宁波理工学院安全保卫部 · 命中公告</h1>
<div class="meta">检查时间 {when:%Y-%m-%d %H:%M:%S} ｜ 共 {len(items)} 条</div>
<ul>{rows or '<li class="empty">本次没有新的命中公告</li>'}</ul>
</html>"""


def append_log(path: Path, items: list[dict], hits: set[str]) -> None:
    with path.open("a", encoding="utf-8") as f:
        for it in items:
            flag = "HIT " if it["url"] in hits else "MISS"
            f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S}\t{flag}\t{it['site']}\t"
                    f"{it['date']}\t{it['title']}\t{it['url']}\n")


# --------------------------------------------------------------------------- 主流程
def load_config() -> dict:
    cfg = json.loads(json.dumps(DEFAULTS))
    if CONFIG_FILE.exists():
        user = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        for k, v in user.items():
            if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                cfg[k] = {**cfg[k], **v}
            else:
                cfg[k] = v
    _apply_env_overrides(cfg)
    return cfg


def _apply_env_overrides(cfg: dict) -> None:
    """云端（GitHub Actions）通过环境变量注入密钥，仓库里就不用存明文。"""
    notify = cfg.setdefault("notify", {})
    for env, key in (
        ("BWC_DINGTALK_WEBHOOK", "dingtalk_webhook"),
        ("BWC_DINGTALK_SECRET", "dingtalk_secret"),
        ("BWC_PUSHPLUS_TOKEN", "pushplus_token"),
        ("BWC_SERVERCHAN_KEY", "serverchan_key"),
    ):
        val = os.environ.get(env)
        if val:
            notify[key] = val


def load_state(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            log("状态文件损坏，忽略并重建")
    return {"seen": {}}


def save_state(path: Path, state: dict, keep: int = 3000) -> None:
    for k, ids in list(state["seen"].items()):
        state["seen"][k] = ids[-keep:]
    state["updated"] = datetime.now().isoformat(timespec="seconds")
    path.write_text(json.dumps(state, ensure_ascii=False, indent=1), encoding="utf-8")


def run(mode: str, verbose: bool, list_n: int = 10) -> int:
    cfg = load_config()
    state_path = HERE / cfg["state_file"]
    state = load_state(state_path)
    first_run = not state.get("seen")

    all_new: list[dict] = []
    all_items: list[dict] = []
    errors = 0
    for site in cfg["sites"]:
        try:
            items = fetch_site(site)
        except Exception as e:  # noqa: BLE001
            log(f"[{site['name']}] {e}")
            errors += 1
            continue
        all_items.extend(items)
        seen_ids = set(state["seen"].get(site["name"], []))
        new = [it for it in items if it["id"] not in seen_ids]
        log(f"[{site['name']}] 抓取 {len(items)} 条，新 {len(new)} 条")
        all_new.extend(new)
        state["seen"].setdefault(site["name"], [])
        state["seen"][site["name"]].extend(it["id"] for it in new)

    if errors and errors == len(cfg["sites"]):
        log(f"所有 {errors} 个栏目都抓取失败，本次不做任何记录（网络或站点不可达）。")
        return 1

    if mode == "list":
        for it in all_items[:list_n]:
            print(f"  {it['date']}  {it['title']}\n             {it['url']}")
        return 0

    if first_run:
        log(f"首次运行：已记录 {len(all_new)} 条为基线，本次不通知。之后只在有新命中时提醒。")
        save_state(state_path, state)
        (HERE / cfg["digest_file"]).write_text(
            build_html([], datetime.now()), encoding="utf-8")
        return 0

    pats = compile_patterns(cfg["keywords"])
    exc = compile_patterns(cfg.get("exclude") or [])
    mode_kw = cfg.get("match_mode", "any")
    hits, misses = [], []
    for it in all_new:
        text = f"{it['title']} {it.get('date','')}"
        if cfg.get("match_body"):
            text += " " + fetch_body(it["url"])
        ok = matched(text, pats, mode_kw) and not (exc and matched(text, exc, "any"))
        (hits if ok else misses).append(it)

    if verbose:
        for it in misses:
            log(f"  (未命中) {it['date']} {it['title']}")

    save_state(state_path, state)
    append_log(HERE / cfg["log_file"], all_new, {it["url"] for it in hits})
    (HERE / cfg["digest_file"]).write_text(build_html(hits, datetime.now()), encoding="utf-8")

    if not all_new:
        log("没有新公告。")
        return 0
    if not hits:
        log(f"有 {len(all_new)} 条新公告，但没有命中关键词。")
        return 0

    log(f"命中 {len(hits)} 条：")
    for it in hits:
        log(f"  ★ {it['date']} {it['title']}")
        log(f"    {it['url']}")

    title = f"安全保卫部新公告 {len(hits)} 条命中"
    text = build_text(hits)
    if cfg.get("windows_toast"):
        notify_windows_toast(title, "\n".join(f"{it['date']} {it['title']}" for it in hits)[:240])
    notify_webhooks(cfg.get("notify") or {}, title, text, build_html(hits, datetime.now()))
    notify_email(cfg.get("notify") or {}, title, text, build_html(hits, datetime.now()))
    return 2


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    ap = argparse.ArgumentParser(description="安全保卫部公告关键词监控")
    ap.add_argument("--test", action="store_true", help="发送测试通知")
    ap.add_argument("--list", nargs="?", type=int, const=10, default=None, metavar="N",
                    help="只打印站上最新 N 条公告（默认 10），不写状态")
    ap.add_argument("--reset", action="store_true", help="清空已读记录")
    ap.add_argument("--verbose", action="store_true", help="打印未命中的新公告")
    args = ap.parse_args()

    cfg = load_config()
    if args.reset:
        (HERE / cfg["state_file"]).unlink(missing_ok=True)
        log("已清空状态文件，下次运行将重新建立基线。")
        return 0
    if args.test:
        log("发送测试通知……")
        notify_windows_toast("安全保卫部监控测试", "看到这条说明桌面提醒可用。")
        notify_webhooks(cfg.get("notify") or {}, "安全保卫部监控测试", "测试消息", "<p>测试消息</p>")
        notify_email(
            cfg.get("notify") or {}, "安全保卫部监控测试", "测试消息",
            "<p>看到这封邮件说明<b>邮件提醒通道可用</b>。</p>"
            "<p>以后站上出现含有关键词的新公告，会有一封同样格式的邮件，点标题直达公告页。</p>")
        return 0
    return run("list" if args.list is not None else "run", args.verbose, args.list or 10)


if __name__ == "__main__":
    sys.exit(main())
