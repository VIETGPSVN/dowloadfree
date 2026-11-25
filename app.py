"""
Website tải video / ảnh từ link Facebook, Instagram, TikTok (v2).

Luồng: dán link -> CAPTCHA -> Phân tích (ảnh, tiêu đề, chất lượng) -> chọn chất lượng -> tải.

Chạy thử:   python app.py          -> http://localhost:8000
Chạy thật:  gunicorn -w 1 --threads 8 -b 0.0.0.0:8000 app:app
LƯU Ý: chỉ dùng 1 worker vì danh sách phiên/tác vụ lưu trong bộ nhớ.
Cấu hình qua biến môi trường, xem file .env.example.
"""
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid
import zipfile
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse

import yt_dlp
from flask import Flask, Response, abort, jsonify, render_template, request, send_file
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__, template_folder=".")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)  # lấy IP thật khi chạy sau Nginx/Cloudflare

# ---------------- Cấu hình ----------------
BASE = Path(os.environ.get("DL_DIR", "/tmp/dl_jobs"))
BASE.mkdir(parents=True, exist_ok=True)
MAX_MB = int(os.environ.get("MAX_MB", "200"))              # dung lượng tối đa mỗi file
MAX_DURATION = int(os.environ.get("MAX_DURATION", "900"))  # thời lượng tối đa (giây)
TTL = int(os.environ.get("TTL", "900"))                    # giữ file bao lâu (giây)
ANALYSIS_TTL = 600                                         # phiên phân tích sống bao lâu (giây)
RATE_LIMIT = int(os.environ.get("RATE_LIMIT", "10"))       # số lượt phân tích / IP
RATE_WINDOW = int(os.environ.get("RATE_WINDOW", "600"))    # trong bao nhiêu giây
MAX_CONCURRENT = int(os.environ.get("MAX_CONCURRENT", "2"))        # số tác vụ tải đồng thời
MAX_ANALYZE_CONCURRENT = int(os.environ.get("MAX_ANALYZE_CONCURRENT", "4"))

SITE_NAME = os.environ.get("SITE_NAME", "TaiVideo")
CONTACT_EMAIL = os.environ.get("CONTACT_EMAIL", "lienhe@example.com")
LEGAL_UPDATED = os.environ.get("LEGAL_UPDATED", "25/11/2026")

TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "")
TURNSTILE_SECRET = os.environ.get("TURNSTILE_SECRET", "")
BLOCKLIST_FILE = Path(os.environ.get("BLOCKLIST_FILE", Path(__file__).with_name("blocked_urls.txt")))

HAS_FFMPEG = shutil.which("ffmpeg") is not None

ALLOWED_DOMAINS = ("facebook.com", "fb.watch", "fb.com", "instagram.com", "tiktok.com")

PLATFORMS = {
    "all": {
        "slug": "/",
        "name": "Tất cả",
        "domains": ALLOWED_DOMAINS,
        "h1": "Tải video, ảnh từ Facebook, Instagram, TikTok",
        "placeholder": "Dán link Facebook, Instagram hoặc TikTok vào đây...",
        "intro": "Dán link bài đăng công khai, xem trước nội dung, chọn chất lượng rồi tải về máy.",
        "meta": "Công cụ tải video, ảnh từ Facebook, Instagram, TikTok miễn phí. Dán link, chọn chất lượng và tải về.",
    },
    "facebook": {
        "slug": "/tai-video-facebook",
        "name": "Facebook",
        "domains": ("facebook.com", "fb.watch", "fb.com"),
        "h1": "Tải video Facebook",
        "placeholder": "Dán link video, Reels Facebook (facebook.com, fb.watch)...",
        "intro": "Tải video, Reels Facebook công khai về máy. Chọn chất lượng bạn muốn.",
        "meta": "Tải video Facebook, Reels Facebook công khai miễn phí. Dán link, chọn chất lượng, tải về.",
    },
    "instagram": {
        "slug": "/tai-video-instagram",
        "name": "Instagram",
        "domains": ("instagram.com",),
        "h1": "Tải video, ảnh Instagram",
        "placeholder": "Dán link bài viết, Reels Instagram (instagram.com)...",
        "intro": "Tải video, Reels và ảnh Instagram công khai về máy.",
        "meta": "Tải video, Reels, ảnh Instagram công khai miễn phí. Dán link, xem trước, tải về.",
    },
    "tiktok": {
        "slug": "/tai-video-tiktok",
        "name": "TikTok",
        "domains": ("tiktok.com",),
        "h1": "Tải video TikTok",
        "placeholder": "Dán link video TikTok (tiktok.com, vm.tiktok.com)...",
        "intro": "Tải video TikTok công khai hoặc chỉ lấy âm thanh MP3.",
        "meta": "Tải video TikTok công khai miễn phí, hỗ trợ xuất MP3. Dán link, chọn chất lượng, tải về.",
    },
}

LEGAL_PATHS = ["/dieu-khoan", "/chinh-sach-rieng-tu", "/lien-he", "/go-noi-dung"]

jobs = {}      # job_id -> thông tin tác vụ tải
analyses = {}  # analysis_id -> kết quả phân tích
hits = {}      # ip -> [timestamp, ...]
lock = threading.Lock()
slots = threading.Semaphore(MAX_CONCURRENT)
analyze_slots = threading.Semaphore(MAX_ANALYZE_CONCURRENT)


class UserError(Exception):
    """Lỗi có thông điệp thân thiện để hiển thị cho người dùng."""


# ---------------- Tiện ích ----------------
def url_allowed(url: str, domains=ALLOWED_DOMAINS) -> bool:
    try:
        p = urlparse(url)
    except ValueError:
        return False
    if p.scheme not in ("http", "https") or not p.hostname:
        return False
    h = p.hostname.lower()
    return any(h == d or h.endswith("." + d) for d in domains)


def rate_ok(ip: str) -> bool:
    now = time.time()
    with lock:
        arr = [t for t in hits.get(ip, []) if now - t < RATE_WINDOW]
        if len(arr) >= RATE_LIMIT:
            hits[ip] = arr
            return False
        arr.append(now)
        hits[ip] = arr
        return True


def verify_turnstile(token, ip) -> bool:
    """Xác minh Cloudflare Turnstile. Nếu chưa cấu hình khoá thì bỏ qua (chế độ phát triển)."""
    if not TURNSTILE_SECRET:
        return True
    if not token:
        return False
    data = urllib.parse.urlencode({"secret": TURNSTILE_SECRET, "response": token, "remoteip": ip}).encode()
    try:
        with urllib.request.urlopen(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify", data=data, timeout=10
        ) as r:
            return json.load(r).get("success") is True
    except Exception:  # noqa: BLE001
        return False


# ---- Danh sách chặn (xử lý yêu cầu gỡ nội dung) ----
_KEEP_QUERY = {"v", "story_fbid", "fbid", "id", "story_id"}


def norm_url(url: str) -> str:
    p = urlparse(url.strip())
    host = (p.hostname or "").lower()
    for pre in ("www.", "m.", "web.", "mbasic."):
        if host.startswith(pre):
            host = host[len(pre):]
    q = sorted(kv for kv in parse_qsl(p.query) if kv[0] in _KEEP_QUERY)
    s = host + p.path.rstrip("/")
    if q:
        s += "?" + urlencode(q)
    return s


def is_blocked(url: str) -> bool:
    if not url:
        return False
    try:
        lines = BLOCKLIST_FILE.read_text(encoding="utf-8").splitlines()
    except OSError:
        return False
    n = norm_url(url)
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        b = norm_url(line if "://" in line else "https://" + line)
        if n == b or n.startswith(b + "/"):
            return True
    return False


# ---- Dọn dẹp định kỳ ----
def cleanup_loop():
    while True:
        time.sleep(60)
        now = time.time()
        with lock:
            for k in [k for k, j in jobs.items() if now - j["created"] > TTL]:
                shutil.rmtree(jobs[k]["dir"], ignore_errors=True)
                del jobs[k]
            for k in [k for k, a in analyses.items() if now - a["created"] > ANALYSIS_TTL]:
                del analyses[k]
            for ip in list(hits):
                hits[ip] = [t for t in hits[ip] if now - t < RATE_WINDOW]
                if not hits[ip]:
                    del hits[ip]


threading.Thread(target=cleanup_loop, daemon=True).start()


# ---------------- Phân tích link ----------------
def analyze_ytdlp(url):
    opts = {
        "quiet": True,
        "no_warnings": True,
        "noplaylist": True,
        "skip_download": True,
        "socket_timeout": 20,
        "retries": 1,
    }
    with yt_dlp.YoutubeDL(opts) as ydl:
        info = ydl.extract_info(url, download=False)
    if not info:
        raise RuntimeError("Không có thông tin")

    multi, count, first = False, 1, info
    if info.get("_type") == "playlist":
        entries = [e for e in (info.get("entries") or []) if e]
        if not entries:
            raise RuntimeError("Danh sách trống")
        first, count, multi = entries[0], len(entries), len(entries) > 1

    duration = first.get("duration")
    if duration and duration > MAX_DURATION:
        raise UserError(f"Video dài quá giới hạn {MAX_DURATION // 60} phút của hệ thống.")

    heights = sorted(
        {
            f["height"]
            for f in (first.get("formats") or [])
            if f.get("height") and f.get("vcodec") not in (None, "none")
        },
        reverse=True,
    )[:5]

    options = []
    if multi:
        options.append({"id": "best", "label": f"Tải tất cả {count} mục (nén ZIP)"})
    elif len(heights) > 1:
        for i, h in enumerate(heights):
            label = f"Video {h}p (MP4)" + (" - cao nhất" if i == 0 else "")
            options.append({"id": f"h{h}", "label": label})
    else:
        options.append({"id": "best", "label": "Video chất lượng cao nhất (MP4)"})
    if HAS_FFMPEG and not multi:
        options.append({"id": "audio", "label": "Chỉ âm thanh (MP3)"})

    thumb = first.get("thumbnail") or info.get("thumbnail")
    if not (isinstance(thumb, str) and thumb.startswith("https://")):
        thumb = None
    title = (info.get("title") or first.get("title") or "Video").strip()[:120]
    if multi:
        title += f" ({count} mục)"

    return {
        "kind": "ytdlp",
        "url": url,
        "canonical": info.get("webpage_url") or url,
        "multi": multi,
        "title": title,
        "uploader": first.get("uploader") or first.get("channel") or info.get("uploader"),
        "duration": duration,
        "thumbnail": thumb,
        "options": options,
    }


def analyze_gallery(url):
    try:
        r = subprocess.run(
            [sys.executable, "-m", "gallery_dl", "-g", "--range", "1-30", url],
            capture_output=True, text=True, timeout=60,
        )
    except Exception:  # noqa: BLE001
        raise UserError("Không phân tích được link này.")
    urls = [l.strip() for l in r.stdout.splitlines() if l.strip().startswith("http")]
    if not urls:
        raise UserError(
            "Không tìm thấy nội dung tải được. Link có thể riêng tư, đã bị xoá, "
            "cần đăng nhập hoặc nền tảng đang chặn."
        )
    first = urls[0]
    is_img = any(ext in first.lower().split("?")[0] for ext in (".jpg", ".jpeg", ".png", ".webp"))
    return {
        "kind": "gallery",
        "url": url,
        "canonical": url,
        "multi": len(urls) > 1,
        "title": f"Bài đăng có {len(urls)} tệp ảnh/video",
        "uploader": None,
        "duration": None,
        "thumbnail": first if (is_img and first.startswith("https://")) else None,
        "options": [{"id": "images", "label": f"Tải tất cả ({len(urls)} tệp)"}],
    }


def analyze(url):
    try:
        return analyze_ytdlp(url)
    except UserError:
        raise
    except Exception:  # noqa: BLE001
        return analyze_gallery(url)


# ---------------- Tải xuống ----------------
def try_ytdlp(url, d: Path, choice, multi):
    opts = {
        "outtmpl": str(d / "%(extractor)s_%(id)s.%(ext)s"),
        "noplaylist": not multi,
        "quiet": True,
        "no_warnings": True,
        "restrictfilenames": True,
        "socket_timeout": 20,
        "retries": 2,
        "max_filesize": MAX_MB * 1024 * 1024,
        "match_filter": yt_dlp.utils.match_filter_func(f"duration <=? {MAX_DURATION}"),
        "format_sort": ["vcodec:h264", "res", "acodec:m4a"],
    }
    if multi:
        opts["playlistend"] = 10
    if choice == "audio":
        opts["format"] = "bestaudio/best"
        opts["postprocessors"] = [{"key": "FFmpegExtractAudio", "preferredcodec": "mp3"}]
    else:
        if choice.startswith("h") and choice[1:].isdigit() and HAS_FFMPEG:
            h = int(choice[1:])
            opts["format"] = f"bv*[height<={h}]+ba/b[height<={h}]"
        elif HAS_FFMPEG:
            opts["format"] = "bv*+ba/b"
        else:
            opts["format"] = "b"
        if HAS_FFMPEG:
            opts["merge_output_format"] = "mp4"
    try:
        with yt_dlp.YoutubeDL(opts) as ydl:
            ydl.download([url])
        return True, ""
    except Exception as e:  # noqa: BLE001
        return False, str(e)


def try_gallerydl(url, d: Path):
    try:
        r = subprocess.run(
            [sys.executable, "-m", "gallery_dl", "--range", "1-30", "-d", str(d), url],
            capture_output=True, text=True, timeout=120,
        )
        return r.returncode == 0, (r.stderr or r.stdout)
    except Exception as e:  # noqa: BLE001
        return False, str(e)


def run_job(job_id, rec, choice):
    job = jobs[job_id]
    d: Path = job["dir"]
    with slots:
        job["status"] = "running"
        try:
            if rec["kind"] == "gallery":
                try_gallerydl(rec["url"], d)
            else:
                try_ytdlp(rec["url"], d, choice, rec["multi"])
            files = [f for f in d.rglob("*") if f.is_file()]
            if not files:
                raise RuntimeError(
                    "Không tải được. Có thể link riêng tư, đã bị xoá, quá nặng "
                    f"(giới hạn {MAX_MB} MB) hoặc nền tảng đang chặn."
                )
            if len(files) > 1:
                z = d / "media.zip"
                with zipfile.ZipFile(z, "w") as zf:
                    for f in files:
                        zf.write(f, f.relative_to(d))
                result = z
            else:
                result = files[0]
            job.update(status="done", file=str(result), filename=result.name)
        except Exception as e:  # noqa: BLE001
            job.update(status="error", message=str(e)[:300])


# ---------------- Trang web ----------------
@app.context_processor
def inject_globals():
    return {
        "SITE_NAME": SITE_NAME,
        "CONTACT_EMAIL": CONTACT_EMAIL,
        "PLATFORMS": PLATFORMS,
        "LEGAL_UPDATED": LEGAL_UPDATED,
    }


def make_page(key):
    def view():
        return render_template(
            "downloader.html",
            key=key,
            active=key,
            p=PLATFORMS[key],
            ts_site_key=TURNSTILE_SITE_KEY,
            max_mb=MAX_MB,
            max_min=MAX_DURATION // 60,
        )

    view.__name__ = f"page_{key}"
    return view


for _k, _p in PLATFORMS.items():
    app.add_url_rule(_p["slug"], endpoint=f"page_{_k}", view_func=make_page(_k))


@app.get("/dieu-khoan")
def terms():
    return render_template("terms.html", active=None)


@app.get("/chinh-sach-rieng-tu")
def privacy():
    return render_template("privacy.html", active=None)


@app.get("/lien-he")
def contact():
    return render_template("contact.html", active=None)


@app.get("/go-noi-dung")
def takedown():
    return render_template("takedown.html", active=None)


@app.get("/robots.txt")
def robots():
    body = f"User-agent: *\nAllow: /\nDisallow: /api/\nSitemap: {request.url_root}sitemap.xml\n"
    return Response(body, mimetype="text/plain")


@app.get("/sitemap.xml")
def sitemap():
    paths = [p["slug"] for p in PLATFORMS.values()] + LEGAL_PATHS
    root = request.url_root.rstrip("/")
    items = "".join(f"<url><loc>{root}{p}</loc></url>" for p in paths)
    xml = f'<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{items}</urlset>'
    return Response(xml, mimetype="application/xml")


@app.get("/googlec4e115eedc464aff.html")
def google_verify():
    return Response("google-site-verification: googlec4e115eedc464aff.html", mimetype="text/html")
def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    return resp


# ---------------- API ----------------
def err(message, code):
    return jsonify(error=message), code


@app.post("/api/analyze")
def api_analyze():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()[:2000]
    platform = PLATFORMS.get(data.get("platform"), PLATFORMS["all"])
    ip = request.remote_addr or "unknown"

    if not data.get("agree"):
        return err("Bạn cần xác nhận cam kết sử dụng.", 400)
    if not url_allowed(url, platform["domains"]):
        return err(f"Link không hợp lệ. Trang này hỗ trợ link {platform['name']}.", 400)
    if len(analyses) > 5000:
        return err("Hệ thống đang quá tải, vui lòng thử lại sau.", 503)
    if not rate_ok(ip):
        return err("Bạn thao tác quá nhanh, vui lòng thử lại sau vài phút.", 429)
    if not verify_turnstile(data.get("cf_token"), ip):
        return err("Xác minh CAPTCHA thất bại, hãy thử lại.", 400)
    if is_blocked(url):
        return err("Nội dung này đã bị chặn theo yêu cầu của chủ sở hữu.", 451)
    if not analyze_slots.acquire(timeout=10):
        return err("Hệ thống đang bận, vui lòng thử lại sau ít phút.", 503)
    try:
        rec = analyze(url)
    except UserError as e:
        return err(str(e), 422)
    except Exception:  # noqa: BLE001
        return err("Không phân tích được link này. Hãy kiểm tra link công khai và thử lại.", 422)
    finally:
        analyze_slots.release()

    if is_blocked(rec["canonical"]):
        return err("Nội dung này đã bị chặn theo yêu cầu của chủ sở hữu.", 451)

    rec.update(created=time.time(), starts=0)
    aid = uuid.uuid4().hex
    analyses[aid] = rec
    return jsonify(
        analysis_id=aid,
        title=rec["title"],
        uploader=rec["uploader"],
        duration=rec["duration"],
        thumbnail=rec["thumbnail"],
        options=rec["options"],
    )


@app.post("/api/start")
def api_start():
    data = request.get_json(silent=True) or {}
    rec = analyses.get(data.get("analysis_id"))
    if not rec:
        return err("Phiên phân tích đã hết hạn, hãy phân tích lại link.", 410)
    choice = data.get("choice")
    if choice not in {o["id"] for o in rec["options"]}:
        return err("Lựa chọn không hợp lệ.", 400)
    if rec["starts"] >= 3:
        return err("Bạn đã tải quá số lần cho phiên này, hãy phân tích lại link.", 429)
    if is_blocked(rec["url"]) or is_blocked(rec["canonical"]):
        return err("Nội dung này đã bị chặn theo yêu cầu của chủ sở hữu.", 451)

    rec["starts"] += 1
    job_id = uuid.uuid4().hex
    d = BASE / job_id
    d.mkdir(parents=True)
    jobs[job_id] = {"status": "queued", "dir": d, "created": time.time()}
    threading.Thread(target=run_job, args=(job_id, rec, choice), daemon=True).start()
    return jsonify(job_id=job_id)


@app.get("/api/status/<job_id>")
def status(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify(status="error", message="Phiên đã hết hạn, hãy thử lại."), 404
    return jsonify(status=job["status"], message=job.get("message"), filename=job.get("filename"))


@app.get("/api/file/<job_id>")
def get_file(job_id):
    job = jobs.get(job_id)
    if not job or job["status"] != "done":
        abort(404)
    return send_file(job["file"], as_attachment=True, download_name=job["filename"])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
