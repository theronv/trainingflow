#!/usr/bin/env python3
"""
Build Pregame course bundles from a Freshdesk snapshot (kb_snapshot.py) and manifest.json.

Run from the repo root:
  pip install markdownify beautifulsoup4 pillow
  python3 kb_build.py --snapshot ~/Downloads/snapshot --manifest ~/Downloads/manifest.json --only synergy-softball-app
  python3 kb_build.py --snapshot ~/Downloads/snapshot --manifest ~/Downloads/manifest.json          # all courses
Options:
  --base https://pregame-academy.vickerydigital.com/assets/synergy/   public URL of the images folder
  --max-width 1280     shrink wider screenshots (needs Pillow); 0 to keep originals

Images are kept small: PNGs without transparency are saved as JPEG (quality 82) and linked by their .jpg
name, and GIFs over 1.5 MB are optimised with gifsicle when it is installed (brew install gifsicle).
Files that already exist in assets/synergy are reused untouched, so published names never change.

Writes (safe to rerun; existing questions in a bundle are kept):
  content/synergy/<course-id>.json   one bundle per course, in the importer's format
  assets/synergy/<articleId>-NN.ext  images and attachments, named like the earlier Baseball import
  content/synergy/build-report.csv   everything that needs a look before importing
"""
import os, re, sys, csv, json, html, shutil, subprocess
from bs4 import BeautifulSoup, NavigableString
from markdownify import markdownify

def arg(name, default=None):
    return sys.argv[sys.argv.index(name) + 1] if name in sys.argv else default

SNAP = os.path.expanduser(arg("--snapshot") or sys.exit(__doc__))
MANIFEST = os.path.expanduser(arg("--manifest") or sys.exit(__doc__))
BASE = (arg("--base") or "https://pregame-academy.vickerydigital.com/assets/synergy/").rstrip("/") + "/"
ONLY = arg("--only")
MAX_W = int(arg("--max-width", "1280"))
JPEG_QUALITY = 82
GIF_MIN_BYTES = 1_500_000  # only GIFs larger than this are optimised
GIFSICLE = shutil.which("gifsicle")
OUT_JSON, OUT_ASSETS = "content/synergy", "assets/synergy"
PUBLIC = "https://support.synergysports.com/support/solutions/articles/"
ART_LINK = re.compile(r"/solutions/articles/(\d+)")

man = json.load(open(MANIFEST, encoding="utf-8"))
asset_map = {}
for r in csv.DictReader(open(f"{SNAP}/asset_map.csv", encoding="utf-8")):
    if r["local_path"]:
        asset_map.setdefault(r["article_id"], {})[r["old_url"]] = os.path.join(SNAP, os.path.relpath(r["local_path"], "snapshot")) \
            if not os.path.isabs(r["local_path"]) else r["local_path"]
where = {}  # article id -> (course title, module title)
for c in man["courses"]:
    for m in c["modules"]:
        for a in m["articles"]:
            where[a] = (c["title"], m["title"])
report = []

def note(course, module, aid, issue, detail=""):
    report.append({"course": course, "module": module, "article_id": aid, "issue": issue, "detail": detail})

def norm(url):
    url = html.unescape(url or "").strip()
    return "https:" + url if url.startswith("//") else url

def load(aid):
    return json.load(open(f"{SNAP}/articles/{aid}.json", encoding="utf-8"))

def ordered_images(aid):
    """Local image files for an article, in the order they appear in its body."""
    soup = BeautifulSoup(load(aid).get("description") or "", "html.parser")
    files = asset_map.get(aid, {})
    return [files.get(norm(i.get("src"))) for i in soup.find_all("img")]

def has_transparency(im):
    if im.mode in ("RGBA", "LA"):
        return im.getchannel("A").getextrema()[0] < 255
    return "transparency" in im.info

def shrink_gif(path):
    """Lossy-optimise a big GIF in place with gifsicle (skipped if it is not installed)."""
    if not GIFSICLE or os.path.getsize(path) <= GIF_MIN_BYTES:
        return
    tmp = path + ".tmp"
    run = subprocess.run([GIFSICLE, "-O3", "--lossy=80", "--colors", "128", "-o", tmp, path], capture_output=True)
    if run.returncode == 0 and os.path.exists(tmp) and os.path.getsize(tmp) < os.path.getsize(path):
        os.replace(tmp, path)
    elif os.path.exists(tmp):
        os.remove(tmp)

def publish(local, aid, n, prefix=""):
    """Copy an image/attachment into assets/synergy as <articleId>-NN.<ext> and return its public URL.
    Files that already exist are kept as they are, so names stay stable across rebuilds. Images wider
    than --max-width are shrunk, PNGs without transparency become JPEG, and big GIFs go through gifsicle."""
    ext = os.path.splitext(local)[1].lower() or ".bin"
    ext = {".jpe": ".jpg", ".jpeg": ".jpg"}.get(ext, ext)
    stem = f"{aid}-{prefix}{n:02d}"
    names = [stem + ext] + ([stem + ".jpg"] if ext == ".png" else [])  # a PNG may have been converted earlier
    for name in names:
        if os.path.exists(os.path.join(OUT_ASSETS, name)):
            return BASE + name
    name = stem + ext
    dest = os.path.join(OUT_ASSETS, name)
    shutil.copyfile(local, dest)
    if ext == ".gif":
        shrink_gif(dest)
    elif MAX_W and ext in (".jpg", ".png", ".webp"):
        try:
            from PIL import Image
            with Image.open(dest) as im:
                im.load()
                if im.width > MAX_W:
                    im.thumbnail((MAX_W, 10_000), Image.LANCZOS)
                if ext == ".png" and not has_transparency(im):
                    name = stem + ".jpg"
                    im.convert("RGB").save(os.path.join(OUT_ASSETS, name), "JPEG", quality=JPEG_QUALITY, optimize=True)
                    os.remove(dest)
                else:
                    im.save(dest, optimize=True, **({"quality": JPEG_QUALITY} if ext == ".jpg" else {}))
        except Exception as e:
            print(f"  could not compress {name}: {e}")
    return BASE + name

def to_markdown(aid, course, module, demote):
    a = load(aid)
    title = a.get("title", "").strip()
    soup = BeautifulSoup(a.get("description") or "", "html.parser")
    for t in soup(["script", "style", "meta", "link"]):
        t.decompose()
    for t in soup.find_all(["span", "font", "u"]):
        t.unwrap()

    # images
    files = asset_map.get(aid, {})
    override = man.get("image_overrides", {}).get(aid)
    borrowed = ordered_images(override["use_images_from"]) if override else []
    for n, img in enumerate(soup.find_all("img"), 1):
        local = files.get(norm(img.get("src")))
        if not local and override and n <= len(borrowed):
            local = borrowed[n - 1]
            if n == 1:
                note(course, module, aid, "images borrowed", f"from article {override['use_images_from']}: check they match")
        if local and os.path.exists(local):
            img.attrs = {"src": publish(local, aid, n), "alt": img.get("alt") or f"Screenshot: {title}"}
        else:
            note(course, module, aid, "missing image", f"image {n}: {norm(img.get('src'))[:120]}")
            img.decompose()

    # links: attachments, other articles, old help center
    k = 0
    for link in soup.find_all("a"):
        href = norm(link.get("href"))
        m = ART_LINK.search(href)
        if href in files:
            k += 1
            link.attrs = {"href": publish(files[href], aid, k, "file-")}
        elif m:
            target = m.group(1)
            text = link.get_text(" ", strip=True) or "this article"
            if target in where:
                tc, tm = where[target]
                same = tc == course
                link.replace_with(NavigableString(f"{text} (see the “{tm}” lesson{'' if same else ' in ' + tc})"))
            else:
                link.replace_with(NavigableString(text))
                note(course, module, aid, "link to excluded article", f"{text} -> {target}")
        elif "synergysports.com/support" in href or "zendesk.com" in href:
            note(course, module, aid, "link to old help center", href[:150])
        elif link.get_text(strip=True).lower() in ("click here", "here", "this link"):
            note(course, module, aid, "vague link text", href[:150])
    for t in soup.find_all(["iframe", "video", "embed"]):
        src = norm(t.get("src"))
        t.replace_with(NavigableString(f"[Watch the video]({src})" if src else ""))
        note(course, module, aid, "video embed converted to link", src[:150])

    # complex tables stay as HTML (marked renders raw HTML); simple ones become Markdown
    keep = []
    for tbl in soup.find_all("table"):
        if tbl.find_parent("table"):
            continue
        if tbl.find(attrs={"colspan": True}) or tbl.find(attrs={"rowspan": True}) or tbl.find("table") or tbl.find("img"):  # Markdown tables lose images
            for t in tbl.find_all(True):
                t.attrs = {k: v for k, v in t.attrs.items() if k in ("colspan", "rowspan", "src", "alt", "href")}
            keep.append(str(tbl))
            tbl.replace_with(NavigableString(f"@@TABLE{len(keep) - 1}@@"))
            note(course, module, aid, "table kept as HTML", "has images or merged cells: check it displays well")

    # tidy attributes, headings and empty paragraphs
    for t in soup.find_all(True):
        t.attrs = {k: v for k, v in t.attrs.items() if k in ("href", "src", "alt", "start", "colspan", "rowspan")}
    for h in soup.find_all(re.compile("^h[1-6]$")):  # headings are flattened to text, so move images out after them
        tail = h
        for img in h.find_all("img"):
            wrap = soup.new_tag("p")
            wrap.append(img.extract())
            tail.insert_after(wrap)
            tail = wrap
    for h in soup.find_all(re.compile("^h[1-6]$")):
        level = int(h.name[1]) + (1 if demote else 0)
        h.name = f"h{max(2 if not demote else 3, min(level, 6))}"
    for p in soup.find_all(["p", "div"]):
        if not p.get_text(strip=True) and not p.find("img"):
            p.decompose()

    text = markdownify(str(soup), heading_style="ATX", bullets="-", escape_underscores=False, escape_asterisks=False)
    for i, t in enumerate(keep):
        text = text.replace(f"@@TABLE{i}@@", f"\n\n{t}\n\n")
    text = text.replace("\xa0", " ")
    # drop help-center filler like "In this article, we will discuss how to ..." when it opens a paragraph
    text = re.sub(r"(?im)^(?:In this (?:article|guide|section)|This article)[^.\n]*\b(?:will|we'll|explains?|covers?|describes?|discuss(?:es)?|provides?)\b[^.\n]*\.[ \t]*", "", text)
    text = re.sub(r"(?<=\S)[ \t]*(!\[)", r"\n\1", text)  # images on their own line, still inside list items
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    if len(text.split()) < 20:
        note(course, module, aid, "nearly empty article", f"{len(text.split())} words")
    if re.search(r"^1\.\s.*\n\n!\[[^\n]*\n\n1\.\s", text, re.M):
        note(course, module, aid, "list numbering may restart", "a numbered list is split by an image")
    return title, text

def build(c):
    path = f"{OUT_JSON}/{c['id']}.json"
    old = {}
    if os.path.exists(path):
        prev = json.load(open(path, encoding="utf-8"))
        old = {m.get("reference_url"): m for m in prev.get("modules", [])}
    modules = []
    for m in c["modules"]:
        ids = m["articles"]
        parts = []
        for aid in ids:
            title, md = to_markdown(aid, c["title"], m["title"], demote=len(ids) > 1)
            parts.append(f"## {title}\n\n{md}" if len(ids) > 1 else md)
        content = "\n\n".join(parts)
        words = len(content.split())
        if words > 2500:
            note(c["title"], m["title"], ids[0], "long module", f"{words} words")
        ref = PUBLIC + ids[0]
        prev = old.get(ref, {})
        modules.append({"title": m["title"], "summary": prev.get("summary", ""),
                        "learning_objectives": prev.get("learning_objectives", []), "reference_url": ref,
                        "content": content, "questions": prev.get("questions", [])})
    bundle = {"title": c["title"], "icon": c.get("icon", ""), "description": c.get("description", ""), "modules": modules}
    if os.path.exists(path):
        bundle["description"] = bundle["description"] or json.load(open(path, encoding="utf-8")).get("description", "")
    json.dump(bundle, open(path, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    have_q = sum(1 for m in modules if m["questions"])
    print(f"  {c['title']}: {len(modules)} modules, {sum(len(m['content'].split()) for m in modules)} words, "
          f"{have_q}/{len(modules)} with questions -> {path}")

def main():
    os.makedirs(OUT_JSON, exist_ok=True)
    os.makedirs(OUT_ASSETS, exist_ok=True)
    courses = [c for c in man["courses"] if not ONLY or c["id"] == ONLY]
    if not courses:
        sys.exit(f"No course with id {ONLY}. Ids: " + ", ".join(c["id"] for c in man["courses"]))
    print(f"Building {len(courses)} course(s)...")
    for c in courses:
        build(c)
    rp = f"{OUT_JSON}/build-report.csv"
    with open(rp, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["course", "module", "article_id", "issue", "detail"])
        w.writeheader()
        w.writerows(report)
    size = sum(os.path.getsize(os.path.join(OUT_ASSETS, f)) for f in os.listdir(OUT_ASSETS))
    from collections import Counter
    print(f"\n{len(os.listdir(OUT_ASSETS))} files in {OUT_ASSETS} ({size / 1e6:.0f} MB)")
    print(f"{len(report)} items in {rp}: " + ", ".join(f"{n} {k}" for k, n in Counter(r['issue'] for r in report).most_common()))

if __name__ == "__main__":
    main()
