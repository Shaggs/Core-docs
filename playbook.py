"""
Client "playbook" PDF export for CoreSight Vault.

build_playbook(data, options) turns a plain dict of an organisation's records
into a single PDF: cover page, clickable contents, one section per record type,
rich-text documentation pages rendered inline, and (optionally) uploaded PDFs /
images appended as attachments. The PDF can be AES-256 encrypted.

This module has no Flask / database dependency so it can be tested on its own.
"""
import base64
import io
import os
import re
import secrets
from datetime import datetime, date
from html.parser import HTMLParser
from pathlib import Path
from xml.sax.saxutils import escape as _xml_escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.platypus import (
    BaseDocTemplate, Frame, PageTemplate, NextPageTemplate, PageBreak,
    Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable, CondPageBreak,
    Image as RLImage, SimpleDocTemplate,
)
from reportlab.platypus.tableofcontents import TableOfContents

PAGE_W, PAGE_H = A4
MARGIN = 40
FRAME_W = PAGE_W - 2 * MARGIN

NAVY = colors.HexColor("#0a1628")
ACCENT = colors.HexColor("#1a5fd0")
LIGHT = colors.HexColor("#eef3fb")
GRID = colors.HexColor("#c9d3e3")
MUTED = colors.HexColor("#5b6678")
WARN_BG = colors.HexColor("#fff6dd")
WARN_BORDER = colors.HexColor("#e0b84a")

SECTION_ORDER = [
    ("overview", "Overview"),
    ("contacts", "Contacts"),
    ("sites", "Sites"),
    ("network", "Network"),
    ("domains", "Domains"),
    ("assets", "Assets"),
    ("records", "Custom Records"),
    ("docs", "Documentation"),
    ("passwords", "Passwords & Credentials"),
]

EMBEDDABLE_IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".webp"}


# --------------------------------------------------------------------------
# Fonts
# --------------------------------------------------------------------------
_FONT_CACHE = {}


def _font_dirs():
    dirs = []
    if os.environ.get("PLAYBOOK_FONT_DIR"):
        dirs.append(Path(os.environ["PLAYBOOK_FONT_DIR"]))
    here = Path(__file__).resolve().parent
    dirs += [
        here / "fonts",
        Path("/usr/share/fonts/truetype/dejavu"),
        Path("/usr/share/fonts/dejavu"),
        Path("/usr/share/fonts/TTF"),
        Path("/Library/Fonts"),
        Path.home() / "Library/Fonts",
        Path("C:/Windows/Fonts"),
    ]
    return dirs


def _find(name):
    for d in _font_dirs():
        p = d / name
        if p.exists():
            return str(p)
    return None


def setup_fonts():
    """
    Prefer DejaVu (full Unicode, so any character in a password prints
    correctly). Fall back to the built-in Helvetica/Courier, which only cover
    Western European characters; the builder flags anything they can't show.
    """
    if _FONT_CACHE:
        return _FONT_CACHE
    files = {k: _find(v) for k, v in {
        "r": "DejaVuSans.ttf", "b": "DejaVuSans-Bold.ttf",
        "i": "DejaVuSans-Oblique.ttf", "bi": "DejaVuSans-BoldOblique.ttf",
        "m": "DejaVuSansMono.ttf",
    }.items()}
    if all(files.values()):
        pdfmetrics.registerFont(TTFont("PBSans", files["r"]))
        pdfmetrics.registerFont(TTFont("PBSans-Bold", files["b"]))
        pdfmetrics.registerFont(TTFont("PBSans-Italic", files["i"]))
        pdfmetrics.registerFont(TTFont("PBSans-BoldItalic", files["bi"]))
        pdfmetrics.registerFont(TTFont("PBMono", files["m"]))
        pdfmetrics.registerFontFamily(
            "PBSans", normal="PBSans", bold="PBSans-Bold",
            italic="PBSans-Italic", boldItalic="PBSans-BoldItalic")
        pdfmetrics.registerFontFamily(
            "PBMono", normal="PBMono", bold="PBMono", italic="PBMono", boldItalic="PBMono")
        _FONT_CACHE.update(sans="PBSans", bold="PBSans-Bold", mono="PBMono", unicode=True)
    else:
        _FONT_CACHE.update(sans="Helvetica", bold="Helvetica-Bold", mono="Courier", unicode=False)
    return _FONT_CACHE


def can_render(text, font_key="mono"):
    """
    True if every character can be drawn. Checks the real glyph table of the
    registered font, so characters DejaVu lacks (e.g. CJK, emoji) are caught
    instead of silently printing as empty boxes.
    """
    text = text or ""
    f = setup_fonts()
    if not f["unicode"]:
        try:
            text.encode("cp1252")
            return True
        except UnicodeEncodeError:
            return False
    try:
        glyphs = pdfmetrics.getFont(f[font_key]).face.charToGlyph
    except Exception:
        return True
    return all((ord(ch) in glyphs) or ch in "\t\r\n" for ch in text)


def clean(text):
    """Make text safe for the active font (non-Unicode fonts: replace unsupported chars)."""
    text = "" if text is None else str(text)
    # control characters other than tab/newline break the PDF text stream
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)
    if not setup_fonts()["unicode"]:
        text = text.encode("cp1252", "replace").decode("cp1252")
    return text


def T(text):
    """Escape + clean user text for use inside a reportlab Paragraph."""
    return _xml_escape(clean(text))


def TL(text):
    """Like T() but keeps line breaks."""
    return T(text).replace("\r\n", "\n").replace("\r", "\n").replace("\n", "<br/>")


# --------------------------------------------------------------------------
# Styles
# --------------------------------------------------------------------------
def make_styles():
    f = setup_fonts()
    S = {}
    S["body"] = ParagraphStyle("PBBody", fontName=f["sans"], fontSize=9.5, leading=13.5, textColor=colors.HexColor("#1b2330"))
    S["small"] = ParagraphStyle("PBSmall", parent=S["body"], fontSize=8, leading=10.5, textColor=MUTED)
    S["cell"] = ParagraphStyle("PBCell", parent=S["body"], fontSize=8.5, leading=11)
    S["cellb"] = ParagraphStyle("PBCellB", parent=S["cell"], fontName=f["bold"])
    S["head"] = ParagraphStyle("PBHead", parent=S["cell"], fontName=f["bold"], textColor=colors.white)
    S["label"] = ParagraphStyle("PBLabel", parent=S["cell"], fontName=f["bold"], textColor=MUTED)
    S["mono"] = ParagraphStyle("PBMonoCell", parent=S["cell"], fontName=f["mono"], fontSize=9)
    # headings (names are used by afterFlowable to build contents + bookmarks)
    S["h1"] = ParagraphStyle("PBH1", fontName=f["bold"], fontSize=20, leading=24, textColor=NAVY,
                             spaceBefore=22, spaceAfter=10, keepWithNext=1)
    S["h2"] = ParagraphStyle("PBH2", fontName=f["bold"], fontSize=14, leading=18, textColor=ACCENT,
                             spaceBefore=14, spaceAfter=6, keepWithNext=1)
    S["h3"] = ParagraphStyle("PBH3", fontName=f["bold"], fontSize=11, leading=14, textColor=NAVY,
                             spaceBefore=10, spaceAfter=4, keepWithNext=1)
    # rich-text body headings (not in contents)
    S["bh1"] = ParagraphStyle("PBBH1", parent=S["body"], fontName=f["bold"], fontSize=13, leading=17, spaceBefore=8, spaceAfter=4, textColor=NAVY)
    S["bh2"] = ParagraphStyle("PBBH2", parent=S["body"], fontName=f["bold"], fontSize=11.5, leading=15, spaceBefore=6, spaceAfter=3, textColor=NAVY)
    S["bh3"] = ParagraphStyle("PBBH3", parent=S["body"], fontName=f["bold"], fontSize=10, leading=13.5, spaceBefore=4, spaceAfter=2, textColor=NAVY)
    S["quote"] = ParagraphStyle("PBQuote", parent=S["body"], leftIndent=14, textColor=MUTED, borderPadding=(0, 0, 0, 0))
    S["code"] = ParagraphStyle("PBCode", parent=S["body"], fontName=f["mono"], fontSize=8.5, leading=11.5,
                               backColor=colors.HexColor("#f3f4f6"), borderPadding=5, spaceBefore=4, spaceAfter=6)
    S["cover_kicker"] = ParagraphStyle("PBKicker", fontName=f["bold"], fontSize=11, leading=14, textColor=ACCENT)
    S["cover_title"] = ParagraphStyle("PBCoverTitle", fontName=f["bold"], fontSize=30, leading=36, textColor=NAVY, spaceAfter=8)
    S["cover_sub"] = ParagraphStyle("PBCoverSub", parent=S["body"], fontSize=11, leading=16, textColor=MUTED)
    S["toc1"] = ParagraphStyle("PBToc1", fontName=f["bold"], fontSize=10.5, leading=17, textColor=NAVY)
    S["toc2"] = ParagraphStyle("PBToc2", fontName=f["sans"], fontSize=9, leading=14, leftIndent=16, textColor=colors.HexColor("#334155"))
    return S


# --------------------------------------------------------------------------
# Rich-text (Quill HTML) -> reportlab flowables
# --------------------------------------------------------------------------
class HtmlToFlowables(HTMLParser):
    INLINE = {
        "b": ("<b>", "</b>"), "strong": ("<b>", "</b>"),
        "i": ("<i>", "</i>"), "em": ("<i>", "</i>"),
        "u": ("<u>", "</u>"),
        "s": ("<strike>", "</strike>"), "strike": ("<strike>", "</strike>"), "del": ("<strike>", "</strike>"),
        "sub": ("<sub>", "</sub>"), "sup": ("<super>", "</super>"),
    }
    BLOCKS = {"p", "div", "h1", "h2", "h3", "h4", "h5", "h6", "li", "blockquote", "pre", "ul", "ol"}

    def __init__(self, styles, width):
        super().__init__(convert_charrefs=True)
        self.S = styles
        self.width = width
        self.out = []
        self.buf = []
        self.istack = []          # open inline tags: (tag, closer)
        self.cur = "p"
        self.attrs = {}
        self.lists = []           # [kind, counter]
        self.pending_bullet = None
        self.skip = 0
        self.pre = 0
        self.saw_br = False
        self.table = None
        self.mono = setup_fonts()["mono"]

    # ---- helpers
    def _close_inline(self):
        return "".join(c for _, c in reversed(self.istack))

    def _text(self):
        return "".join(self.buf)

    def _style(self):
        S = self.S
        base = {
            "p": S["body"], "li": S["body"], "quote": S["quote"], "pre": S["code"],
            "h1": S["bh1"], "h2": S["bh2"], "h3": S["bh3"],
        }.get(self.cur, S["body"])
        indent = int(self.attrs.get("indent", 0) or 0)
        align = self.attrs.get("align")
        depth = len(self.lists)
        if self.cur == "li":
            left = 16 + 16 * max(depth - 1, 0) + 14 * indent
            ps = ParagraphStyle("li", parent=base, leftIndent=left, bulletIndent=left - 12, spaceAfter=2)
        elif indent or align:
            ps = ParagraphStyle("pi", parent=base, leftIndent=base.leftIndent + 14 * indent)
        else:
            ps = ParagraphStyle("pp", parent=base, spaceAfter=base.spaceAfter or 4)
        if align == "center":
            ps.alignment = TA_CENTER
        elif align == "right":
            ps.alignment = TA_RIGHT
        elif align == "justify":
            ps.alignment = TA_JUSTIFY
        return ps

    def flush(self):
        if self.table is not None:
            return
        text = self._text() + self._close_inline()
        self.buf, self.istack = [], []
        plain = re.sub(r"<[^>]+>", "", text).replace("&nbsp;", " ").strip()
        if not plain:
            if self.saw_br and self.cur in ("p", "div"):
                self.out.append(Spacer(1, 6))
            self.saw_br = False
            self.pending_bullet = self.pending_bullet if self.cur == "li" else None
            return
        self.saw_br = False
        style = self._style()
        bullet = None
        if self.cur == "li" and self.pending_bullet is not None:
            bullet = self.pending_bullet
            self.pending_bullet = None
        try:
            self.out.append(Paragraph(text.strip() if not self.pre else text, style, bulletText=bullet))
        except Exception:
            self.out.append(Paragraph(_xml_escape(plain), style, bulletText=bullet))

    def _block_break_in_cell(self):
        if self.buf and not self._text().endswith("<br/>"):
            self.buf.append("<br/>")

    # ---- parser callbacks
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        cls = a.get("class") or ""
        if tag in ("script", "style", "head", "title"):
            self.skip += 1
            return
        if self.skip:
            return

        if tag in self.INLINE:
            o, c = self.INLINE[tag]
            self.buf.append(o)
            self.istack.append((tag, c))
        elif tag == "code" and not self.pre:
            self.buf.append(f'<font face="{self.mono}">')
            self.istack.append((tag, "</font>"))
        elif tag == "a":
            href = (a.get("href") or "").strip()
            if re.match(r"^(https?://|mailto:)", href, re.I):
                self.buf.append(f'<a href="{_xml_escape(href, {chr(34): "&quot;"})}" color="#1a5fd0">')
                self.istack.append((tag, "</a>"))
            else:
                self.istack.append((tag, ""))
        elif tag == "br":
            self.buf.append("<br/>")
            self.saw_br = True
        elif tag == "img":
            self._image(a)
        elif tag == "hr":
            self.flush()
            if self.table is None:
                self.out.append(HRFlowable(width="100%", thickness=0.6, color=GRID, spaceBefore=4, spaceAfter=6))
        elif tag == "table":
            self.flush()
            self.table = {"rows": [], "row": None, "head": False}
        elif tag == "tr" and self.table is not None:
            self.table["row"] = []
        elif tag in ("td", "th") and self.table is not None:
            self.buf, self.istack = [], []
            if tag == "th":
                self.table["head"] = True
            self._cell_is_th = tag == "th"
        elif tag in ("ul", "ol"):
            if self.table is not None:
                self._block_break_in_cell()
            else:
                self.flush()
            self.lists.append([tag, 0])
        elif tag in self.BLOCKS:
            if self.table is not None:
                self._block_break_in_cell()
                return
            self.flush()
            self.attrs = {}
            m = re.search(r"ql-indent-(\d+)", cls)
            if m:
                self.attrs["indent"] = int(m.group(1))
            m = re.search(r"ql-align-(center|right|justify)", cls)
            if m:
                self.attrs["align"] = m.group(1)
            if tag == "li":
                self.cur = "li"
                kind, n = self.lists[-1] if self.lists else ("ul", 0)
                if self.lists:
                    self.lists[-1][1] += 1
                    n = self.lists[-1][1]
                self.pending_bullet = "\u2022" if kind == "ul" else f"{n}."
                if not setup_fonts()["unicode"]:
                    self.pending_bullet = "\u2022" if kind == "ul" else f"{n}."
            elif tag == "blockquote":
                self.cur = "quote"
            elif tag == "pre":
                self.cur = "pre"
                self.pre += 1
            elif tag in ("h1", "h2", "h3"):
                self.cur = tag
            elif tag in ("h4", "h5", "h6"):
                self.cur = "h3"
            else:
                self.cur = "p"

    def handle_endtag(self, tag):
        if tag in ("script", "style", "head", "title"):
            self.skip = max(0, self.skip - 1)
            return
        if self.skip:
            return
        if tag in ("td", "th") and self.table is not None:
            text = self._text() + self._close_inline()
            self.buf, self.istack = [], []
            style = self.S["head"] if getattr(self, "_cell_is_th", False) else self.S["cell"]
            try:
                para = Paragraph(text.strip() or "&nbsp;", style)
            except Exception:
                para = Paragraph(_xml_escape(re.sub(r"<[^>]+>", "", text)), style)
            if self.table["row"] is not None:
                self.table["row"].append(para)
        elif tag == "tr" and self.table is not None:
            if self.table["row"]:
                self.table["rows"].append(self.table["row"])
            self.table["row"] = None
        elif tag == "table" and self.table is not None:
            self._finish_table()
        elif tag in self.INLINE or tag in ("code", "a"):
            for idx in range(len(self.istack) - 1, -1, -1):
                if self.istack[idx][0] == tag:
                    closers = [c for _, c in reversed(self.istack[idx:])]
                    self.buf.append("".join(closers))
                    del self.istack[idx:]
                    break
        elif tag in ("ul", "ol"):
            if self.table is None:
                self.flush()
            if self.lists:
                self.lists.pop()
            if not self.lists:
                self.cur = "p"
        elif tag in self.BLOCKS:
            if self.table is not None:
                self._block_break_in_cell()
                return
            self.flush()
            if tag == "pre":
                self.pre = max(0, self.pre - 1)
            self.cur = "li" if self.lists else "p"
            self.attrs = {}

    def handle_data(self, data):
        if self.skip:
            return
        if self.pre:
            txt = T(data).replace("\n", "<br/>").replace("  ", "&nbsp;&nbsp;")
            self.buf.append(txt)
            return
        txt = re.sub(r"\s+", " ", T(data))
        if not self.buf or self._text().endswith("<br/>"):
            txt = txt.lstrip()
        if txt:
            self.buf.append(txt)

    # ---- tables / images
    def _finish_table(self):
        rows = self.table["rows"]
        head = self.table["head"]
        self.table = None
        if not rows:
            return
        ncols = max(len(r) for r in rows)
        rows = [r + [Paragraph("", self.S["cell"])] * (ncols - len(r)) for r in rows]
        t = Table(rows, colWidths=[self.width / ncols] * ncols, repeatRows=1 if head else 0)
        style = [
            ("GRID", (0, 0), (-1, -1), 0.5, GRID),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
        if head:
            style.append(("BACKGROUND", (0, 0), (-1, 0), ACCENT))
        t.setStyle(TableStyle(style))
        self.out.append(Spacer(1, 3))
        self.out.append(t)
        self.out.append(Spacer(1, 6))

    def _image(self, a):
        src = a.get("src") or ""
        alt = a.get("alt") or "image"
        m = re.match(r"^data:image/[a-zA-Z0-9.+-]+;base64,(.+)$", src, re.S)
        if m and self.table is None:
            try:
                from PIL import Image as PILImage
                raw = base64.b64decode(m.group(1))
                im = PILImage.open(io.BytesIO(raw))
                im.load()
                if im.width > 1600:
                    im = im.resize((1600, int(im.height * 1600 / im.width)))
                if im.mode not in ("RGB", "RGBA", "L"):
                    im = im.convert("RGBA")
                bio = io.BytesIO()
                im.save(bio, "PNG")
                bio.seek(0)
                w, h = im.size
                scale = min(self.width / w, 380 / h, 1.0)
                self.flush()
                self.out.append(Spacer(1, 3))
                self.out.append(RLImage(bio, width=w * scale, height=h * scale))
                self.out.append(Spacer(1, 6))
                return
            except Exception:
                pass
        self.buf.append(f"<i>[{T(alt)}]</i>")

    def result(self):
        self.flush()
        if self.table is not None:
            self._finish_table()
        return self.out


def html_to_flowables(html, styles, width):
    try:
        p = HtmlToFlowables(styles, width)
        p.feed(html or "")
        p.close()
        return p.result()
    except Exception:
        plain = re.sub(r"<[^>]+>", " ", html or "")
        return [Paragraph(TL(plain), styles["body"])]


# --------------------------------------------------------------------------
# Document template
# --------------------------------------------------------------------------
def make_canvas_class(org_name, confidential_text):
    f = setup_fonts()

    class NumberedCanvas(rl_canvas.Canvas):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self._saved = []

        def showPage(self):
            self._saved.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total = len(self._saved)
            for state in self._saved:
                self.__dict__.update(state)
                if self._pageNumber > 1:
                    self._decorate(total)
                super().showPage()
            super().save()

        def _decorate(self, total):
            self.saveState()
            self.setStrokeColor(GRID)
            self.setLineWidth(0.5)
            self.line(MARGIN, PAGE_H - 30, PAGE_W - MARGIN, PAGE_H - 30)
            self.line(MARGIN, 36, PAGE_W - MARGIN, 36)
            self.setFont(f["sans"], 7.5)
            self.setFillColor(MUTED)
            self.drawString(MARGIN, PAGE_H - 25, clean(org_name)[:80])
            self.drawRightString(PAGE_W - MARGIN, PAGE_H - 25, "IT Playbook")
            self.drawString(MARGIN, 24, clean(confidential_text))
            self.drawRightString(PAGE_W - MARGIN, 24, f"Page {self._pageNumber} of {total}")
            self.restoreState()

    return NumberedCanvas


class PlaybookDoc(BaseDocTemplate):
    def __init__(self, buf, logo_path=None, **kw):
        super().__init__(buf, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN,
                         topMargin=48, bottomMargin=50, **kw)
        self.logo_path = logo_path
        self._seq = 0
        cover_frame = Frame(MARGIN, 70, FRAME_W, PAGE_H - 215 - 70, id="cover", leftPadding=0, rightPadding=0)
        main_frame = Frame(MARGIN, 50, FRAME_W, PAGE_H - 48 - 50, id="main", leftPadding=0, rightPadding=0)
        self.addPageTemplates([
            PageTemplate(id="cover", frames=[cover_frame], onPage=self._draw_cover),
            PageTemplate(id="main", frames=[main_frame]),
        ])

    def _draw_cover(self, canv, doc):
        canv.saveState()
        canv.setFillColor(NAVY)
        canv.rect(0, PAGE_H - 175, PAGE_W, 175, stroke=0, fill=1)
        canv.setFillColor(ACCENT)
        canv.rect(0, PAGE_H - 181, PAGE_W, 6, stroke=0, fill=1)
        if self.logo_path and Path(self.logo_path).exists():
            try:
                lw = 300
                lh = lw * 220 / 800
                canv.drawImage(ImageReader(self.logo_path), MARGIN - 20, PAGE_H - 175 + (175 - lh) / 2,
                               width=lw, height=lh, mask="auto")
            except Exception:
                pass
        canv.restoreState()

    def beforeDocument(self):
        # multiBuild runs several passes; bookmark keys must be identical each
        # pass or the contents page never settles.
        self._seq = 0

    def afterFlowable(self, flowable):
        if isinstance(flowable, Paragraph):
            name = flowable.style.name
            if name in ("PBH1", "PBH2"):
                level = 0 if name == "PBH1" else 1
                text = flowable.getPlainText()
                key = f"pb{self._seq}"
                self._seq += 1
                self.canv.bookmarkPage(key)
                self.canv.addOutlineEntry(text, key, level, 0)
                self.notify("TOCEntry", (level, _xml_escape(text), self.page, key))


# --------------------------------------------------------------------------
# Section builders
# --------------------------------------------------------------------------
def _tbl(header, rows, widths, S, zebra=True):
    data = [[Paragraph(T(h), S["head"]) for h in header]] + rows
    t = Table(data, colWidths=widths, repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
        ("GRID", (0, 0), (-1, -1), 0.5, GRID),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    if zebra:
        style.append(("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]))
    t.setStyle(TableStyle(style))
    return t


def _kv_block(pairs, S, label_w=95):
    rows = []
    for label, value_para in pairs:
        rows.append([Paragraph(T(label), S["label"]), value_para])
    t = Table(rows, colWidths=[label_w, FRAME_W - label_w])
    t.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.6, GRID),
        ("LINEBELOW", (0, 0), (-1, -2), 0.3, GRID),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (0, -1), LIGHT),
        ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def _fmt_date(d):
    if isinstance(d, (datetime, date)):
        return d.strftime("%d %b %Y")
    return str(d) if d else "-"


def _dash(v):
    return v if (v not in (None, "")) else "-"


def _related_pair(item, S):
    rel = item.get("related") or []
    return [("Related", Paragraph(T("; ".join(rel)), S["cell"]))] if rel else []


def _notes_para(notes, S):
    return Paragraph(TL(notes), S["cell"])


def sec_overview(data, S, num):
    out = [Paragraph(f"{num}. Overview", S["h1"])]
    org = data["org"]
    if org.get("description"):
        out.append(Paragraph(TL(org["description"]), S["body"]))
        out.append(Spacer(1, 8))

    counts = data.get("counts", {})
    if counts:
        tiles = [Paragraph(f'<font size="16" color="#1a5fd0"><b>{n}</b></font><br/>'
                           f'<font size="8" color="#5b6678">{T(label)}</font>', ParagraphStyle(
                               "PBTile", parent=S["cell"], leading=17, alignment=TA_LEFT))
                 for label, n in counts.items()]
        per_row = 4
        rows = []
        for i in range(0, len(tiles), per_row):
            row = tiles[i:i + per_row]
            row += [""] * (per_row - len(row))
            rows.append(row)
        t = Table(rows, colWidths=[FRAME_W / per_row] * per_row)
        t.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 0.6, GRID), ("INNERGRID", (0, 0), (-1, -1), 0.4, GRID),
            ("BACKGROUND", (0, 0), (-1, -1), LIGHT), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        out += [t, Spacer(1, 10)]

    ob = data.get("onboarding")
    if ob:
        out.append(Paragraph("Onboarding checklist", S["h2"]))
        out.append(Paragraph(f"<b>Progress:</b> {ob['done']} of {ob['total']} complete ({ob['percent']}%)", S["body"]))
        out.append(Spacer(1, 4))
        rows = []
        for label, done, by, on in ob["items"]:
            rows.append([
                Paragraph(T(label), S["cell"]),
                Paragraph("<font color='#1a7f37'><b>Complete</b></font>" if done else "<font color='#9a6700'>Pending</font>", S["cell"]),
                Paragraph(T(_dash(by)), S["cell"]),
                Paragraph(T(_fmt_date(on)), S["cell"]),
            ])
        out.append(_tbl(["Item", "Status", "Actioned by", "Date"], rows, [230, 75, 130, 80], S))
        if ob.get("notes"):
            out += [Spacer(1, 6), Paragraph("<b>Notes</b>", S["body"]), Paragraph(TL(ob["notes"]), S["body"])]
    return out


def sec_contacts(data, S, num):
    out = [Paragraph(f"{num}. Contacts", S["h1"])]
    rows = []
    for c in data["contacts"]:
        name = T(f"{c['first']} {c['last']}".strip())
        if c.get("decision"):
            name += " <font color='#1a5fd0'>[decision maker]</font>"
        cell = [Paragraph(f"<b>{name}</b>", S["cell"])]
        if c.get("notes"):
            cell.append(Paragraph(TL(c["notes"]), S["small"]))
        rows.append([cell, Paragraph(T(_dash(c.get("position"))), S["cell"]),
                     Paragraph(T(_dash(c.get("email"))), S["cell"]),
                     Paragraph(T(_dash(c.get("mobile"))), S["cell"]),
                     Paragraph(T(_dash(c.get("office"))), S["cell"])])
    if not rows:
        return out + [Paragraph("No contacts recorded.", S["body"])]
    out.append(_tbl(["Name", "Position", "Email", "Mobile", "Office"], rows, [135, 85, 130, 80, 85], S))
    return out


def sec_sites(data, S, num):
    out = [Paragraph(f"{num}. Sites", S["h1"])]
    if not data["sites"]:
        return out + [Paragraph("No sites recorded.", S["body"])]
    for s in data["sites"]:
        pairs = [("Address", Paragraph(TL(s["address"]), S["cell"]))]
        if s.get("notes"):
            pairs.append(("Notes", _notes_para(s["notes"], S)))
        pairs += _related_pair(s, S)
        out.append(Paragraph(T(s["name"]), S["h3"]))
        out.append(_kv_block(pairs, S))
    return out


def sec_network(data, S, num):
    out = [Paragraph(f"{num}. Network", S["h1"])]
    if not data["network"]:
        return out + [Paragraph("No network devices recorded.", S["body"])]
    rows = [[Paragraph(f"<b>{T(n['name'])}</b>", S["cell"]),
             Paragraph(T(_dash(n.get("ip"))), S["mono"]),
             Paragraph(T(_dash(n.get("mac"))), S["mono"]),
             Paragraph(TL(n.get("notes") or "-"), S["cell"])] for n in data["network"]]
    out.append(_tbl(["Device", "IP address", "MAC address", "Notes"], rows, [120, 100, 110, 185], S))
    return out


def sec_domains(data, S, num):
    out = [Paragraph(f"{num}. Domains", S["h1"])]
    if not data["domains"]:
        return out + [Paragraph("No domains recorded.", S["body"])]
    for d in data["domains"]:
        pairs = [
            ("Registrar", Paragraph(T(_dash(d.get("registrar"))), S["cell"])),
            ("DNS provider", Paragraph(T(_dash(d.get("dns_provider"))), S["cell"])),
            ("Nameservers", Paragraph(TL(d.get("nameservers") or "-"), S["mono"])),
            ("Expires", Paragraph(T(_fmt_date(d.get("expires"))), S["cell"])),
        ]
        if d.get("notes"):
            pairs.append(("Notes", _notes_para(d["notes"], S)))
        pairs += _related_pair(d, S)
        out.append(Paragraph(T(d["name"]), S["h3"]))
        out.append(_kv_block(pairs, S))
    return out


def sec_assets(data, S, num):
    out = [Paragraph(f"{num}. Assets", S["h1"])]
    if not data["assets"]:
        return out + [Paragraph("No assets recorded.", S["body"])]
    rows = []
    for a in data["assets"]:
        sub = " / ".join(x for x in [a.get("type"), a.get("brand")] if x)
        first = [Paragraph(f"<b>{T(a['name'])}</b>", S["cell"])]
        if sub:
            first.append(Paragraph(T(sub), S["small"]))
        if a.get("notes"):
            first.append(Paragraph(TL(a["notes"]), S["small"]))
        if a.get("warranty"):
            first.append(Paragraph("Warranty to " + T(_fmt_date(a["warranty"])), S["small"]))
        if a.get("related"):
            first.append(Paragraph("Related: " + T("; ".join(a["related"])), S["small"]))
        ids = [Paragraph(T(_dash(a.get("serial"))), S["mono"])]
        if a.get("asset_id"):
            ids.append(Paragraph("ID: " + T(a["asset_id"]), S["small"]))
        where = [Paragraph(T(_dash(a.get("issued_to"))), S["cell"])]
        loc = " / ".join(x for x in [a.get("location"), a.get("site")] if x)
        if loc:
            where.append(Paragraph(T(loc), S["small"]))
        if a.get("contact"):
            where.append(Paragraph("Contact: " + T(a["contact"]), S["small"]))
        rows.append([first, ids, Paragraph(T(_fmt_date(a.get("purchased"))), S["cell"]), where,
                     Paragraph(T(_dash(a.get("status"))), S["cell"])])
    out.append(_tbl(["Device", "Serial / ID", "Purchased", "Issued to / location", "Status"], rows,
                    [160, 105, 65, 130, 55], S))
    return out


def sec_records(data, S, num, options):
    out = [Paragraph(f"{num}. Custom Records", S["h1"])]
    groups = data.get("records") or []
    if not groups:
        return out + [Paragraph("No custom records.", S["body"])]
    for g in groups:
        out.append(Paragraph(T(g["name"]), S["h2"]))
        for r in g["records"]:
            pairs = []
            for f in r["fields"]:
                if f["value"] in (None, ""):
                    continue
                style = S["mono"] if f["type"] == "password" else S["cell"]
                val = f["value"]
                if f["type"] == "password" and val != "(omitted)" and not can_render(val):
                    pairs.append((f["label"], Paragraph(
                        "<font color='#b42318'><b>Contains characters this PDF cannot display. "
                        "Retrieve it from the vault.</b></font>", S["cell"])))
                    continue
                pairs.append((f["label"], Paragraph(TL(val) if f["type"] == "textarea" else T(val), style)))
            pairs += _related_pair(r, S)
            pairs.append(("Last updated", Paragraph(T(_fmt_date(r.get("updated"))), S["small"])))
            out.append(Paragraph(T(r["name"]), S["h3"]))
            out.append(_kv_block(pairs, S))
    return out


def sec_docs(data, S, num, options, attach_names):
    out = [Paragraph(f"{num}. Documentation", S["h1"])]
    pages = data["doc_pages"]
    files = data["files"]
    if not pages and not files:
        return out + [Paragraph("No documentation recorded.", S["body"])]

    if pages:
        last_path = object()
        for p in pages:
            title = T(p["title"])
            path = p.get("path") or ""
            head = Paragraph(title, S["h2"])
            sub = Paragraph(
                (T(path) + " &nbsp;|&nbsp; " if path else "") + "Updated " + T(_fmt_date(p.get("updated"))),
                S["small"])
            body = html_to_flowables(p.get("html"), S, FRAME_W)
            out += [head, sub, Spacer(1, 4)]
            out += body or [Paragraph("(empty page)", S["small"])]

    if files:
        out.append(Paragraph("Uploaded files", S["h2"]))
        rows = []
        for f in files:
            if f["name"] in attach_names:
                status = attach_names[f["name"]] if False else f.get("status", "")
            status = f.get("status", "Listed only")
            rows.append([
                Paragraph(T(f["name"]), S["cell"]),
                Paragraph(T(_dash(f.get("path"))), S["cell"]),
                Paragraph(T(_size(f.get("size"))), S["cell"]),
                Paragraph(T(_fmt_date(f.get("uploaded"))), S["cell"]),
                Paragraph(T(status), S["cell"]),
            ])
        out.append(_tbl(["File", "Folder", "Size", "Uploaded", "In this PDF"], rows, [155, 105, 50, 70, 135], S))
    return out


def _size(n):
    if not n:
        return "-"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def sec_passwords(data, S, num, options):
    out = [Paragraph(f"{num}. Passwords &amp; Credentials", S["h1"])]
    show = options.get("include_passwords")
    warn_text = (
        "<b>Handle with care.</b> This section contains live credentials. Store the file securely, "
        "do not email it unencrypted, and delete copies you no longer need."
        if show else
        "Passwords and 2FA secrets have been <b>omitted</b> from this export. "
        "Usernames and URLs are listed for reference."
    )
    box = Table([[Paragraph(warn_text, S["body"])]], colWidths=[FRAME_W])
    box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), WARN_BG), ("BOX", (0, 0), (-1, -1), 0.8, WARN_BORDER),
        ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    out += [box, Spacer(1, 6)]
    if not data["passwords"]:
        return out + [Paragraph("No passwords recorded.", S["body"])]

    unsupported = []
    for p in data["passwords"]:
        pairs = []
        if p.get("url"):
            pairs.append(("URL", Paragraph(T(p["url"]), S["cell"])))
        pairs.append(("Username", Paragraph(T(_dash(p.get("username"))), S["mono"])))
        if show:
            pw = p.get("password") or ""
            pairs.append(("Password", Paragraph(T(pw) if pw else "-", S["mono"])))
            if p.get("otp_secret"):
                pairs.append(("2FA secret", Paragraph(T(p["otp_secret"]), S["mono"])))
            bad = [lbl for lbl, v in (("username", p.get("username")), ("password", pw),
                                      ("2FA secret", p.get("otp_secret"))) if v and not can_render(v)]
            if bad:
                unsupported.append(p["name"])
                pairs.append(("WARNING", Paragraph(
                    "<font color='#b42318'><b>The " + ", ".join(bad) + " contains characters that "
                    "this PDF cannot display (they appear as boxes or ?). Retrieve the real value from the vault.</b></font>", S["cell"])))
        else:
            pairs.append(("Password", Paragraph("<font color='#8a94a6'>(omitted)</font>", S["cell"])))
        if p.get("notes"):
            pairs.append(("Notes", _notes_para(p["notes"], S)))
        pairs += _related_pair(p, S)
        pairs.append(("Last updated", Paragraph(T(_fmt_date(p.get("updated"))), S["small"])))
        out.append(Paragraph(T(p["name"]), S["h3"]))
        out.append(_kv_block(pairs, S))
    return out


# --------------------------------------------------------------------------
# Attachments (appended after the main document)
# --------------------------------------------------------------------------
def _one_page_pdf(title, subtitle, image_bytes=None, S=None):
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN, topMargin=MARGIN, bottomMargin=MARGIN)
    story = [Paragraph(T(title), S["h2"]), Paragraph(T(subtitle), S["small"]), Spacer(1, 10)]
    if image_bytes is not None:
        from PIL import Image as PILImage
        im = PILImage.open(io.BytesIO(image_bytes))
        im.load()
        try:
            from PIL import ImageOps
            im = ImageOps.exif_transpose(im)
        except Exception:
            pass
        if im.mode not in ("RGB", "L"):
            bg = PILImage.new("RGB", im.size, "white")
            alpha = im.convert("RGBA")
            bg.paste(alpha, mask=alpha.split()[3])
            im = bg
        if im.width > 2200:
            im = im.resize((2200, int(im.height * 2200 / im.width)))
        bio = io.BytesIO()
        im.save(bio, "JPEG", quality=88)
        bio.seek(0)
        maxw, maxh = FRAME_W, PAGE_H - 2 * MARGIN - 70
        scale = min(maxw / im.width, maxh / im.height)
        story.append(RLImage(bio, width=im.width * scale, height=im.height * scale))
    else:
        story.append(Paragraph("The original file follows on the next page(s).", S["body"]))
    doc.build(story)
    buf.seek(0)
    return buf


def _assemble(main_bytes, files, options, S, warnings, meta):
    """Merge attachments + apply encryption using pypdf."""
    from pypdf import PdfReader, PdfWriter

    writer = PdfWriter()
    writer.append(PdfReader(io.BytesIO(main_bytes)))
    root = None
    budget = int(options.get("max_attach_bytes", 100 * 1024 * 1024))
    used = 0

    for f in files:
        if f.get("status") != "Attached":
            continue
        path = Path(f["disk_path"])
        ext = path.suffix.lower()
        label = f["name"] if not f.get("path") else f"{f['path']} / {f['name']}"
        try:
            size = path.stat().st_size
            if used + size > budget:
                f["status"] = "Skipped (size limit)"
                warnings.append(f"{f['name']}: skipped, attachments exceed the size limit.")
                continue
            start = len(writer.pages)
            if ext == ".pdf":
                reader = PdfReader(str(path))
                if reader.is_encrypted and reader.decrypt("") == 0:
                    f["status"] = "Skipped (password-protected)"
                    warnings.append(f"{f['name']}: skipped, the PDF is password-protected.")
                    continue
                writer.append(_one_page_pdf(f"Attachment: {f['name']}", f.get("path") or "Documentation", None, S))
                writer.append(reader)
            else:
                writer.append(_one_page_pdf(f"Attachment: {f['name']}", f.get("path") or "Documentation",
                                            path.read_bytes(), S))
            used += size
            if root is None:
                root = writer.add_outline_item("Attachments", start)
            writer.add_outline_item(label, start, parent=root)
        except Exception as e:
            f["status"] = "Skipped (could not be read)"
            warnings.append(f"{f['name']}: skipped ({type(e).__name__}).")

    writer.add_metadata(meta)
    pw = options.get("pdf_password")
    if pw:
        writer.encrypt(user_password=pw, owner_password=secrets.token_urlsafe(24), algorithm="AES-256")
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------
def pypdf_available():
    try:
        import pypdf  # noqa: F401
        return True
    except Exception:
        return False


def build_playbook(data, options):
    """
    data: see app.py:collect_playbook_data()
    options: sections (set), include_passwords (bool), attach_files (bool),
             pdf_password (str|None), logo_path (str|None)
    returns (pdf_bytes, warnings)
    """
    S = make_styles()
    warnings = []
    sections = set(options.get("sections") or [])
    show_pw = bool(options.get("include_passwords"))
    org = data["org"]

    # decide which uploaded files can be embedded
    attach = bool(options.get("attach_files")) and "docs" in sections
    for f in data.get("files", []):
        ext = Path(f["name"]).suffix.lower()
        if attach and f.get("disk_path") and (ext == ".pdf" or ext in EMBEDDABLE_IMAGE_EXTS):
            f["status"] = "Attached"
        elif attach:
            f["status"] = "Not embeddable (listed only)"
        else:
            f["status"] = "Listed only"

    confidential = ("CONFIDENTIAL - contains credentials" if show_pw else "CONFIDENTIAL") + " - " + clean(org["name"])
    gen_at = data.get("generated_at") or datetime.utcnow()
    gen_by = data.get("generated_by") or ""

    # ---- cover
    story = []
    story.append(Paragraph("IT PLAYBOOK", S["cover_kicker"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph(T(org["name"]), S["cover_title"]))
    if org.get("description"):
        story.append(Paragraph(TL(org["description"][:600]), S["cover_sub"]))
    story.append(Spacer(1, 26))
    meta_rows = [
        [Paragraph("Generated", S["label"]), Paragraph(T(gen_at.strftime("%d %B %Y, %H:%M UTC")), S["cell"])],
    ]
    if gen_by:
        meta_rows.append([Paragraph("Generated by", S["label"]), Paragraph(T(gen_by), S["cell"])])
    incl = [label for key, label in SECTION_ORDER if key in sections]
    meta_rows.append([Paragraph("Includes", S["label"]), Paragraph(T(", ".join(incl)), S["cell"])])
    mt = Table(meta_rows, colWidths=[90, 300])
    mt.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 3),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 3), ("LINEBELOW", (0, 0), (-1, -1), 0.3, GRID)]))
    story.append(mt)
    story.append(Spacer(1, 30))
    notice = ("This document contains confidential information, including account credentials, and is intended only "
              "for authorised personnel. Store it securely and do not share it without permission."
              if show_pw else
              "This document contains confidential information and is intended only for authorised personnel.")
    nt = Table([[Paragraph(notice, S["small"])]], colWidths=[FRAME_W])
    nt.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), LIGHT), ("BOX", (0, 0), (-1, -1), 0.5, GRID),
                            ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                            ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    story.append(nt)
    story += [NextPageTemplate("main"), PageBreak()]

    # ---- contents
    story.append(Paragraph("Contents", ParagraphStyle("PBContentsTitle", parent=S["body"], fontName=setup_fonts()["bold"],
                                                       fontSize=20, leading=24, textColor=NAVY, spaceAfter=10)))
    toc = TableOfContents()
    toc.levelStyles = [S["toc1"], S["toc2"]]
    toc.dotsMinLevel = 0
    story.append(toc)
    story.append(PageBreak())

    # ---- sections
    builders = {
        "overview": lambda n: sec_overview(data, S, n),
        "contacts": lambda n: sec_contacts(data, S, n),
        "sites": lambda n: sec_sites(data, S, n),
        "network": lambda n: sec_network(data, S, n),
        "domains": lambda n: sec_domains(data, S, n),
        "assets": lambda n: sec_assets(data, S, n),
        "records": lambda n: sec_records(data, S, n, options),
        "docs": lambda n: sec_docs(data, S, n, options, {}),
        "passwords": lambda n: sec_passwords(data, S, n, options),
    }
    n = 0
    first = True
    for key, _label in SECTION_ORDER:
        if key not in sections:
            continue
        n += 1
        if not first:
            # long sections start a fresh page; short ones flow on
            story.append(PageBreak() if key in ("docs", "passwords") else CondPageBreak(190))
        first = False
        story += builders[key](n)

    if n == 0:
        story.append(Paragraph("No sections were selected.", S["body"]))

    # ---- build (two passes for contents + page counts)
    buf = io.BytesIO()
    title = f"IT Playbook - {clean(org['name'])}"
    doc = PlaybookDoc(buf, logo_path=options.get("logo_path"), title=title, author=gen_by or "CoreSight Vault",
                      subject="Client documentation export")
    doc.multiBuild(story, canvasmaker=make_canvas_class(org["name"], confidential))
    main_bytes = buf.getvalue()

    need_pypdf = bool(options.get("pdf_password")) or any(f.get("status") == "Attached" for f in data.get("files", []))
    if not need_pypdf:
        return main_bytes, warnings

    meta = {"/Title": title, "/Author": gen_by or "CoreSight Vault", "/Subject": "Client documentation export"}
    final = _assemble(main_bytes, data.get("files", []), options, S, warnings, meta)
    return final, warnings
