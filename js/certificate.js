// ══════════════════════════════════════════════════════════
//  PREGAME ACADEMY — Certificate: verify link, QR code, PDF, sharing
//  The PDF is drawn natively with jsPDF (selectable text, vector QR), laid out to match the on-screen sheet.
// ══════════════════════════════════════════════════════════

const Certificate = {
  _data: null, // what the sheet currently shows (see Learner._certData)

  // ─── Pure helpers (unit-tested) ───
  // The public page a certificate's QR code opens. `base` is the app's origin and path, with no query or hash.
  verifyUrl(certId, base = location.origin + location.pathname) {
    return `${base}#/verify/${encodeURIComponent(certId)}`;
  },

  // Certificate id from a `#/verify/<id>` location hash, or null.
  idFromHash(hash) {
    const m = /^#\/verify\/([A-Za-z0-9-]{3,40})$/.exec(hash || '');
    return m ? m[1] : null;
  },

  // Standard PDF fonts only cover Latin-1: fold typographic punctuation, strip what can't be drawn.
  pdfText(s) {
    return String(s ?? '')
      .replace(/[‘’‚]/g, "'").replace(/[“”„]/g, '"').replace(/[–—]/g, '-').replace(/…/g, '...')
      .normalize('NFC')
      .replace(/[^ -~ -ÿ]/g, '?');
  },

  // True when the standard PDF fonts can't draw this text (so it is rendered as an image instead).
  needsImage(s) { return /[^\u0020-\u007e\u00a0-\u00ff‘’‚“”„–—…]/.test(String(s ?? '')); },

  fileName(data) {
    const slug = s => String(s).replace(/[^a-z0-9]+/gi, '_').replace(/^_|_$/g, '');
    return `Certificate_${slug(data.course) || 'Course'}_${slug(data.name) || 'Learner'}.pdf`;
  },

  linkedInUrl(data) {
    const at = new Date(data.at);
    const p = new URLSearchParams({
      startTask: 'CERTIFICATION_NAME', name: data.course, organizationName: data.org,
      issueYear: String(at.getFullYear()), issueMonth: String(at.getMonth() + 1),
      certUrl: data.verifyUrl, certId: data.certId
    });
    return `https://www.linkedin.com/profile/add?${p}`;
  },

  // '#rrggbb' to [r, g, b]; falls back for anything malformed.
  toRgb(hex, fallback = [21, 101, 255]) {
    const m = /^#?([0-9a-f]{6})$/i.exec(String(hex || ''));
    if (!m) return fallback;
    const n = parseInt(m[1], 16);
    return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
  },

  // QR as a boolean matrix (needs the qrcode-generator library).
  qrMatrix(text) {
    const qr = qrcode(0, 'M');
    qr.addData(text);
    qr.make();
    const n = qr.getModuleCount();
    return Array.from({ length: n }, (_, r) => Array.from({ length: n }, (_, c) => qr.isDark(r, c)));
  },

  // One path of unit squares in a viewBox with a 2-module quiet zone; colour comes from `currentColor`.
  qrSvg(matrix) {
    const q = 2, size = matrix.length + q * 2;
    let d = '';
    matrix.forEach((row, r) => row.forEach((dark, c) => { if (dark) d += `M${c + q} ${r + q}h1v1h-1z`; }));
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges" aria-hidden="true"><path fill="currentColor" d="${d}"/></svg>`;
  },

  // ─── Sheet ───
  // Fill the on-screen sheet and remember what it shows for download / share.
  render(data) {
    const d = { ...data, verifyUrl: Certificate.verifyUrl(data.certId) };
    Certificate._data = d;
    $$('c-org').textContent    = d.org;
    $$('c-name').textContent   = d.name;
    $$('c-course').textContent = d.course;
    $$('c-date').textContent   = d.date;
    $$('c-score').textContent  = d.score + '%';
    $$('c-id').textContent     = d.certId;
    $$('c-sig-name').textContent  = d.signName;
    $$('c-sig-title').textContent = d.signTitle || `${d.org} Training Department`;
    const logo = $$('c-logo');
    if (d.logo) { logo.src = d.logo; $$('c-logo-wrap').classList.remove('hidden'); }
    else { logo.removeAttribute('src'); $$('c-logo-wrap').classList.add('hidden'); }
    try { $$('c-qr').innerHTML = Certificate.qrSvg(Certificate.qrMatrix(d.verifyUrl)); }
    catch (e) { console.error('QR error:', e); $$('c-qr').textContent = ''; }
    $$('cert-native-share').classList.toggle('hidden', !navigator.share);
    return d;
  },

  // ─── Sharing ───
  async copyLink() {
    const d = Certificate._data; if (!d) return;
    try { await navigator.clipboard.writeText(d.verifyUrl); Toast.ok('Verify link copied.'); }
    catch { Toast.err('Could not copy. Long-press the QR code or copy the link from the address bar after opening it.'); }
  },

  async share() {
    const d = Certificate._data; if (!d || !navigator.share) return;
    try { await navigator.share({ title: `${d.course} — ${d.org}`, text: `I completed ${d.course}.`, url: d.verifyUrl }); }
    catch (e) { if (e.name !== 'AbortError') Toast.err('Sharing failed. Use Copy verify link instead.'); }
  },

  addToLinkedIn() {
    const d = Certificate._data; if (!d) return;
    window.open(Certificate.linkedInUrl(d), '_blank', 'noopener');
  },

  // ─── PDF ───
  // Redraw a logo through a canvas so any format (including SVG) becomes a PNG jsPDF can embed.
  _loadLogo(src) {
    return new Promise(resolve => {
      if (!src) return resolve(null);
      const img = new Image();
      img.crossOrigin = 'anonymous';
      img.onload = () => {
        try {
          const w = img.naturalWidth || 300, h = img.naturalHeight || 100;
          const k = Math.min(1, 600 / Math.max(w, h));
          const cv = document.createElement('canvas');
          cv.width = Math.round(w * k); cv.height = Math.round(h * k);
          cv.getContext('2d').drawImage(img, 0, 0, cv.width, cv.height);
          resolve({ url: cv.toDataURL('image/png'), w: cv.width, h: cv.height });
        } catch { resolve(null); }
      };
      img.onerror = () => resolve(null);
      img.src = src;
    });
  },

  // Text the PDF fonts can't draw (CJK, Vietnamese, Polish...) rendered with the system font into a PNG.
  _textImage(text, { size, font, weight, italic, color, maxW }) {
    const px = 8, cv = document.createElement('canvas'), ctx = cv.getContext('2d');
    const face = `${italic ? 'italic ' : ''}${weight} ${size * px}px ${font}`;
    ctx.font = face;
    const w = Math.ceil(ctx.measureText(text).width) + 8, h = Math.ceil(size * px * 1.4);
    cv.width = w; cv.height = h;
    ctx.font = face; ctx.fillStyle = '#' + color.map(v => v.toString(16).padStart(2, '0')).join(''); ctx.textBaseline = 'middle';
    ctx.fillText(text, 4, h / 2);
    const PT = 0.3528; // mm per point: sizes are in pt, drawn at `px` canvas pixels per pt
    let mmW = w / px * PT, mmH = h / px * PT;
    if (mmW > maxW) { mmH *= maxW / mmW; mmW = maxW; }
    return { url: cv.toDataURL('image/png'), w: mmW, h: mmH };
  },

  // Greedy wrap by measured width (works for scripts without spaces); at most two lines.
  _wrapImageLines(text, maxMm, size, font) {
    const ctx = document.createElement('canvas').getContext('2d');
    ctx.font = `700 ${size * 8}px ${font}`;
    const fits = t => ctx.measureText(t).width / 8 * 0.3528 <= maxMm;
    const words = text.split(/(\s+)/), lines = [''];
    words.forEach(w => {
      const cur = lines[lines.length - 1];
      if (fits(cur + w) || !cur) { lines[lines.length - 1] = cur + w; return; }
      if (lines.length < 2) lines.push(w.trimStart());
      else lines[1] += w;
    });
    return lines.map(l => l.trim()).filter(Boolean);
  },

  async buildPdf(d) {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF({ orientation: 'landscape', unit: 'mm', format: 'a4' });
    const T = Certificate.pdfText;
    const c1 = Certificate.toRgb(brandCache.c1), c2 = Certificate.toRgb(brandCache.c2, [27, 26, 92]), c3 = Certificate.toRgb(brandCache.c3, [217, 145, 0]);
    const ink = [11, 18, 32], mid = [90, 100, 120], rule = [205, 213, 228], white = [255, 255, 255];
    const W = 297, CX = W / 2;
    const color = (c) => { doc.setTextColor(...c); };
    const fit = (text, maxW, size, min) => { doc.setFontSize(size); while (size > min && doc.getTextWidth(text) > maxW) { size -= 1; doc.setFontSize(size); } };

    // Centre text at (x, y): native font when it can draw it, else a rendered image of the same size and weight.
    const sysFont = '-apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans", sans-serif';
    const drawText = (text, x, y, { size, bold, italic, c, maxW, charSpace }) => {
      if (!Certificate.needsImage(text)) {
        doc.setFont(italic ? 'times' : 'helvetica', italic ? 'italic' : (bold ? 'bold' : 'normal')); color(c);
        fit(T(text), maxW, size, 7);
        doc.text(T(text), x, y, { align: 'center', charSpace });
        return;
      }
      const img = Certificate._textImage(text, { size, font: italic ? `Georgia, ${sysFont}` : sysFont, weight: bold ? 700 : 400, italic, color: c, maxW });
      doc.addImage(img.url, 'PNG', x - img.w / 2, y - img.h * 0.7, img.w, img.h);
    };

    doc.setProperties({ title: `${T(d.course)} - Certificate of Completion`, subject: T(d.name), author: T(d.org), keywords: d.certId });

    // Top band: brand gradient, drawn as overlapping slices so no seams show.
    const slices = 120, bandH = 7.7;
    for (let i = 0; i < slices; i++) {
      const t = i / (slices - 1);
      const [a, b, u] = t < 0.6 ? [c2, c1, t / 0.6] : [c1, c3, (t - 0.6) / 0.4];
      doc.setFillColor(...a.map((v, k) => Math.round(v + (b[k] - v) * u)));
      doc.rect((W / slices) * i, 0, W / slices + 0.4, bandH, 'F');
    }
    doc.setDrawColor(...rule); doc.setLineWidth(0.3);
    doc.rect(10, 13, W - 20, 187);

    // Header: logo, organisation, title
    const logo = await Certificate._loadLogo(d.logo);
    if (d.logo && !logo) Toast.info('Your organisation logo could not be added to the PDF.');
    let y = 32;
    if (logo) {
      const h = Math.min(19, 71 * logo.h / logo.w), w = h * logo.w / logo.h;
      doc.addImage(logo.url, 'PNG', CX - w / 2, 20, w, h);
      y = 20 + h + 9;
    }
    drawText(Certificate.needsImage(d.org) ? d.org : d.org.toUpperCase(), CX, y, { size: 10, bold: true, c: c1, maxW: 200, charSpace: 1.6 });
    doc.setFont('helvetica', 'bold'); color(ink); doc.setFontSize(30);
    doc.text('Certificate of Completion', CX, y + 14, { align: 'center' });
    doc.setFont('helvetica', 'normal'); color(mid); doc.setFontSize(10.5);
    doc.text('This certifies that', CX, y + 27, { align: 'center' });

    // Name, with a rule beneath it
    drawText(d.name, CX, y + 43, { size: 38, italic: true, c: ink, maxW: 230 });
    const half = Math.min(125, (Certificate.needsImage(d.name) ? 100 : doc.getTextWidth(T(d.name)) / 2) + 10);
    doc.setDrawColor(...rule); doc.line(CX - half, y + 47, CX + half, y + 47);

    doc.setFont('helvetica', 'normal'); color(mid); doc.setFontSize(10.5);
    doc.text('has successfully completed', CX, y + 58, { align: 'center' });
    doc.setFont('helvetica', 'bold'); doc.setFontSize(18);
    const lines = Certificate.needsImage(d.course)
      ? Certificate._wrapImageLines(d.course, 220, 18, sysFont)
      : doc.splitTextToSize(T(d.course), 220).slice(0, 2);
    lines.forEach((line, i) => drawText(line, CX, y + 69 + i * 8, { size: 18, bold: true, c: ink, maxW: 220 }));

    // Date, score, id
    const metaY = y + 69 + (lines.length - 1) * 8 + 22;
    [['DATE', d.date, 'helvetica'], ['SCORE', d.score + '%', 'helvetica'], ['CERTIFICATE ID', d.certId, 'courier']].forEach(([label, value, font], i) => {
      const x = CX + (i - 1) * 72;
      doc.setFont('helvetica', 'bold'); color(mid); doc.setFontSize(7);
      doc.text(label, x, metaY, { align: 'center', charSpace: 0.8 });
      doc.setFont(font, 'bold'); color(ink); doc.setFontSize(font === 'courier' ? 10.5 : 12);
      doc.text(T(value), x, metaY + 6, { align: 'center' });
    });

    // Signatory (left)
    const sigX = 51;
    if (d.signName) drawText(d.signName, sigX, 183, { size: 16, italic: true, c: ink, maxW: 56 });
    doc.setDrawColor(...mid); doc.setLineWidth(0.3); doc.line(sigX - 30, 185, sigX + 30, 185);
    doc.setFont('helvetica', 'bold'); color(mid); doc.setFontSize(7);
    doc.text(T(d.signTitle || `${d.org} Training Department`).toUpperCase(), sigX, 190, { align: 'center', maxWidth: 62 });

    // Seal (centre)
    doc.setFillColor(...c1); doc.circle(CX, 179, 13, 'F');
    doc.setDrawColor(...white); doc.setLineWidth(0.6); doc.circle(CX, 179, 10.6, 'S');
    doc.setLineWidth(1.7); doc.setLineCap('round'); doc.setLineJoin('round');
    doc.line(CX - 6, 179.5, CX - 1.8, 184); doc.line(CX - 1.8, 184, CX + 6.5, 174);

    // QR (right), drawn as vector squares
    const m = Certificate.qrMatrix(d.verifyUrl), cell = 25 / (m.length + 4), qx = 251, qy = 164;
    doc.setFillColor(...ink);
    m.forEach((row, r) => row.forEach((dark, c) => { if (dark) doc.rect(qx + (c + 2) * cell, qy + (r + 2) * cell, cell + 0.02, cell + 0.02, 'F'); }));
    doc.setFont('helvetica', 'bold'); color(mid); doc.setFontSize(6);
    doc.text('SCAN TO VERIFY', qx + 12.5, 192, { align: 'center', charSpace: 0.4 });
    doc.setFont('helvetica', 'normal'); doc.setFontSize(6);
    doc.text(d.verifyUrl, CX, 197, { align: 'center', maxWidth: 200 });
    return doc;
  },

  async downloadPdf() {
    const d = Certificate._data;
    if (!d) { Toast.err('Certificate not ready.'); return; }
    if (!window.jspdf) { Toast.err('PDF library not loaded. Check your connection and try again.'); return; }
    if (typeof qrcode !== 'function') { Toast.err('QR library not loaded. Check your connection and try again.'); return; }
    Toast.info('Preparing your PDF…');
    try {
      const doc = await Certificate.buildPdf(d);
      doc.save(Certificate.fileName(d));
      Toast.ok('Certificate downloaded.');
    } catch (e) {
      console.error('PDF error:', e);
      Toast.err('Could not create the PDF. Please try again.');
    }
  },

  // ─── Public verification page ───
  async showVerify(certId) {
    App.show('screen-verify');
    const card = $$('verify-card');
    card.className = 'card verify-card';
    card.innerHTML = '<div class="skeleton" style="height:64px;width:64px;border-radius:50%;margin:0 auto var(--space-4);"></div><div class="skeleton" style="height:24px;width:60%;margin:0 auto var(--space-3);"></div><div class="skeleton" style="height:16px;width:80%;margin:0 auto;"></div>';
    try {
      const res = await fetch(`${WORKER_URL}/api/verify/${encodeURIComponent(certId)}`);
      if (res.status === 404) return Certificate._verifyResult(card, null, certId);
      if (!res.ok) throw new Error(String(res.status));
      Certificate._verifyResult(card, await res.json(), certId);
    } catch {
      card.innerHTML = `<h1 class="verify-title">We couldn’t check that right now</h1><p class="verify-sub">Check your connection and reload this page to try again.</p>`;
    }
  },

  _verifyResult(card, r, certId) {
    if (!r || !r.valid) {
      card.classList.add('verify-bad');
      card.innerHTML = `<div class="verify-badge" aria-hidden="true">!</div>
        <h1 class="verify-title">Certificate not found</h1>
        <p class="verify-sub">We have no valid certificate with the ID <strong>${esc(certId)}</strong>. Check the ID for typos, or ask the learner to share the link from their certificate.</p>`;
      return;
    }
    const date = new Date(r.completed_at * 1000).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
    card.classList.add('verify-ok');
    card.innerHTML = `<div class="verify-badge" aria-hidden="true">✓</div>
      <h1 class="verify-title">Certificate verified</h1>
      <p class="verify-sub">This certificate was issued by ${esc(r.org)}.</p>
      <dl class="verify-facts">
        <div><dt>Awarded to</dt><dd>${esc(r.name)}</dd></div>
        <div><dt>Course</dt><dd>${esc(r.course)}</dd></div>
        <div><dt>Completed</dt><dd>${esc(date)}</dd></div>
        <div><dt>Certificate ID</dt><dd>${esc(r.cert_id)}</dd></div>
      </dl>`;
  }
};
