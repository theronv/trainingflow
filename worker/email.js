/**
 * Transactional email through Resend (https://resend.com/docs/api-reference/emails/send-email).
 * Inert until RESEND_API_KEY is set. A failed send is logged (never the address) and never throws.
 */

const RESEND_URL = 'https://api.resend.com/emails'
const DEFAULT_APP_URL = 'https://pregame-academy.vickerydigital.com'
const DEFAULT_FROM = 'Pregame Academy <academy@vickerydigital.com>'
const MAX_MANAGER_RECIPIENTS = 20

export function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]))
}

export function appUrl(env) {
  return String(env.APP_URL || DEFAULT_APP_URL).replace(/\/+$/, '')
}

/** Send one message. Resolves true on success, false on any failure. */
export async function sendEmail(env, { to, subject, html, text, idempotencyKey, label = '' }) {
  if (!env.RESEND_API_KEY) return false
  try {
    const res = await fetch(RESEND_URL, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${String(env.RESEND_API_KEY).trim()}`,
        'Content-Type': 'application/json',
        ...(idempotencyKey ? { 'Idempotency-Key': idempotencyKey } : {}),
      },
      body: JSON.stringify({ from: env.EMAIL_FROM || DEFAULT_FROM, to: [to], subject, html, text }),
    })
    if (!res.ok) console.error(`Resend send failed: HTTP ${res.status} ${label}`.trim())
    return res.ok
  } catch (e) {
    console.error(`Resend send failed: ${e.message} ${label}`.trim())
    return false
  }
}

const DEFAULT_ACCENT = '#1565ff'
const accentOf = (color) => (/^#[0-9a-f]{6}$/i.test(color || '') ? color : DEFAULT_ACCENT)

function layout({ org, color, heading, intro, rows, buttonLabel, buttonUrl, footer }) {
  const accent = accentOf(color)
  const facts = rows.map(([k, v]) => `<tr><td style="padding:8px 0;color:#5a6478;font-size:14px;">${escapeHtml(k)}</td><td style="padding:8px 0;text-align:right;font-weight:600;font-size:14px;color:#0b1220;">${escapeHtml(v)}</td></tr>`).join('')
  return `<!doctype html><html><body style="margin:0;background:#f3f5fa;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="padding:24px 12px;"><tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:520px;background:#ffffff;border-radius:12px;overflow:hidden;">
<tr><td style="height:6px;background:${accent};font-size:0;line-height:0;">&nbsp;</td></tr>
<tr><td style="padding:28px 28px 8px;"><div style="font-size:12px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:${accent};">${escapeHtml(org)}</div>
<h1 style="margin:12px 0 8px;font-size:22px;line-height:1.25;color:#0b1220;">${escapeHtml(heading)}</h1>
<p style="margin:0 0 16px;font-size:15px;line-height:1.5;color:#3b4559;">${escapeHtml(intro)}</p></td></tr>
<tr><td style="padding:0 28px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-top:1px solid #e3e8f2;border-bottom:1px solid #e3e8f2;">${facts}</table></td></tr>
<tr><td style="padding:24px 28px 8px;"><a href="${escapeHtml(buttonUrl)}" style="display:inline-block;padding:12px 22px;background:${accent};color:#ffffff;text-decoration:none;border-radius:6px;font-weight:700;font-size:15px;">${escapeHtml(buttonLabel)}</a></td></tr>
<tr><td style="padding:16px 28px 28px;font-size:12px;line-height:1.5;color:#5a6478;">${footer}</td></tr>
</table></td></tr></table></body></html>`
}

const fmtDate = (epochSec) => new Date(epochSec * 1000).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric', timeZone: 'UTC' })

/** The two messages sent when a learner passes. Pure: no I/O. */
export function certificateMessages({ env, org, color, learnerName, course, score, completedAt, certId }) {
  const base = appUrl(env)
  const verifyUrl = `${base}/#/verify/${encodeURIComponent(certId)}`
  const date = fmtDate(completedAt)
  const rows = (who) => [[who, learnerName], ['Course', course], ['Score', `${score}%`], ['Completed', date], ['Certificate ID', certId]]
  const settings = 'You can turn these emails off under Account in the app.'

  const learner = {
    subject: `You earned a certificate: ${course}`,
    html: layout({
      org, color, heading: `Congratulations, ${learnerName}!`,
      intro: `You passed ${course}. Your certificate is ready to view, download and share.`,
      rows: rows('Awarded to'), buttonLabel: 'Open your certificates', buttonUrl: base,
      footer: `Anyone can confirm this certificate at <a href="${escapeHtml(verifyUrl)}" style="color:${accentOf(color)};">${escapeHtml(verifyUrl)}</a>.<br>${settings}`,
    }),
    text: `Congratulations, ${learnerName}!\n\nYou passed ${course} with ${score}% on ${date}.\nSign in to view, download and share your certificate: ${base}\n\nCertificate ID: ${certId}\nVerify: ${verifyUrl}\n\n${settings}`,
  }
  const manager = {
    subject: `${learnerName} earned a certificate: ${course}`,
    html: layout({
      org, color, heading: `${learnerName} earned a certificate`,
      intro: `A member of your team passed ${course}.`,
      rows: rows('Learner'), buttonLabel: 'View team progress', buttonUrl: base,
      footer: `Certificate check: <a href="${escapeHtml(verifyUrl)}" style="color:${accentOf(color)};">${escapeHtml(verifyUrl)}</a>.<br>${settings}`,
    }),
    text: `${learnerName} passed ${course} with ${score}% on ${date}.\nView team progress: ${base}\n\nCertificate ID: ${certId}\nVerify: ${verifyUrl}\n\n${settings}`,
  }
  return { learner, manager }
}

/**
 * Notify the learner and their team's managers about a passed course. Runs after the response is sent.
 * `ensure` makes sure the schema is current. Only a course's first pass sends email: retakes (each of which
 * mints a new certificate) would otherwise repeat the same message. Never throws.
 */
export async function notifyCertificateEarned({ env, db, ensure, learnerId, learnerName, courseId, score, completedAt, certId }) {
  if (!env.RESEND_API_KEY) return
  try {
    await ensure()
    const [learnerRes, courseRes, brandRes, earlierRes] = await Promise.all([
      db.execute({ sql: 'SELECT email, email_notifications, team_id FROM users WHERE id = ?', args: [learnerId] }),
      db.execute({ sql: 'SELECT title FROM courses WHERE id = ?', args: [courseId] }),
      db.execute({ sql: "SELECT org_name, primary_color FROM brand WHERE id = 'default'", args: [] }).catch(() => ({ rows: [] })),
      db.execute({ sql: 'SELECT COUNT(*) AS n FROM completions WHERE learner_id = ? AND course_id = ? AND passed = 1 AND cert_id != ?', args: [learnerId, courseId, certId] }),
    ])
    const learner = learnerRes.rows[0], courseRow = courseRes.rows[0], brand = brandRes.rows[0] || {}
    if (!courseRow || Number(earlierRes.rows[0].n) > 0) return
    const managers = learner && learner.team_id != null
      ? (await db.execute({
          sql: `SELECT id, email FROM users WHERE role = 'manager' AND team_id = ? AND id != ?
                AND email IS NOT NULL AND email != '' AND email_notifications = 1 LIMIT ?`,
          args: [learner.team_id, learnerId, MAX_MANAGER_RECIPIENTS],
        })).rows
      : []
    const { learner: toLearner, manager: toManager } = certificateMessages({
      env, org: brand.org_name || 'Pregame Academy', color: brand.primary_color, learnerName,
      course: courseRow.title, score, completedAt, certId,
    })
    const jobs = []
    if (learner && learner.email && Number(learner.email_notifications) === 1) {
      jobs.push(sendEmail(env, { to: learner.email, ...toLearner, idempotencyKey: `cert-${certId}-${learnerId}`, label: `cert=${certId} to=learner` }))
    }
    for (const m of managers) {
      jobs.push(sendEmail(env, { to: m.email, ...toManager, idempotencyKey: `cert-${certId}-${m.id}`, label: `cert=${certId} to=manager` }))
    }
    await Promise.all(jobs)
  } catch (e) {
    console.error(`Certificate email failed: ${e.message} cert=${certId}`)
  }
}
