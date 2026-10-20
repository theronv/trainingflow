#!/usr/bin/env node
/**
 * Additive demo activity for the live database. NEVER deletes people, courses, teams, brand or admin rows.
 * Touches only the demo accounts listed below.
 *
 *   node seed-demo-activity.mjs            > /tmp/demo-seed.sql      # generate
 *   node seed-demo-activity.mjs --remove   > /tmp/demo-remove.sql    # undo exactly what this adds
 *   turso db shell trainflow < /tmp/demo-seed.sql
 *
 * Adds: assignments (some overdue), completions + certificates + per-question results,
 * in-progress module progress, recent last-login times, and resets the demo accounts' passwords
 * to `demo1234` so every demo login is predictable.
 */
import { pbkdf2Sync, randomBytes } from 'node:crypto'

const REMOVE = process.argv.includes('--remove')
const DEMO_PASSWORD = 'demo1234'
const LEARNERS = ['alex.rivera', 'avery.wilson', 'blake.thompson', 'casey.morgan', 'drew.martinez',
  'jordan.kim', 'quinn.foster', 'riley.hayes', 'sam.patel', 'taylor.brooks']
const MANAGERS = ['sarah.chen', 'marcus.johnson']
const TEAM = {   // which course set each learner gets
  'avery.wilson': 1, 'blake.thompson': 1, 'drew.martinez': 1,
  'alex.rivera': 2, 'casey.morgan': 2, 'jordan.kim': 2, 'sam.patel': 2, 'taylor.brooks': 2,
  'quinn.foster': 3, 'riley.hayes': 3,
}
const COURSES = {
  1: ['Security Awareness: Phishing, MFA and Data Handling', 'Customer Service Excellence', 'Getting Started with Synergy Team Site'],
  2: ['Security Awareness: Phishing, MFA and Data Handling', 'Customer Service Excellence', 'Working with sports customers', 'Getting Started with Synergy Team Site'],
  3: ['Security Awareness: Phishing, MFA and Data Handling', 'Working with sports customers', 'Switching from Windows to Mac at Work', 'Basketball'],
}

const q = (v) => `'${String(v).replace(/'/g, "''")}'`
const names = (list) => list.map(q).join(', ')
const out = []
const emit = (s) => out.push(s.trim().replace(/\s+/g, ' ') + ';')

if (REMOVE) {
  const who = `(SELECT id FROM users WHERE name IN (${names([...LEARNERS, ...MANAGERS])}))`
  emit(`DELETE FROM question_responses WHERE completion_id LIKE 'demo-c-%'`)
  emit(`DELETE FROM completions WHERE id LIKE 'demo-c-%'`)
  emit(`DELETE FROM module_progress WHERE id LIKE 'demo-mp-%'`)
  emit(`DELETE FROM assignments WHERE learner_id IN ${who}`)
  console.log(out.join('\n'))
  process.exit(0)
}

// deterministic PRNG so re-runs generate the same story
let seed = 20261016
const rnd = () => { seed |= 0; seed = (seed + 0x6D2B79F5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296 }
const now = Math.floor(Date.now() / 1000)
const DAY = 86400
const dateStr = (offsetDays) => new Date((now + offsetDays * DAY) * 1000).toISOString().slice(0, 10)

// 1) demo passwords + recent logins
const salt = randomBytes(16)
const hash = `pbkdf2v1:${salt.toString('base64')}:${pbkdf2Sync(DEMO_PASSWORD, salt, 100000, 32, 'sha256').toString('base64')}`
emit(`UPDATE users SET password_hash = ${q(hash)} WHERE name IN (${names([...LEARNERS, ...MANAGERS])})`)
;[...LEARNERS, ...MANAGERS].forEach((n, i) => {
  emit(`UPDATE users SET last_login_at = ${now - Math.floor(rnd() * 6 * DAY) - i * 3600} WHERE name = ${q(n)}`)
})

// 2) per learner x course story
let cn = 0
for (const learner of LEARNERS) {
  for (const course of COURSES[TEAM[learner]]) {
    const r = rnd()
    const assignedAgo = 20 + Math.floor(rnd() * 25)
    let due
    if (r < 0.55) due = dateStr(-(Math.floor(rnd() * 10) + 1))            // completed: due date already passed, done on time
    else if (r < 0.70) due = dateStr(-(Math.floor(rnd() * 8) + 2))        // in progress but overdue
    else if (r < 0.85) due = dateStr(Math.floor(rnd() * 10) + 3)          // in progress, upcoming
    else due = dateStr(Math.floor(rnd() * 20) + 7)                         // not started
    emit(`INSERT OR IGNORE INTO assignments (course_id, learner_id, due_at, assigned_at)
          SELECT c.id, u.id, ${q(due)}, ${q(dateStr(-assignedAgo) + ' 09:00:00')}
          FROM courses c, users u WHERE c.title = ${q(course)} AND u.name = ${q(learner)}`)

    if (r < 0.55) {
      // maybe a failed first try, then a pass
      const attempts = rnd() < 0.25 ? [Math.floor(55 + rnd() * 22), Math.floor(82 + rnd() * 18)] : [Math.floor(80 + rnd() * 20)]
      attempts.forEach((score, k) => {
        cn++
        const id = `demo-c-${String(cn).padStart(3, '0')}`
        const ts = now - (Math.floor(rnd() * 26) + 1 + (attempts.length - 1 - k) * 2) * DAY
        const cert = 'TF-' + (0xD0000000 + cn * 7919).toString(16).toUpperCase().slice(-8)
        const passed = score >= 80 ? 1 : 0
        emit(`INSERT OR IGNORE INTO completions (id, course_id, learner_name, score, passed, completed_at, updated_at, cert_id, learner_id)
              SELECT ${q(id)}, c.id, u.name, ${score}, ${passed}, ${ts}, ${ts}, ${q(cert)}, u.id
              FROM courses c, users u WHERE c.title = ${q(course)} AND u.name = ${q(learner)}`)
        // per-question results consistent with the score (drives "trouble spots")
        emit(`INSERT INTO question_responses (completion_id, question_id, is_correct)
              SELECT ${q(id)}, qn.id, CASE WHEN ((unicode(substr(qn.id,1,1)) * 7 + unicode(substr(qn.id,2,1)) * 13 + ${cn * 17}) % 100) < ${score} THEN 1 ELSE 0 END
              FROM questions qn JOIN modules m ON qn.module_id = m.id JOIN courses c ON m.course_id = c.id
              WHERE c.title = ${q(course)}
                AND NOT EXISTS (SELECT 1 FROM question_responses WHERE completion_id = ${q(id)})`)
      })
    } else if (r < 0.85) {
      // in progress: first k modules passed
      const k = 1 + Math.floor(rnd() * 2)
      const ts = now - (Math.floor(rnd() * 5) + 1) * DAY
      emit(`INSERT OR IGNORE INTO module_progress (id, learner_id, module_id, course_id, passed, score, completed_at, created_at, updated_at)
            SELECT 'demo-mp-' || u.id || '-' || m.id, u.id, m.id, c.id, 1, ${Math.floor(82 + rnd() * 18)}, ${ts}, ${ts}, ${ts}
            FROM courses c JOIN modules m ON m.course_id = c.id, users u
            WHERE c.title = ${q(course)} AND u.name = ${q(learner)} AND m.sort_order < ${k}`)
    }
  }
}

console.log(out.join('\n'))
