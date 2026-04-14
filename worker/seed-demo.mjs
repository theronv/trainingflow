/**
 * TrainingFlow — Demo Seed Script
 *
 * Populates the database with realistic demo data:
 *   - 2 teams, 2 managers, 10 learners
 *   - 4 courses with 3 modules & 3 questions each
 *   - Assignments, completions, and in-progress module progress
 *   - Backdated over 5 weeks so stats look like real usage
 *
 * Usage (run from the worker/ directory):
 *   # Seed local dev database:
 *   node seed-demo.mjs
 *
 *   # Seed production (courses preserved — only users/teams/activity reset):
 *   TURSO_URL=libsql://... TURSO_TOKEN=... node seed-demo.mjs --prod --reset
 *
 *   # Seed production using your existing courses (don't add the 4 demo courses):
 *   TURSO_URL=... TURSO_TOKEN=... node seed-demo.mjs --prod --reset --skip-courses
 *
 *   # Full wipe including courses (destructive!):
 *   TURSO_URL=... TURSO_TOKEN=... node seed-demo.mjs --prod --reset-courses
 *
 * Demo credentials (all use password: demo1234):
 *   Admin:    (password only)
 *   Managers: sarah.chen  |  marcus.johnson
 *   Learners: alex.rivera, jordan.kim, taylor.brooks, sam.patel, casey.morgan
 *             blake.thompson, drew.martinez, quinn.foster, avery.wilson, riley.hayes
 */

import { createClient } from '@libsql/client'
import { resolve, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dir = dirname(fileURLToPath(import.meta.url))

// ── Args ──────────────────────────────────────────────────────────────────────

const args         = process.argv.slice(2)
const PROD         = args.includes('--prod')
const RESET        = args.includes('--reset')         // clears users/teams/activity, keeps courses
const RESET_COURSES = args.includes('--reset-courses') // also clears courses
const SKIP_COURSES = args.includes('--skip-courses')   // don't seed the 4 demo courses

// ── DB Connection ─────────────────────────────────────────────────────────────

let db
if (PROD) {
  const url   = process.env.TURSO_URL
  const token = process.env.TURSO_TOKEN
  if (!url || !token) {
    console.error('ERROR: Set TURSO_URL and TURSO_TOKEN env vars for --prod mode.')
    console.error('  export TURSO_URL=libsql://your-db.turso.io')
    console.error('  export TURSO_TOKEN=your-auth-token')
    process.exit(1)
  }
  db = createClient({ url, authToken: token })
  console.log('🌐 Seeding PRODUCTION database:', url)
} else {
  const localDb = resolve(__dir, 'local.db')
  db = createClient({ url: `file:${localDb}` })
  console.log('💾 Seeding local database:', localDb)
}

// ── Utilities ─────────────────────────────────────────────────────────────────

const ENC = new TextEncoder()

function uid() {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 12)
}

function certId() {
  return 'TF-' + crypto.randomUUID().replace(/-/g, '').slice(0, 8).toUpperCase()
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const key  = await crypto.subtle.importKey('raw', ENC.encode(password), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100_000 },
    key, 256
  )
  const b64 = (bytes) => btoa(String.fromCharCode(...bytes))
  return `pbkdf2v1:${b64(salt)}:${b64(new Uint8Array(bits))}`
}

/** Returns a Unix timestamp (seconds) N days ago, optionally offset by hours */
function daysAgo(n, hourOffset = 0) {
  return Math.floor(Date.now() / 1000) - (n * 86400) - (hourOffset * 3600)
}

/** Pick a random integer between min and max (inclusive) */
function rand(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min
}

async function exec(sql, args = []) {
  return db.execute({ sql, args })
}

// ── Reset ─────────────────────────────────────────────────────────────────────

async function resetData() {
  console.log('\n🗑️  Clearing demo users/teams/activity (courses preserved)...')
  // Courses, modules, and questions are intentionally NOT cleared —
  // use --reset-courses to also wipe course content.
  await db.batch([
    { sql: 'DELETE FROM question_responses', args: [] },
    { sql: 'DELETE FROM module_progress',    args: [] },
    { sql: 'DELETE FROM completions',        args: [] },
    { sql: 'DELETE FROM assignments',        args: [] },
    { sql: 'DELETE FROM learner_tags',       args: [] },
    { sql: 'DELETE FROM invite_codes',       args: [] },
    { sql: 'DELETE FROM users',              args: [] },
    { sql: 'DELETE FROM teams',              args: [] },
    { sql: 'DELETE FROM brand',              args: [] },
    { sql: 'DELETE FROM admin',              args: [] },
  ], 'write')
  console.log('   ✓ Users, teams, and activity cleared (courses kept)')
}

async function resetCourses() {
  console.log('\n🗑️  Clearing courses...')
  await db.batch([
    { sql: 'DELETE FROM question_responses', args: [] },
    { sql: 'DELETE FROM module_progress',    args: [] },
    { sql: 'DELETE FROM completions',        args: [] },
    { sql: 'DELETE FROM assignments',        args: [] },
    { sql: 'DELETE FROM tag_assignments',    args: [] },
    { sql: 'DELETE FROM questions',          args: [] },
    { sql: 'DELETE FROM modules',            args: [] },
    { sql: 'DELETE FROM courses',            args: [] },
  ], 'write')
  console.log('   ✓ Courses cleared')
}

// ── Brand ─────────────────────────────────────────────────────────────────────

async function seedBrand() {
  console.log('\n🎨 Seeding brand...')
  const now = Math.floor(Date.now() / 1000)
  await exec(
    `INSERT OR REPLACE INTO brand
       (id, org_name, tagline, primary_color, secondary_color,
        pass_threshold, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ['default', 'Meridian Health', 'Empowering our people through learning',
     '#0F4C81', '#1A6B3C', 80, now, now]
  )
  console.log('   ✓ Brand: Meridian Health')
}

// ── Admin ─────────────────────────────────────────────────────────────────────

async function seedAdmin(passwordHash) {
  console.log('\n🔐 Seeding admin account...')
  const now = Math.floor(Date.now() / 1000)
  await exec(
    `INSERT OR REPLACE INTO admin (id, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?)`,
    ['default', passwordHash, now, now]
  )
  console.log('   ✓ Admin password set')
}

// ── Teams ─────────────────────────────────────────────────────────────────────

async function seedTeams() {
  console.log('\n🏢 Seeding teams...')
  await exec(`INSERT OR IGNORE INTO teams (name, created_at) VALUES (?, datetime('now', '-40 days'))`, ['Patient Services'])
  await exec(`INSERT OR IGNORE INTO teams (name, created_at) VALUES (?, datetime('now', '-40 days'))`, ['Facilities & Operations'])

  const r1 = await exec(`SELECT id FROM teams WHERE name = 'Patient Services'`)
  const r2 = await exec(`SELECT id FROM teams WHERE name = 'Facilities & Operations'`)
  const t1 = r1.rows[0][0]
  const t2 = r2.rows[0][0]
  console.log(`   ✓ Patient Services (id: ${t1})`)
  console.log(`   ✓ Facilities & Operations (id: ${t2})`)
  return { patientServices: t1, facilities: t2 }
}

// ── Users ─────────────────────────────────────────────────────────────────────

async function seedUsers(teams, hash) {
  console.log('\n👥 Seeding managers & learners...')

  const managers = [
    { name: 'sarah.chen',     team: teams.patientServices },
    { name: 'marcus.johnson', team: teams.facilities },
  ]

  const learners = [
    // Patient Services
    { name: 'alex.rivera',    team: teams.patientServices },
    { name: 'jordan.kim',     team: teams.patientServices },
    { name: 'taylor.brooks',  team: teams.patientServices },
    { name: 'sam.patel',      team: teams.patientServices },
    { name: 'casey.morgan',   team: teams.patientServices },
    // Facilities & Operations
    { name: 'blake.thompson', team: teams.facilities },
    { name: 'drew.martinez',  team: teams.facilities },
    { name: 'quinn.foster',   team: teams.facilities },
    { name: 'avery.wilson',   team: teams.facilities },
    { name: 'riley.hayes',    team: teams.facilities },
  ]

  const ids = {}

  for (const m of managers) {
    const id = uid()
    ids[m.name] = id
    await exec(
      `INSERT OR IGNORE INTO users (id, name, password_hash, role, team_id, last_login_at, created_at)
       VALUES (?, ?, ?, 'manager', ?, ?, ?)`,
      [id, m.name, hash, m.team, daysAgo(1), daysAgo(38)]
    )
    console.log(`   ✓ Manager: ${m.name}`)
  }

  for (const l of learners) {
    const id = uid()
    ids[l.name] = id
    await exec(
      `INSERT OR IGNORE INTO users (id, name, password_hash, role, team_id, last_login_at, created_at)
       VALUES (?, ?, ?, 'learner', ?, ?, ?)`,
      [id, l.name, hash, l.team, daysAgo(rand(1, 5)), daysAgo(rand(33, 38))]
    )
  }
  console.log(`   ✓ 10 learners created`)

  // Re-read IDs in case of OR IGNORE skipping inserts
  for (const name of [...managers.map(m => m.name), ...learners.map(l => l.name)]) {
    const r = await exec(`SELECT id FROM users WHERE name = ?`, [name])
    if (r.rows[0]) ids[name] = r.rows[0][0]
  }

  return ids
}

// ── Courses ───────────────────────────────────────────────────────────────────

async function seedCourses() {
  console.log('\n📚 Seeding courses...')

  const courses = [
    {
      id:          uid(),
      icon:        '🦺',
      title:       'Workplace Safety Fundamentals',
      description: 'A comprehensive introduction to identifying hazards, following emergency procedures, and using personal protective equipment safely in a healthcare environment.',
      modules: [
        {
          title: 'Hazard Identification & Risk Assessment',
          content: `<h2>What Is a Workplace Hazard?</h2>
<p>A hazard is any source of potential damage, harm, or adverse health effects on something or someone. In healthcare settings, hazards fall into five main categories: <strong>biological</strong> (infectious agents), <strong>chemical</strong> (cleaning agents, medications), <strong>physical</strong> (slips, falls, sharp objects), <strong>ergonomic</strong> (lifting, repetitive motion), and <strong>psychosocial</strong> (stress, violence).</p>
<h2>The Risk Assessment Process</h2>
<p>When you identify a hazard, follow the five-step process: (1) Identify the hazard, (2) Determine who might be harmed, (3) Evaluate the risk and decide on controls, (4) Record findings, (5) Review and update regularly.</p>
<h2>Reporting Hazards</h2>
<p>Every team member has both the right and the responsibility to report unsafe conditions. Use the incident reporting system immediately—do not wait. Near-misses are just as important to report as actual incidents, because they reveal gaps before someone gets hurt.</p>`,
          summary: 'Learn to identify five categories of workplace hazards and apply the five-step risk assessment process.',
          learning_objectives: ['Identify the five categories of workplace hazards', 'Apply the risk assessment process', 'Report hazards using the correct procedure'],
          questions: [
            { question: 'Which of the following is an example of a BIOLOGICAL hazard in a healthcare setting?', options: ['A wet floor', 'A needlestick injury from a used syringe', 'Repetitive keyboard use', 'Loud noise from equipment'], correct: 1, explanation: 'Used syringes carry the risk of bloodborne pathogen exposure, which is a biological hazard.' },
            { question: 'What is the FIRST step in the five-step risk assessment process?', options: ['Record your findings', 'Evaluate the risk', 'Identify the hazard', 'Review and update'], correct: 2, explanation: 'You must identify the hazard before you can evaluate or control it.' },
            { question: 'Why should near-miss incidents be reported, even when no one is injured?', options: ['They are legally required by OSHA in all cases', 'They reveal gaps in safety systems before actual harm occurs', 'They increase insurance premiums if not reported', 'They only matter if a supervisor witnessed them'], correct: 1, explanation: 'Near-misses are valuable early-warning signals that allow corrective action before a real injury happens.' },
          ]
        },
        {
          title: 'Emergency Procedures & Evacuation',
          content: `<h2>Know Your Emergency Codes</h2>
<p>Our facility uses a standardized color-code system. Familiarize yourself with: <strong>Code Red</strong> (fire), <strong>Code Blue</strong> (medical emergency), <strong>Code Gray</strong> (violent or combative person), <strong>Code Orange</strong> (hazardous material spill), and <strong>Code Silver</strong> (active threat with weapon).</p>
<h2>Fire Safety — RACE & PASS</h2>
<p>In a fire emergency, remember <strong>RACE</strong>: <em>Rescue</em> anyone in immediate danger, <em>Activate</em> the alarm, <em>Contain</em> the fire by closing doors, <em>Extinguish</em> or <em>Evacuate</em>. When using a fire extinguisher, use <strong>PASS</strong>: <em>Pull</em> the pin, <em>Aim</em> at the base, <em>Squeeze</em> the handle, <em>Sweep</em> side to side.</p>
<h2>Evacuation Routes</h2>
<p>Know at least two evacuation routes from every area you work in. Evacuation maps are posted on every floor. Do not use elevators during a fire evacuation. Assembly points are marked with a green figure on a white background.</p>`,
          summary: 'Understand emergency codes, the RACE & PASS frameworks, and proper evacuation procedures.',
          learning_objectives: ['Recall the five primary emergency color codes', 'Apply the RACE acronym during a fire', 'Locate evacuation routes and assembly points'],
          questions: [
            { question: 'What does the "A" in the RACE acronym stand for?', options: ['Assess', 'Activate the alarm', 'Alert security', 'Assist patients'], correct: 1, explanation: 'After rescuing anyone in immediate danger, you activate the fire alarm to alert others.' },
            { question: 'Which emergency code indicates a hazardous material spill?', options: ['Code Red', 'Code Blue', 'Code Orange', 'Code Gray'], correct: 2, explanation: 'Code Orange is used for hazardous material spills or releases.' },
            { question: 'During a fire evacuation, you should:', options: ['Use the elevator to move patients quickly', 'Close doors to contain fire and smoke', 'Wait for fire department before evacuating', 'Take personal belongings first'], correct: 1, explanation: 'Closing doors slows the spread of fire and smoke, buying critical time for evacuation.' },
          ]
        },
        {
          title: 'Personal Protective Equipment (PPE)',
          content: `<h2>Why PPE Matters</h2>
<p>Personal Protective Equipment is your last line of defense against workplace hazards. While engineering controls and safe work practices come first, PPE fills the gaps when other controls aren't sufficient. Using it correctly—every time—can mean the difference between going home safe and a serious injury.</p>
<h2>Common PPE in Healthcare</h2>
<ul>
<li><strong>Gloves</strong> — protect hands from biological and chemical hazards. Change between patients; dispose of properly.</li>
<li><strong>Masks/Respirators</strong> — surgical masks filter large droplets; N95 respirators filter airborne particles. Know the difference and use the right one.</li>
<li><strong>Eye Protection</strong> — goggles or face shields prevent splash exposure to eyes.</li>
<li><strong>Gowns</strong> — protect clothing and skin from contamination. Remove by rolling outward to contain contaminants.</li>
</ul>
<h2>Donning & Doffing Order</h2>
<p><strong>Donning (putting on):</strong> Gown → Mask/Respirator → Goggles/Face Shield → Gloves.<br>
<strong>Doffing (removing):</strong> Gloves → Goggles/Face Shield → Gown → Mask/Respirator. Always perform hand hygiene between each step.</p>`,
          summary: 'Select, use, and remove PPE correctly to protect yourself and patients from cross-contamination.',
          learning_objectives: ['Identify the correct PPE for different hazard types', 'Follow the proper donning and doffing sequence', 'Dispose of used PPE safely'],
          questions: [
            { question: 'What is the correct ORDER for doffing (removing) PPE?', options: ['Mask → Gown → Gloves → Goggles', 'Gloves → Goggles → Gown → Mask', 'Gown → Gloves → Mask → Goggles', 'Goggles → Gown → Gloves → Mask'], correct: 1, explanation: 'Gloves are the most contaminated item and are removed first. The mask/respirator is removed last because it protects your airway.' },
            { question: 'An N95 respirator is required (rather than a surgical mask) when:', options: ['Any patient contact is expected', 'There is risk of airborne particle transmission (e.g., TB, COVID-19)', 'Performing a blood draw', 'Working in a clean area of the facility'], correct: 1, explanation: 'N95 respirators filter at least 95% of airborne particles, making them essential for airborne precaution situations.' },
            { question: 'When should you perform hand hygiene while doffing PPE?', options: ['Only after all PPE has been removed', 'Before doffing begins, and after the entire sequence', 'Between each PPE item removed', 'It is not required if gloves were worn'], correct: 2, explanation: 'Hand hygiene between each doffing step prevents transferring contaminants from one item to your hands and then to the next item.' },
          ]
        }
      ]
    },

    {
      id:          uid(),
      icon:        '🔒',
      title:       'HIPAA Compliance & Patient Privacy',
      description: 'Understand your obligations under HIPAA, how to handle protected health information responsibly, and how to respond if a breach occurs.',
      modules: [
        {
          title: 'Understanding HIPAA',
          content: `<h2>What Is HIPAA?</h2>
<p>The Health Insurance Portability and Accountability Act (HIPAA) was enacted in 1996. Its Privacy Rule establishes national standards to protect individuals' medical records and other protected health information (PHI). If you work with patient data in any capacity, HIPAA applies to you.</p>
<h2>What Counts as PHI?</h2>
<p>Protected Health Information is any individually identifiable health information. This includes: names, addresses, dates (except year), phone numbers, email addresses, Social Security numbers, medical record numbers, account numbers, photos, and any other unique identifier. PHI can be in any format—paper, electronic (ePHI), or spoken.</p>
<h2>The Minimum Necessary Standard</h2>
<p>HIPAA requires that you access, use, or disclose only the minimum amount of PHI necessary to accomplish your task. Before accessing a patient's record, ask yourself: "Do I actually need this information to do my job right now?" If the answer is no, don't access it—even if you technically have permission.</p>`,
          summary: 'Understand what HIPAA protects, what counts as PHI, and the minimum necessary standard.',
          learning_objectives: ['Define PHI and list at least five identifiers', 'Explain the minimum necessary standard', 'Describe who is covered by HIPAA'],
          questions: [
            { question: 'Which of the following is NOT considered Protected Health Information (PHI)?', options: ['A patient\'s date of birth combined with their diagnosis', 'Anonymized aggregate statistics with no individual identifiers', 'A patient\'s email address linked to their treatment record', 'A photograph of a patient taken during care'], correct: 1, explanation: 'Truly anonymized data with all 18 identifiers removed is no longer considered PHI under HIPAA.' },
            { question: 'The "minimum necessary" standard means you should:', options: ['Only request records that your supervisor approves', 'Access only the PHI you need to complete your specific task', 'Minimize the number of systems you log into', 'Use the shortest password possible to reduce login time'], correct: 1, explanation: 'You are required to limit PHI access to what is actually needed for the task at hand, even if you have broader system access.' },
            { question: 'PHI can exist in which formats?', options: ['Only electronic records (ePHI)', 'Only written/paper records', 'Electronic, paper, and spoken/verbal', 'Only records created after 1996'], correct: 2, explanation: 'HIPAA protects PHI in all formats: electronic, paper, and oral communications.' },
          ]
        },
        {
          title: 'Handling Patient Data Securely',
          content: `<h2>Access Controls & Passwords</h2>
<p>Your login credentials are personal and non-transferable. Never share your username or password with anyone—including colleagues or supervisors. Use strong, unique passwords and enable multi-factor authentication wherever available. Always lock your screen when stepping away from a workstation, even for a moment.</p>
<h2>Safe Communication of PHI</h2>
<p>When you must communicate PHI: (1) Verify the identity of the recipient before sharing. (2) Use secure, encrypted channels—not personal email or SMS. (3) Fax only to verified numbers with a cover sheet. (4) In verbal conversations, use private spaces and lower your voice.</p>
<h2>Physical Safeguards</h2>
<p>Paper records must be stored in locked filing cabinets or secure areas. Shred documents containing PHI—never put them in regular recycling. Computer screens should be positioned so passersby cannot view patient data. Visitor logs and badge access systems help control physical access to sensitive areas.</p>`,
          summary: 'Apply technical, administrative, and physical safeguards to protect PHI in daily work.',
          learning_objectives: ['Enforce proper access control and password hygiene', 'Communicate PHI securely across different channels', 'Apply physical safeguards for paper and digital records'],
          questions: [
            { question: 'A colleague asks to use your login to quickly check a patient record because they\'re locked out. You should:', options: ['Allow it once as a courtesy since you trust them', 'Refuse and direct them to IT for access restoration', 'Let them use it but stand next to them the whole time', 'Allow it only if a supervisor is present'], correct: 1, explanation: 'Sharing credentials is a HIPAA violation regardless of trust or intent. Direct the colleague to IT to restore their own access.' },
            { question: 'Which is the SAFEST way to send a patient\'s lab results to another provider?', options: ['Personal Gmail with a password-protected attachment', 'Secure encrypted messaging or fax to a verified number', 'Standard SMS text message for speed', 'Verbal description over a public phone in the hallway'], correct: 1, explanation: 'Only secure, encrypted channels or verified fax lines are appropriate for transmitting PHI.' },
            { question: 'You finish reviewing a patient chart on a shared workstation. What should you do before leaving?', options: ['Leave it open so the next clinician can see the context', 'Log out and lock the screen', 'Close the browser tab only', 'It\'s fine to leave if you\'ll be back in 10 minutes'], correct: 1, explanation: 'You must always log out and lock the screen when leaving a workstation to prevent unauthorized access to PHI.' },
          ]
        },
        {
          title: 'Breach Prevention & Response',
          content: `<h2>What Is a HIPAA Breach?</h2>
<p>A breach is the acquisition, access, use, or disclosure of PHI that is not permitted under HIPAA's Privacy Rule and that compromises the security or privacy of the PHI. Breaches can be accidental (sending a fax to the wrong number) or intentional (unauthorized access to celebrity records). Both are serious and both must be reported.</p>
<h2>Common Breach Causes</h2>
<ul>
<li>Lost or stolen devices containing unencrypted ePHI</li>
<li>Phishing emails that trick employees into providing credentials</li>
<li>Improper disposal of records (recycling instead of shredding)</li>
<li>Unauthorized access out of curiosity (e.g., looking up a family member)</li>
<li>Misdirected emails or faxes</li>
</ul>
<h2>What to Do If a Breach Occurs</h2>
<p>Report any suspected or actual breach immediately to your Privacy Officer—do not try to assess or contain it yourself first. Under the Breach Notification Rule, covered entities must notify affected individuals within 60 days of discovering a breach. Breaches affecting 500 or more individuals also require notification to HHS and prominent media outlets. The penalty for not reporting can exceed the penalty for the breach itself.</p>`,
          summary: 'Recognize common breach scenarios, prevent them through daily habits, and respond correctly when one occurs.',
          learning_objectives: ['Define a HIPAA breach and give three examples', 'Identify the most common causes of PHI breaches', 'Follow the correct breach reporting procedure'],
          questions: [
            { question: 'You accidentally fax a patient\'s records to the wrong clinic. What should you do?', options: ['Call the wrong clinic and ask them to destroy the fax', 'Do nothing, since it was an accident', 'Report it immediately to your Privacy Officer as a potential breach', 'Wait to see if any harm results before reporting'], correct: 2, explanation: 'Any accidental disclosure of PHI must be reported to the Privacy Officer immediately, regardless of intent. They will conduct a risk assessment.' },
            { question: 'A coworker mentions they checked their neighbor\'s medical records out of curiosity. This is:', options: ['Acceptable if they did not share the information', 'A HIPAA violation regardless of what they did with the information', 'Only a problem if the neighbor complains', 'Fine if they are also a patient at the facility'], correct: 1, explanation: 'Accessing PHI without a job-related need is an unauthorized use regardless of whether the information was shared further.' },
            { question: 'Under the HIPAA Breach Notification Rule, affected individuals must be notified within:', options: ['24 hours', '30 days', '60 days of discovering the breach', '90 days of the breach occurring'], correct: 2, explanation: 'Covered entities must notify affected individuals no later than 60 days after discovery of the breach.' },
          ]
        }
      ]
    },

    {
      id:          uid(),
      icon:        '⭐',
      title:       'Customer Service Excellence',
      description: 'Build the communication skills and service mindset needed to deliver consistently outstanding experiences, even in high-pressure situations.',
      modules: [
        {
          title: 'Communication Foundations',
          content: `<h2>The Communication Model</h2>
<p>Every interaction involves a sender, a message, a channel, and a receiver—plus the ever-present risk of noise (anything that distorts the message). Great communicators manage all four elements: they choose the right channel, craft a clear message, and actively verify that the receiver understood what was intended.</p>
<h2>Active Listening</h2>
<p>Active listening is the most underrated communication skill. It involves: giving full attention (put down your phone), reflecting back what you heard ("So what I'm hearing is…"), asking clarifying questions, and withholding judgment until the person has finished speaking. Studies consistently show that people rate interactions as "excellent" when they feel genuinely heard—even if the outcome wasn't what they wanted.</p>
<h2>Non-Verbal Communication</h2>
<p>Body language, facial expressions, tone of voice, and eye contact account for the majority of what people "hear." Crossed arms signal defensiveness. Downward gaze signals disinterest. A warm, neutral tone combined with appropriate eye contact signals presence and respect. Align your non-verbals with your words—if they contradict each other, people will believe the non-verbals.</p>`,
          summary: 'Master active listening, clear messaging, and non-verbal communication for high-quality interactions.',
          learning_objectives: ['Apply the active listening framework in conversations', 'Align verbal and non-verbal communication', 'Choose the right communication channel for each situation'],
          questions: [
            { question: 'Which behavior BEST demonstrates active listening?', options: ['Preparing your response while the other person is still speaking', 'Reflecting back what you heard to confirm understanding', 'Nodding continuously to show agreement', 'Taking notes and not making eye contact'], correct: 1, explanation: 'Reflecting back confirms understanding and signals to the speaker that they have been genuinely heard.' },
            { question: 'When verbal and non-verbal messages contradict each other, people typically believe:', options: ['The verbal message, because words are explicit', 'The non-verbal message, because it is harder to fake', 'Whichever message came first', 'Neither — they ask for clarification'], correct: 1, explanation: 'Non-verbal communication is largely subconscious and therefore perceived as more authentic than spoken words.' },
            { question: 'A customer is explaining a problem. The best time to start formulating your response is:', options: ['While they are still talking, so you are ready immediately', 'After they have finished and you have confirmed understanding', 'Midway through their explanation to save time', 'Before the conversation starts, by assuming the likely issue'], correct: 1, explanation: 'Formulating a response while someone speaks divides your attention and leads to missing key details.' },
          ]
        },
        {
          title: 'Handling Difficult Situations',
          content: `<h2>The HEAT Framework</h2>
<p>When someone is upset, use the HEAT framework: <strong>Hear them out</strong> (let them express frustration without interrupting), <strong>Empathize</strong> ("I can see why that would be frustrating"), <strong>Apologize</strong> for the experience even if it wasn't your fault ("I'm sorry you had this experience"), <strong>Take action</strong> (state what you will do and follow through).</p>
<h2>Defusing Anger</h2>
<p>Never match an angry person's energy. Stay calm, lower your voice slightly (not your eye contact), and slow your speech. Use "I" statements to avoid sounding accusatory. Avoid phrases like "You need to calm down" (invalidating) or "That's our policy" without explanation (dismissive). Instead: "Let me find out what we can do" keeps the door open.</p>
<h2>Setting Limits Without Escalating</h2>
<p>If a person becomes abusive or threatening, you have the right to set a firm, respectful limit: "I want to help you, but I'm not able to continue our conversation while being spoken to this way. I'll step away briefly—when you're ready, I'll be right back." Then follow through. Involve a supervisor or security if behavior doesn't improve.</p>`,
          summary: 'Use the HEAT framework to de-escalate difficult interactions and set appropriate limits with upset customers.',
          learning_objectives: ['Apply the HEAT framework to an upset customer', 'Use language that de-escalates rather than inflames', 'Set limits professionally without escalating further'],
          questions: [
            { question: 'In the HEAT framework, what does the "E" stand for?', options: ['Evaluate the complaint', 'Empathize with the customer', 'Explain your policy', 'Escalate to a supervisor'], correct: 1, explanation: 'Empathizing acknowledges the customer\'s feelings and lowers emotional temperature before moving to resolution.' },
            { question: 'A customer is shouting. The most effective immediate response is to:', options: ['Match their volume to show you take it seriously', 'Lower your own voice and slow your speech', 'Immediately call a supervisor', 'Read them the relevant policy out loud'], correct: 1, explanation: 'Lowering your voice and slowing your speech creates contrast that naturally encourages the other person to do the same.' },
            { question: 'Saying "That\'s just our policy" without further explanation is problematic because:', options: ['Policies cannot be mentioned to customers', 'It is dismissive and closes off options without helping', 'Policies must always be shown in writing', 'It might reveal confidential information'], correct: 1, explanation: 'Citing policy without context or an attempt to help signals indifference, which increases frustration rather than resolving it.' },
          ]
        },
        {
          title: 'Service Recovery',
          content: `<h2>The Service Recovery Paradox</h2>
<p>Research shows that customers who experience a problem that is resolved quickly and well often end up more loyal than customers who never had a problem at all. This is the service recovery paradox—it means a mistake, handled exceptionally, is an opportunity. The key word is "quickly": a delayed recovery loses most of its loyalty-building power.</p>
<h2>The Five Steps of Service Recovery</h2>
<ol>
<li><strong>Acknowledge</strong> the failure directly ("You're right, that should not have happened").</li>
<li><strong>Apologize</strong> sincerely and specifically ("I'm sorry your appointment was delayed by 45 minutes").</li>
<li><strong>Ask</strong> what would make it right ("What can I do to make this better for you?").</li>
<li><strong>Act</strong> swiftly with a concrete resolution.</li>
<li><strong>Follow up</strong> to confirm the resolution was satisfactory.</li>
</ol>
<h2>Learning from Complaints</h2>
<p>Every complaint is data. Systematically capture what went wrong: Was it a process failure? A communication breakdown? A resource gap? Share findings with your team without blame. Organizations that treat complaints as quality-improvement intelligence consistently outperform those that treat them as problems to bury.</p>`,
          summary: 'Turn service failures into loyalty opportunities using the five-step recovery framework.',
          learning_objectives: ['Explain the service recovery paradox', 'Apply the five-step service recovery process', 'Use complaint data to drive process improvement'],
          questions: [
            { question: 'The "service recovery paradox" suggests that:', options: ['Customer complaints should always be escalated', 'A well-handled service failure can create greater loyalty than no failure at all', 'Service recovery is only effective if it includes a refund', 'Customers are more forgiving of second failures'], correct: 1, explanation: 'When handled quickly and genuinely, a resolved problem can exceed the customer\'s expectations and build stronger loyalty.' },
            { question: 'In the five-step recovery process, what comes AFTER apologizing?', options: ['Follow up to confirm satisfaction', 'Ask what would make it right', 'Act with a concrete resolution', 'Document the incident in your report'], correct: 1, explanation: 'After acknowledging and apologizing, you ask the customer what resolution would satisfy them before acting — this ensures the action you take is actually helpful.' },
            { question: 'Why is it important to share complaint findings with your team?', options: ['To assign blame and prevent repeat offenses', 'To demonstrate compliance during audits', 'To identify process failures and improve quality collectively', 'It is required by customer service law'], correct: 2, explanation: 'Treating complaints as quality-improvement data — shared without blame — is how organizations systematically reduce the root causes of service failures.' },
          ]
        }
      ]
    },

    {
      id:          uid(),
      icon:        '🧼',
      title:       'Infection Control & Hand Hygiene',
      description: 'Master evidence-based hand hygiene techniques, understand transmission routes, and apply isolation precautions to protect patients, colleagues, and yourself.',
      modules: [
        {
          title: 'Understanding Infectious Disease Transmission',
          content: `<h2>The Chain of Infection</h2>
<p>Infection requires a complete chain: a <strong>pathogen</strong> (the infectious agent), a <strong>reservoir</strong> (where it lives), a <strong>portal of exit</strong>, a <strong>mode of transmission</strong>, a <strong>portal of entry</strong>, and a <strong>susceptible host</strong>. Break any link and the infection cannot spread. Most infection control practices target the mode of transmission, because it is the link most within our control.</p>
<h2>Routes of Transmission</h2>
<ul>
<li><strong>Contact</strong> — direct (touching an infected person) or indirect (touching contaminated surfaces). The most common route in healthcare.</li>
<li><strong>Droplet</strong> — large respiratory droplets (>5 µm) that travel short distances (≤3 feet). Example: influenza.</li>
<li><strong>Airborne</strong> — small particles (<5 µm) that remain suspended and travel longer distances. Example: tuberculosis, measles, COVID-19.</li>
<li><strong>Vehicle</strong> — contaminated food, water, or medications.</li>
<li><strong>Vector-borne</strong> — via insects (mosquitoes, ticks).</li>
</ul>
<h2>Healthcare-Associated Infections (HAIs)</h2>
<p>HAIs are infections patients acquire while receiving care, and they are largely preventable. The most common types are central line-associated bloodstream infections (CLABSI), catheter-associated urinary tract infections (CAUTI), surgical site infections (SSI), and ventilator-associated pneumonia (VAP). Strict adherence to infection control protocols is the single most effective prevention strategy.</p>`,
          summary: 'Understand the chain of infection, routes of transmission, and why HAI prevention matters.',
          learning_objectives: ['Describe the six links in the chain of infection', 'Distinguish between contact, droplet, and airborne transmission', 'Name three common healthcare-associated infections'],
          questions: [
            { question: 'Which transmission route involves small airborne particles that remain suspended and can travel beyond 3 feet?', options: ['Contact transmission', 'Droplet transmission', 'Airborne transmission', 'Vehicle transmission'], correct: 2, explanation: 'Airborne transmission involves particles smaller than 5 µm that can remain suspended in the air for extended periods and travel greater distances.' },
            { question: 'Breaking which link in the chain of infection is the PRIMARY focus of most infection control practices?', options: ['The pathogen itself', 'The reservoir', 'The mode of transmission', 'The susceptible host'], correct: 2, explanation: 'The mode of transmission is most reliably interrupted through hand hygiene, PPE, and isolation precautions.' },
            { question: 'Which of the following is a Healthcare-Associated Infection (HAI)?', options: ['An infection a patient had before admission', 'A central line-associated bloodstream infection acquired during care', 'A seasonal cold caught in the parking lot', 'A genetic susceptibility to infection'], correct: 1, explanation: 'HAIs are infections patients acquire during the course of receiving healthcare, such as CLABSI, which is associated with central line insertion.' },
          ]
        },
        {
          title: 'Hand Hygiene Protocols',
          content: `<h2>The Five Moments of Hand Hygiene</h2>
<p>The WHO's Five Moments framework identifies when hand hygiene is mandatory: (1) <strong>Before touching a patient</strong>, (2) <strong>Before a clean/aseptic procedure</strong>, (3) <strong>After body fluid exposure risk</strong>, (4) <strong>After touching a patient</strong>, (5) <strong>After touching patient surroundings</strong>. All five moments apply whether you use alcohol-based hand rub (ABHR) or soap and water.</p>
<h2>Alcohol-Based Hand Rub (ABHR)</h2>
<p>ABHR is the preferred method when hands are not visibly soiled. Apply enough product to cover all surfaces. Rub hands together — including between fingers, backs of hands, and thumbs — for 20–30 seconds until hands are dry. Do NOT rinse off.</p>
<h2>Soap & Water</h2>
<p>Soap and water is required when hands are visibly dirty or soiled, after using the restroom, when caring for a patient with <em>C. difficile</em> (alcohol is not effective against spores), and when handling food. Wet hands → apply soap → scrub all surfaces for at least 20 seconds → rinse → dry with a single-use towel → use the towel to turn off the tap.</p>`,
          summary: 'Apply the WHO Five Moments framework and choose correctly between ABHR and soap-and-water hand hygiene.',
          learning_objectives: ['Identify the five mandatory moments for hand hygiene', 'Perform correct ABHR technique', 'Know when soap and water is required over ABHR'],
          questions: [
            { question: 'According to the WHO Five Moments, hand hygiene is required BEFORE which of the following?', options: ['Leaving the patient room', 'Touching patient surroundings after patient care', 'Performing a clean or aseptic procedure', 'Removing your gloves'], correct: 2, explanation: 'Moment 2 specifically requires hand hygiene before a clean or aseptic procedure to protect the patient from contamination.' },
            { question: 'When caring for a patient with Clostridioides difficile (C. diff), you should:', options: ['Use ABHR — it is effective against all pathogens', 'Use soap and water, because ABHR does not eliminate C. diff spores', 'Skip hand hygiene if wearing gloves', 'Use ABHR after removing gloves, then soap and water at the door'], correct: 1, explanation: 'C. diff produces spores that are resistant to alcohol. Only soap and water physically removes spores from the hands.' },
            { question: 'After applying ABHR, when should you rinse your hands with water?', options: ['After 15 seconds of rubbing', 'You should not rinse — rub until completely dry', 'Only if your skin feels irritated', 'Immediately, to avoid skin dryness'], correct: 1, explanation: 'ABHR must not be rinsed off. The rubbing action activates the alcohol and it must remain until fully dry to be effective.' },
          ]
        },
        {
          title: 'Isolation Precautions',
          content: `<h2>Standard Precautions</h2>
<p>Standard Precautions apply to <em>every patient, every time</em>, regardless of diagnosis. They are based on the assumption that all blood, body fluids (except sweat), non-intact skin, and mucous membranes may contain transmissible pathogens. Standard Precautions include: hand hygiene, appropriate PPE, safe injection practices, respiratory hygiene/cough etiquette, and safe handling of potentially contaminated equipment or surfaces.</p>
<h2>Transmission-Based Precautions</h2>
<p>For patients known or suspected to have specific infectious conditions, additional precautions are layered on top of Standard Precautions:</p>
<ul>
<li><strong>Contact Precautions</strong> — gown and gloves for all room entry. Single-patient room preferred. Example: MRSA, VRE, C. diff.</li>
<li><strong>Droplet Precautions</strong> — surgical mask when within 3 feet of patient. Example: influenza, pertussis, meningococcal disease.</li>
<li><strong>Airborne Precautions</strong> — N95 respirator (fit-tested), negative pressure room required. Example: tuberculosis, measles, varicella.</li>
</ul>
<h2>Signage & Communication</h2>
<p>Isolation precaution signs must be posted at the patient's door before you enter. The sign tells you exactly which PPE to don. Patients and families should be educated about the reason for isolation and the precautions staff will take—transparent communication reduces anxiety and promotes cooperation.</p>`,
          summary: 'Apply standard precautions to all patients and add transmission-based precautions when indicated.',
          learning_objectives: ['Define Standard Precautions and when they apply', 'Select the correct precaution level (Contact, Droplet, Airborne)', 'Use isolation signage correctly before entering a room'],
          questions: [
            { question: 'Standard Precautions apply to:', options: ['Only patients with confirmed infectious diagnoses', 'Every patient, every time, regardless of diagnosis', 'Only patients in isolation rooms', 'Patients who have been in the facility for more than 48 hours'], correct: 1, explanation: 'Standard Precautions assume all body fluids may be infectious and are applied universally to protect both staff and patients.' },
            { question: 'A patient is admitted with suspected pulmonary tuberculosis. Which precaution level is required?', options: ['Standard Precautions only', 'Contact Precautions', 'Droplet Precautions', 'Airborne Precautions in a negative pressure room'], correct: 3, explanation: 'Tuberculosis is airborne (small particle). It requires a fit-tested N95 respirator and a negative pressure room.' },
            { question: 'You see a Contact Precautions sign on a patient\'s door. Before entering, you should:', options: ['Enter and don PPE from supplies inside the room', 'Don gown and gloves BEFORE entering the room', 'Don only gloves — a gown is optional for brief visits', 'Check with a supervisor before every entry'], correct: 1, explanation: 'PPE must be donned before entering a Contact Precautions room to prevent bringing pathogens in or carrying them out.' },
          ]
        }
      ]
    }
  ]

  const courseIds = {}

  for (const course of courses) {
    const now = daysAgo(rand(35, 40))
    await exec(
      `INSERT OR IGNORE INTO courses (id, icon, title, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
      [course.id, course.icon, course.title, course.description, now, now]
    )

    let moduleOrder = 0
    for (const mod of course.modules) {
      const modId = uid()
      const modNow = daysAgo(rand(35, 40))
      await exec(
        `INSERT INTO modules (id, course_id, title, content, summary, learning_objectives, sort_order, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [modId, course.id, mod.title, mod.content, mod.summary,
         JSON.stringify(mod.learning_objectives), moduleOrder++, modNow, modNow]
      )

      let qOrder = 0
      for (const q of mod.questions) {
        const qId = uid()
        await exec(
          `INSERT INTO questions (id, module_id, question, option_a, option_b, option_c, option_d, correct_index, explanation, sort_order, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [qId, modId, q.question, q.options[0], q.options[1], q.options[2], q.options[3],
           q.correct, q.explanation, qOrder++, modNow, modNow]
        )
      }
    }

    courseIds[course.title] = course.id
    console.log(`   ✓ ${course.icon} ${course.title} (${course.modules.length} modules)`)
  }

  return { courses, courseIds }
}

// ── Assignments & Completions ─────────────────────────────────────────────────

async function seedAssignmentsAndCompletions(userIds, courses) {
  console.log('\n📋 Seeding assignments & completions...')

  const learners = [
    // Patient Services — courses 0,1,2 assigned; 3 only to some
    { name: 'alex.rivera',    courses: [0,1,2,3], daysAgoJoined: 35 },
    { name: 'jordan.kim',     courses: [0,1,2],   daysAgoJoined: 33 },
    { name: 'taylor.brooks',  courses: [0,1,2,3], daysAgoJoined: 30 },
    { name: 'sam.patel',      courses: [0,1,2],   daysAgoJoined: 28 },
    { name: 'casey.morgan',   courses: [0,1],     daysAgoJoined: 14 },
    // Facilities & Operations — courses 0,2,3 assigned; 1 only to some
    { name: 'blake.thompson', courses: [0,2,3],   daysAgoJoined: 34 },
    { name: 'drew.martinez',  courses: [0,2,3,1], daysAgoJoined: 31 },
    { name: 'quinn.foster',   courses: [0,2,3],   daysAgoJoined: 25 },
    { name: 'avery.wilson',   courses: [0,2],     daysAgoJoined: 20 },
    { name: 'riley.hayes',    courses: [0],       daysAgoJoined: 7  },
  ]

  const outcomes = {
    'alex.rivera':    { 0: 'pass',     1: 'pass',     2: 'pass',     3: 'pass'     },
    'jordan.kim':     { 0: 'pass',     1: 'pass',     2: 'pass'                    },
    'taylor.brooks':  { 0: 'pass',     1: 'fail',     2: 'progress', 3: null       },
    'sam.patel':      { 0: 'pass',     1: 'pass',     2: 'fail'                    },
    'casey.morgan':   { 0: 'pass',     1: 'progress'                               },
    'blake.thompson': { 0: 'pass',     2: 'pass',     3: 'pass'                    },
    'drew.martinez':  { 0: 'pass',     2: 'pass',     3: 'fail',     1: null       },
    'quinn.foster':   { 0: 'progress', 2: null,       3: null                      },
    'avery.wilson':   { 0: null,       2: null                                      },
    'riley.hayes':    { 0: null                                                      },
  }

  // Fetch module IDs once (needed for module_progress)
  const modRes = await exec('SELECT id, course_id FROM modules ORDER BY sort_order')
  const firstModByCourse = {}
  for (const row of modRes.rows) {
    const [modId, courseId] = [row[0], row[1]]
    if (!firstModByCourse[courseId]) firstModByCourse[courseId] = modId
  }

  // Build all statements first, then execute in one transaction
  const stmts = []
  let assignCount = 0
  let compCount   = 0

  for (const learner of learners) {
    const lid = userIds[learner.name]
    if (!lid) continue

    for (const ci of learner.courses) {
      const cid        = courses[ci].id
      const assignedAt = new Date(daysAgo(learner.daysAgoJoined - rand(0, 2)) * 1000)
        .toISOString().replace('T', ' ').slice(0, 19)
      const dueAt = ci < 2 ? null
        : new Date(new Date(assignedAt).getTime() + 14 * 86400 * 1000)
            .toISOString().slice(0, 10)

      stmts.push({
        sql:  `INSERT OR IGNORE INTO assignments (course_id, learner_id, assigned_at, due_at) VALUES (?, ?, ?, ?)`,
        args: [cid, lid, assignedAt, dueAt]
      })
      assignCount++

      const outcome = outcomes[learner.name]?.[ci]
      if (!outcome) continue

      if (outcome === 'pass' || outcome === 'fail') {
        const passed      = outcome === 'pass'
        const score       = passed ? rand(80, 100) : rand(55, 78)
        const completedAt = daysAgo(rand(2, learner.daysAgoJoined - 5))
        stmts.push({
          sql:  `INSERT OR IGNORE INTO completions (id, course_id, learner_id, learner_name, score, passed, cert_id, completed_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          args: [uid(), cid, lid, learner.name, score, passed ? 1 : 0, certId(), completedAt, completedAt]
        })
        compCount++
      } else if (outcome === 'progress') {
        const modId = firstModByCourse[cid]
        if (modId) {
          const progAt = daysAgo(rand(1, 4))
          stmts.push({
            sql:  `INSERT OR IGNORE INTO module_progress (id, learner_id, module_id, course_id, passed, score, completed_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            args: [uid(), lid, modId, cid, 1, rand(80, 100), progAt, progAt, progAt]
          })
        }
      }
    }
  }

  // Execute all as a single write transaction so FK refs are resolved together
  await db.batch(stmts, 'write')

  console.log(`   ✓ ${assignCount} assignments created`)
  console.log(`   ✓ ${compCount} completions recorded`)
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  console.log('\n╔══════════════════════════════════════════╗')
  console.log('║   TrainingFlow — Demo Seed Script        ║')
  console.log('╚══════════════════════════════════════════╝')

  try {
    if (RESET_COURSES) { await resetCourses(); await resetData() }
    else if (RESET)    { await resetData() }

    console.log('\n⏳ Hashing passwords (this takes ~3s per hash)...')
    const hash = await hashPassword('demo1234')
    console.log('   ✓ Password hash generated')

    await seedBrand()
    await seedAdmin(hash)
    const teams   = await seedTeams()
    const userIds = await seedUsers(teams, hash)

    let courses
    if (SKIP_COURSES) {
      // Use whatever courses already exist in the DB
      const res = await exec('SELECT id, title, icon FROM courses')
      courses = res.rows.map(r => ({ id: r[0], title: r[1], icon: r[2] }))
      console.log(`\n📚 Using ${courses.length} existing courses`)
    } else {
      ;({ courses } = await seedCourses())
    }

    await seedAssignmentsAndCompletions(userIds, courses)

    console.log('\n✅ Demo seed complete!\n')
    console.log('────────────────────────────────────────────')
    console.log('Demo credentials (password: demo1234)')
    console.log('  Admin:    (no username, password only)')
    console.log('  Managers: sarah.chen  |  marcus.johnson')
    console.log('  Learners: alex.rivera, jordan.kim, taylor.brooks,')
    console.log('            sam.patel, casey.morgan, blake.thompson,')
    console.log('            drew.martinez, quinn.foster, avery.wilson,')
    console.log('            riley.hayes')
    console.log('────────────────────────────────────────────\n')

  } catch (err) {
    console.error('\n❌ Seed failed:', err.message)
    if (err.stack) console.error(err.stack)
    process.exit(1)
  }
}

main()
