#!/usr/bin/env node
// Convert Pregame's academy.json into one course.json per path, in the format the
// AI Importer's "Import a course from Claude (JSON)" box accepts.
// Usage: node scripts/pregame-to-course.mjs <academy.json> [outDir]
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

const [src, outDir = 'pregame-courses'] = process.argv.slice(2);
if (!src) { console.error('Usage: node scripts/pregame-to-course.mjs <academy.json> [outDir]'); process.exit(1); }

const ICONS = { orientation: '🧭', foundations: '🏟️', football: '🏈', hockey: '🏒', 'baseball-softball': '⚾', basketball: '🏀', 'support-craft': '🤝' };
const academy = JSON.parse(readFileSync(src, 'utf8'));
mkdirSync(outDir, { recursive: true });

for (const p of academy.paths) {
  const course = {
    title: p.title,
    icon: ICONS[p.id] || '📘',
    description: String(p.blurb || '').slice(0, 300),
    modules: p.modules.map(m => ({
      title: m.title,
      summary: (m.objectives?.[0] || '').slice(0, 200),
      learning_objectives: m.objectives || [],
      content: (Array.isArray(m.body) ? m.body.join('\n') : String(m.body || '')).trim(),
      questions: (m.questions || []).map(q => ({
        question: q.q, options: q.o, correct_index: q.a, explanation: q.w || ''
      }))
    }))
  };
  const file = join(outDir, `${p.id}.json`);
  writeFileSync(file, JSON.stringify(course));
  const qs = course.modules.reduce((n, m) => n + m.questions.length, 0);
  const bad = course.modules.flatMap(m => m.questions).filter(q => q.options.length !== 4).length;
  console.log(`${file}: ${course.modules.length} modules, ${qs} questions${bad ? `, ${bad} without exactly 4 options` : ''}`);
}
