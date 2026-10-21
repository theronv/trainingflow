import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

// js/core.js touches the DOM on load, so evaluate only the course-icon block.
const core = readFileSync(fileURLToPath(new URL('../../js/core.js', import.meta.url)), 'utf8')
const block = core.slice(core.indexOf('const COURSE_ICONS = {'), core.indexOf('function uid()'))
const { COURSE_ICONS, COURSE_ICON_CHOICES, courseIconName, courseIcon } =
  new Function(`${block}\nreturn { COURSE_ICONS, COURSE_ICON_CHOICES, courseIconName, courseIcon };`)()

describe('course icons', () => {
  it('offers every icon once, each with an emoji that maps back to itself', () => {
    expect(COURSE_ICON_CHOICES.map(c => c.name).sort()).toEqual(Object.keys(COURSE_ICONS).sort())
    for (const { name, emoji } of COURSE_ICON_CHOICES) expect(courseIconName(emoji)).toBe(name)
  })
  it('falls back to the cap for empty or unknown values', () => {
    expect(courseIconName('')).toBe('cap')
    expect(courseIconName(undefined)).toBe('cap')
    expect(courseIconName('🦄')).toBe('cap')
  })
  it('resolves emoji variants to the same icon', () => {
    expect(courseIconName('⚾')).toBe('activity')
    expect(courseIconName('🥎')).toBe('activity')
    expect(courseIconName('📞')).toBe('phone')
    expect(courseIcon('📞')).toContain(COURSE_ICONS.phone)
  })
})
