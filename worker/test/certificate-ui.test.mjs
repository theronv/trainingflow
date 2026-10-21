import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

// js/certificate.js is a browser global script; its pure helpers run without a DOM.
const src = readFileSync(fileURLToPath(new URL('../../js/certificate.js', import.meta.url)), 'utf8')
const Certificate = new Function(src + '\nreturn Certificate;')()

describe('verify links', () => {
  it('builds a hash link on the app URL', () => {
    expect(Certificate.verifyUrl('PG-0A1B2C3D', 'https://x.test/trainingflow/')).toBe('https://x.test/trainingflow/#/verify/PG-0A1B2C3D')
  })
  it('reads the id back from a location hash and rejects anything else', () => {
    expect(Certificate.idFromHash('#/verify/PG-0A1B2C3D')).toBe('PG-0A1B2C3D')
    expect(Certificate.idFromHash('#/verify/')).toBeNull()
    expect(Certificate.idFromHash('#/verify/a b')).toBeNull()
    expect(Certificate.idFromHash('#invite=ABC')).toBeNull()
    expect(Certificate.idFromHash('')).toBeNull()
  })
})

describe('pdfText', () => {
  it('keeps Latin-1, folds typographic punctuation, and never emits characters a PDF font cannot draw', () => {
    expect(Certificate.pdfText('Zoë O’Brien – “Safety”')).toBe('Zoë O\'Brien - "Safety"')
    expect(Certificate.pdfText('山田')).toBe('??')
    expect(Certificate.pdfText(null)).toBe('')
  })
})

describe('needsImage', () => {
  it('flags text the standard PDF fonts cannot draw', () => {
    expect(Certificate.needsImage('Zoë O’Brien')).toBe(false)
    expect(Certificate.needsImage('Łukasz')).toBe(true)
    expect(Certificate.needsImage('李雷')).toBe(true)
    expect(Certificate.needsImage('Nguyễn')).toBe(true)
  })
  it('does not let C1 control characters through as printable', () => {
    expect(Certificate.pdfText('a\u0085b')).toBe('a?b')
  })
})

describe('fileName', () => {
  it('slugs the course and learner', () => {
    expect(Certificate.fileName({ course: 'Customer Service: Excellence!', name: 'Jamie Lee' })).toBe('Certificate_Customer_Service_Excellence_Jamie_Lee.pdf')
    expect(Certificate.fileName({ course: '!!!', name: '' })).toBe('Certificate_Course_Learner.pdf')
  })
})

describe('linkedInUrl', () => {
  it('pre-fills the Add to profile form with the course, issuer, date and verify link', () => {
    const url = new URL(Certificate.linkedInUrl({
      course: 'Safety 101', org: 'Acme & Co', certId: 'PG-1', verifyUrl: 'https://x.test/#/verify/PG-1', at: new Date(2026, 9, 20).getTime(),
    }))
    expect(url.origin + url.pathname).toBe('https://www.linkedin.com/profile/add')
    expect(Object.fromEntries(url.searchParams)).toEqual({
      startTask: 'CERTIFICATION_NAME', name: 'Safety 101', organizationName: 'Acme & Co',
      issueYear: '2026', issueMonth: '10', certUrl: 'https://x.test/#/verify/PG-1', certId: 'PG-1',
    })
  })
})

describe('rgb', () => {
  it('parses hex and falls back when malformed', () => {
    expect(Certificate.toRgb('#1565ff')).toEqual([21, 101, 255])
    expect(Certificate.toRgb('nope', [1, 2, 3])).toEqual([1, 2, 3])
  })
})

describe('qrSvg', () => {
  it('draws one square per dark module inside a quiet zone', () => {
    const svg = Certificate.qrSvg([[true, false], [false, true]])
    expect(svg).toContain('viewBox="0 0 6 6"')
    expect(svg).toContain('M2 2h1v1h-1z')
    expect(svg).toContain('M3 3h1v1h-1z')
    expect(svg).not.toContain('M3 2')
  })
})
