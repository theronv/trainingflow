import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

// js/learner.js is a browser global script; evaluate it with a stub `document` so its
// top-level listeners register harmlessly and the pure helpers can be tested.
const src = readFileSync(fileURLToPath(new URL('../../js/learner.js', import.meta.url)), 'utf8')
const document = { addEventListener() {}, getElementById: () => null }
const Learner = new Function('document', src + '\nreturn Learner;')(document)

describe('isSourceLinkVisible', () => {
  it('hides support.synergysports.com links, including subdomains and any case', () => {
    expect(Learner.isSourceLinkVisible('https://support.synergysports.com/support/solutions/articles/77000565399')).toBe(false)
    expect(Learner.isSourceLinkVisible('HTTPS://Support.SynergySports.com/a')).toBe(false)
    expect(Learner.isSourceLinkVisible('https://eu.support.synergysports.com/a')).toBe(false)
  })
  it('shows other links, including lookalike hosts', () => {
    expect(Learner.isSourceLinkVisible('https://docs.example.com/page')).toBe(true)
    expect(Learner.isSourceLinkVisible('https://www.synergysports.com/')).toBe(true)
    expect(Learner.isSourceLinkVisible('https://notsupport.synergysports.com.evil.test/')).toBe(true)
    expect(Learner.isSourceLinkVisible('https://evilsupport.synergysports.com/')).toBe(true)
  })
  it('shows nothing for an empty link and tolerates unparseable ones', () => {
    expect(Learner.isSourceLinkVisible('')).toBe(false)
    expect(Learner.isSourceLinkVisible(null)).toBe(false)
    expect(Learner.isSourceLinkVisible('not a url')).toBe(true)
  })
})
