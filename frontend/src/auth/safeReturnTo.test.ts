import { describe, expect, it } from 'vitest'
import { returnToFromState, safeReturnTo } from './safeReturnTo'

describe('safeReturnTo', () => {
  it('accepts same-origin relative paths with query and hash', () => {
    expect(safeReturnTo('/cases/c1')).toBe('/cases/c1')
    expect(safeReturnTo('/cases?tab=open#row')).toBe('/cases?tab=open#row')
  })

  it('rejects absolute, scheme-relative, and non-path values', () => {
    expect(safeReturnTo('https://evil.example/phish')).toBe('/')
    expect(safeReturnTo('http://evil.example/phish')).toBe('/')
    expect(safeReturnTo('//evil.example/phish')).toBe('/')
    expect(safeReturnTo('javascript:alert(1)')).toBe('/')
    expect(safeReturnTo('cases/c1')).toBe('/')
    expect(safeReturnTo('')).toBe('/')
    expect(safeReturnTo(null)).toBe('/')
    expect(safeReturnTo(['/cases'])).toBe('/')
  })
})

describe('returnToFromState', () => {
  it('returns null for missing or unsafe returnTo values', () => {
    expect(returnToFromState(undefined)).toBeNull()
    expect(returnToFromState({ returnTo: '//evil.example' })).toBeNull()
    expect(returnToFromState({ returnTo: 'https://evil.example' })).toBeNull()
    expect(returnToFromState({ returnTo: 12 })).toBeNull()
  })

  it('returns a sanitized same-origin path', () => {
    expect(returnToFromState({ returnTo: '/cases/c1' })).toBe('/cases/c1')
  })
})
