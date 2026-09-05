import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import SlaBadge from './SlaBadge.vue'

describe('SlaBadge', () => {
  it('renders remaining time for future due dates', () => {
    const due = new Date(Date.now() + 2 * 24 * 3600 * 1000).toISOString()
    const w = mount(SlaBadge, { props: { dueAt: due, breached: false } })
    expect(w.text()).toContain('剩')
    expect(w.classes()).not.toContain('sla-breached')
  })

  it('renders breached state in red', () => {
    const w = mount(SlaBadge, { props: { dueAt: new Date(Date.now() - 1000).toISOString(), breached: true } })
    expect(w.text()).toContain('已超时')
    expect(w.classes()).toContain('sla-breached')
  })

  it('renders overdue state even when breached flag has not caught up', () => {
    const past = new Date(Date.now() - 3600 * 1000).toISOString()
    const w = mount(SlaBadge, { props: { dueAt: past, breached: false } })
    expect(w.text()).toContain('已超时')
    expect(w.text()).not.toContain('剩 ')
  })
})
