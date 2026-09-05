import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import StatusStepper from './StatusStepper.vue'

describe('StatusStepper', () => {
  it('marks triage as the active step (index 1)', () => {
    const w = mount(StatusStepper, { props: { status: 'triage' } })
    expect(w.findAll('.el-step')).toHaveLength(6)
    expect(w.findComponent({ name: 'ElSteps' }).props('active')).toBe(1)
  })

  it('pins side states to the triage step and shows an alert', () => {
    const w = mount(StatusStepper, { props: { status: 'risk_accepted' } })
    expect(w.find('.el-alert').text()).toContain('风险已接受')
  })
})
