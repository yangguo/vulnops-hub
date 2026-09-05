import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import CaseActionBar from './CaseActionBar.vue'
import { useCaseDetailStore } from '../stores/caseDetail'

describe('CaseActionBar', () => {
  it('renders exactly one button per allowed transition', () => {
    setActivePinia(createPinia())
    const store = useCaseDetailStore()
    store.allowed = ['assigned', 'risk_accepted', 'not_applicable']
    const w = mount(CaseActionBar)
    const buttons = w.findAll('button.el-button').filter((b) => !b.attributes('disabled'))
    expect(buttons.map((b) => b.text())).toEqual(['流转到 已分派', '接受风险…', '标记不适用…'])
  })

  it('renders nothing when no transitions allowed', () => {
    setActivePinia(createPinia())
    useCaseDetailStore().allowed = []
    const w = mount(CaseActionBar)
    expect(w.findAll('button.el-button')).toHaveLength(0)
  })
})
