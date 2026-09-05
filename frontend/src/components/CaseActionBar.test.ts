import { describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { ElMessageBox } from 'element-plus'
import CaseActionBar from './CaseActionBar.vue'
import RiskDecisionDrawer from './RiskDecisionDrawer.vue'
import { useCaseDetailStore } from '../stores/caseDetail'
import { ApiError } from '../api/client'

vi.mock('element-plus', async (importOriginal) => ({
  ...(await importOriginal<typeof import('element-plus')>()),
  ElMessageBox: { confirm: vi.fn() },
  ElMessage: { success: vi.fn(), warning: vi.fn(), error: vi.fn() },
}))

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

  it('resets drawer mode when opening risk acceptance after not-applicable', async () => {
    setActivePinia(createPinia())
    const store = useCaseDetailStore()
    store.allowed = ['not_applicable', 'risk_accepted']
    const w = mount(CaseActionBar)
    const buttons = w.findAll('button.el-button')
    await buttons[0].trigger('click') // 标记不适用…
    await buttons[1].trigger('click') // 接受风险…
    expect(w.findComponent(RiskDecisionDrawer).props('mode')).toBe('risk_accepted')
  })

  it('412 confirm triggers refresh', async () => {
    setActivePinia(createPinia())
    const store = useCaseDetailStore()
    store.detail = { id: 'c1', version: 1, status: 'new' } as never
    store.allowed = ['assigned']
    vi.spyOn(store, 'transition').mockRejectedValueOnce(new ApiError(412, 'conflict', 'conflict'))
    const refreshSpy = vi.spyOn(store, 'refresh').mockResolvedValue(undefined)
    ;(ElMessageBox.confirm as ReturnType<typeof vi.fn>).mockResolvedValueOnce('confirm')
    const w = mount(CaseActionBar)
    await w.find('button.el-button').trigger('click')
    await flushPromises()
    expect(refreshSpy).toHaveBeenCalled()
  })

  it('412 cancel does not refresh', async () => {
    setActivePinia(createPinia())
    const store = useCaseDetailStore()
    store.detail = { id: 'c1', version: 1, status: 'new' } as never
    store.allowed = ['assigned']
    vi.spyOn(store, 'transition').mockRejectedValueOnce(new ApiError(412, 'conflict', 'conflict'))
    const refreshSpy = vi.spyOn(store, 'refresh').mockResolvedValue(undefined)
    ;(ElMessageBox.confirm as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('cancel'))
    const w = mount(CaseActionBar)
    await w.find('button.el-button').trigger('click')
    await flushPromises()
    expect(refreshSpy).not.toHaveBeenCalled()
  })
})
