import { describe, expect, it, vi, afterEach } from 'vitest'
import { apiClient } from './client'

afterEach(() => vi.unstubAllGlobals())

describe('apiClient error normalization', () => {
  it('maps Problem Details to ApiError', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(new Response(
        JSON.stringify({ type: 'x', title: 'Invalid Transition', status: 422, code: 'invalid_transition', detail: 'transition new -> closed not allowed' }),
        { status: 422, headers: { 'content-type': 'application/json' } },
      )),
    )
    await expect(apiClient.getCase('org', 'c1')).rejects.toMatchObject({
      status: 422,
      code: 'invalid_transition',
      message: 'transition new -> closed not allowed',
    })
  })

  it('retries once on network failure then throws network_error', async () => {
    const fetchMock = vi.fn().mockRejectedValue(new TypeError('failed'))
    vi.stubGlobal('fetch', fetchMock)
    await expect(apiClient.getCase('org', 'c1')).rejects.toMatchObject({
      status: 0,
      code: 'network_error',
    })
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('sends If-Match header on transition', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ id: 'c1', status: 'triage', version: 2, etag: '"2"' }),
      { status: 200 },
    ))
    vi.stubGlobal('fetch', fetchMock)
    await apiClient.transition('org', 'c1', 1, 'triage', 'alice', 'r')
    const [, init] = fetchMock.mock.calls[0]
    expect(init.headers['If-Match']).toBe('"1"')
  })
})
