import { describe, expect, it, vi, afterEach } from 'vitest'
import { apiClient, configureApiClient } from './client'

afterEach(() => {
  vi.unstubAllGlobals()
  configureApiClient()
})

describe('apiClient error normalization', () => {
  it('maps Problem Details to ApiError', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(new Response(
        JSON.stringify({
          detail: {
            type: 'https://hub.example/problems/invalid-transition',
            title: 'Invalid Transition',
            status: 422,
            code: 'invalid_transition',
            detail: 'transition new -> closed not allowed',
          },
        }),
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

  it('sends If-Match and no client actor field on transition', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ id: 'c1', status: 'triage', version: 2, etag: '"2"' }),
      { status: 200 },
    ))
    vi.stubGlobal('fetch', fetchMock)
    await apiClient.transition('org', 'c1', 1, 'triage', 'r')
    const [, init] = fetchMock.mock.calls[0]
    expect(init.headers['If-Match']).toBe('"1"')
    expect(JSON.parse(init.body)).toEqual({ target: 'triage', reason: 'r' })
    expect(JSON.parse(init.body)).not.toHaveProperty('actor')
  })

  it('injects a token at request time without persisting it', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('{}', { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)
    configureApiClient({ getAccessToken: () => 'access-token' })

    await apiClient.getCase('org', 'c1')

    const [, init] = fetchMock.mock.calls[0]
    expect(init.headers.Authorization).toBe('Bearer access-token')
    expect(localStorage.getItem('access_token')).toBeNull()
  })

  it('normalizes 401 once and does not retry it', async () => {
    const unauthorized = vi.fn()
    const fetchMock = vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ code: 'authentication_required', detail: 'login required' }),
      { status: 401, headers: { 'content-type': 'application/json' } },
    ))
    vi.stubGlobal('fetch', fetchMock)
    configureApiClient({ getAccessToken: () => 'expired-token', onUnauthorized: unauthorized })

    await expect(apiClient.getCase('org', 'c1')).rejects.toMatchObject({
      status: 401,
      code: 'authentication_required',
    })
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(unauthorized).toHaveBeenCalledTimes(1)
    expect(unauthorized).toHaveBeenCalledWith(expect.objectContaining({ status: 401 }))
  })

  it('sends a typed approval request without client identity fields', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ id: 'rd1', case_id: 'c1', status: 'approved' }),
      { status: 200 },
    ))
    vi.stubGlobal('fetch', fetchMock)

    await apiClient.approveRiskDecision('org', 'c1', 'rd1', {
      outcome: 'approve',
      reason: 'reviewed',
    })

    const [, init] = fetchMock.mock.calls[0]
    expect(JSON.parse(init.body)).toEqual({ outcome: 'approve', reason: 'reviewed' })
  })
})
