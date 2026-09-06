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
    expect(new Headers(init.headers).get('if-match')).toBe('"1"')
    expect(JSON.parse(init.body)).toEqual({ target: 'triage', reason: 'r' })
    expect(JSON.parse(init.body)).not.toHaveProperty('actor')
  })

  it('injects a token at request time without persisting it', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('{}', { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)
    configureApiClient({ getAccessToken: () => 'access-token' })

    await apiClient.getCase('org', 'c1')

    const [, init] = fetchMock.mock.calls[0]
    expect(new Headers(init.headers).get('authorization')).toBe('Bearer access-token')
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

  it('normalizes a non-JSON 401 with a stable error and no retry', async () => {
    const unauthorized = vi.fn()
    const fetchMock = vi.fn().mockResolvedValue(new Response('', { status: 401, statusText: '' }))
    vi.stubGlobal('fetch', fetchMock)
    configureApiClient({ onUnauthorized: unauthorized })

    await expect(apiClient.getCase('org', 'c1')).rejects.toMatchObject({
      status: 401,
      code: 'authentication_required',
      message: 'Authentication required',
    })
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(unauthorized).toHaveBeenCalledTimes(1)
  })

  it('replaces authorization case-insensitively and omits an empty token', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('{}', { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)
    configureApiClient({ getAccessToken: () => ' access-token ' })

    await apiClient.getCase('org', 'c1')
    const firstInit = fetchMock.mock.calls[0][1]
    const firstHeaders = new Headers(firstInit.headers)
    expect(firstHeaders.get('authorization')).toBe('Bearer access-token')
    expect([...firstHeaders.keys()].filter((key) => key === 'authorization')).toHaveLength(1)

    configureApiClient({ getAccessToken: () => '   ' })
    await apiClient.getCase('org', 'c1')
    const secondInit = fetchMock.mock.calls[1][1]
    expect(new Headers(secondInit.headers).get('authorization')).toBeNull()
  })

  it('snapshots auth provider and unauthorized handler for an in-flight request', async () => {
    let releaseToken!: (token: string) => void
    const tokenReady = new Promise<string>((resolve) => {
      releaseToken = resolve
    })
    const oldUnauthorized = vi.fn()
    const newUnauthorized = vi.fn()
    const fetchMock = vi.fn().mockResolvedValue(new Response('', { status: 401 }))
    vi.stubGlobal('fetch', fetchMock)
    configureApiClient({ getAccessToken: () => tokenReady, onUnauthorized: oldUnauthorized })

    const request = apiClient.getCase('org', 'c1')
    configureApiClient({ getAccessToken: () => 'new-token', onUnauthorized: newUnauthorized })
    releaseToken('old-token')

    await expect(request).rejects.toMatchObject({ status: 401 })
    expect(fetchMock.mock.calls[0][1].headers.get('authorization')).toBe('Bearer old-token')
    expect(oldUnauthorized).toHaveBeenCalledTimes(1)
    expect(newUnauthorized).not.toHaveBeenCalled()
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
