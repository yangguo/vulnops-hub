import type {
  AllowedTransitionsResponse,
  CaseDetail,
  CaseListResponse,
  RiskDecisionItem,
  RiskDecisionsResponse,
  TransitionResponse,
  VerificationItem,
  VerificationsResponse,
} from './types'

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message)
  }
}

async function request<T>(path: string, init: RequestInit = {}, allowRetry = true): Promise<T> {
  let resp: Response
  try {
    resp = await fetch(path, init)
  } catch {
    if (allowRetry) return request<T>(path, init, false)
    throw new ApiError(0, 'network_error', '无法连接服务器，请检查后端是否运行')
  }
  if (resp.status === 204) return undefined as T
  const body = resp.headers.get('content-type')?.includes('json')
    ? await resp.json().catch(() => null)
    : null
  if (!resp.ok) {
    const raw = body && (body.detail ?? body.title)
    const nested = typeof raw === 'object' && raw !== null ? (raw as Record<string, unknown>) : null
    const message =
      nested != null
        ? String(nested.detail ?? nested.title ?? JSON.stringify(nested))
        : typeof raw === 'string' && raw
          ? raw
          : resp.statusText
    const code = body?.code ?? (nested?.code as string | undefined) ?? 'error'
    throw new ApiError(resp.status, code, message)
  }
  return body as T
}

function jsonInit(method: string, payload: unknown, headers: Record<string, string> = {}): RequestInit {
  return {
    method,
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(payload),
  }
}

export const apiClient = {
  listCases(org: string, query = ''): Promise<CaseListResponse> {
    return request(`/api/v1/organizations/${org}/cases${query}`)
  },
  getCase(org: string, caseId: string): Promise<CaseDetail> {
    return request(`/api/v1/organizations/${org}/cases/${caseId}`)
  },
  getAllowed(org: string, caseId: string): Promise<AllowedTransitionsResponse> {
    return request(`/api/v1/organizations/${org}/cases/${caseId}/allowed-transitions`)
  },
  transition(
    org: string,
    caseId: string,
    version: number,
    target: string,
    actor: string,
    reason?: string,
  ): Promise<TransitionResponse> {
    return request(
      `/api/v1/organizations/${org}/cases/${caseId}/transitions`,
      jsonInit('POST', { target, actor, reason }, { 'If-Match': `"${version}"` }),
    )
  },
  createRiskDecision(org: string, caseId: string, payload: Record<string, unknown>): Promise<RiskDecisionItem> {
    return request(
      `/api/v1/organizations/${org}/cases/${caseId}/risk-decisions`,
      jsonInit('POST', payload),
    )
  },
  listRiskDecisions(org: string, caseId: string): Promise<RiskDecisionsResponse> {
    return request(`/api/v1/organizations/${org}/cases/${caseId}/risk-decisions`)
  },
  submitVerification(org: string, caseId: string, payload: Record<string, unknown>): Promise<VerificationItem> {
    return request(
      `/api/v1/organizations/${org}/cases/${caseId}/verifications`,
      jsonInit('POST', payload),
    )
  },
  listVerifications(org: string, caseId: string): Promise<VerificationsResponse> {
    return request(`/api/v1/organizations/${org}/cases/${caseId}/verifications`)
  },
  submitSbom(org: string, body: unknown, idempotencyKey: string): Promise<Record<string, unknown>> {
    return request(
      `/api/v1/organizations/${org}/sboms`,
      jsonInit('POST', body, { 'Idempotency-Key': idempotencyKey }),
    )
  },
  getHealthLive(): Promise<{ service: string; version: string }> {
    return request('/health/live')
  },
}
