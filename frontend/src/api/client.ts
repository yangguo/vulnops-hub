import type {
  AllowedTransitionsResponse,
  CaseCreateRequest,
  CaseCreateResponse,
  CaseDetail,
  CaseListResponse,
  RiskApprovalRequest,
  RiskApprovalResponse,
  RiskDecisionCreateResponse,
  RiskDecisionRequest,
  RiskDecisionsResponse,
  SbomResponse,
  SbomSubmitResponse,
  TransitionResponse,
  VerificationSubmitResponse,
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

export type AccessTokenProvider = () => string | null | Promise<string | null>
export type UnauthorizedHandler = (error: ApiError) => void

export interface ApiClientConfig {
  getAccessToken?: AccessTokenProvider
  onUnauthorized?: UnauthorizedHandler
}

const noAccessToken: AccessTokenProvider = () => null
let accessTokenProvider: AccessTokenProvider = noAccessToken
let unauthorizedHandler: UnauthorizedHandler | undefined

/** Configure request-time auth without storing access or refresh tokens. */
export function configureApiClient(config: ApiClientConfig = {}): void {
  accessTokenProvider = config.getAccessToken ?? noAccessToken
  unauthorizedHandler = config.onUnauthorized
}

interface RequestContext {
  accessTokenProvider: AccessTokenProvider
  unauthorizedHandler?: UnauthorizedHandler
}

async function authenticatedInit(init: RequestInit, provider: AccessTokenProvider): Promise<RequestInit> {
  const token = await provider()
  const headers = new Headers(init.headers)
  for (const name of headers.keys()) {
    if (name.toLowerCase() === 'authorization') headers.delete(name)
  }
  if (typeof token === 'string' && token.trim()) {
    headers.set('Authorization', `Bearer ${token.trim()}`)
  }
  return { ...init, headers }
}

async function request<T>(
  path: string,
  init: RequestInit = {},
  allowRetry = true,
  context?: RequestContext,
): Promise<T> {
  const requestContext =
    context ?? { accessTokenProvider, unauthorizedHandler }
  let resp: Response
  try {
    resp = await fetch(path, await authenticatedInit(init, requestContext.accessTokenProvider))
  } catch {
    if (allowRetry) return request<T>(path, init, false, requestContext)
    throw new ApiError(0, 'network_error', '无法连接服务器，请检查后端是否运行')
  }
  if (resp.status === 204) return undefined as T
  const body = resp.headers.get('content-type')?.includes('json')
    ? await resp.json().catch(() => null)
    : null
  if (!resp.ok) {
    const raw = body && (body.detail ?? body.title)
    const nested = typeof raw === 'object' && raw !== null ? (raw as Record<string, unknown>) : null
    const fallback =
      resp.status === 401
        ? { code: 'authentication_required', message: 'Authentication required' }
        : { code: 'error', message: resp.statusText || 'Request failed' }
    const message =
      nested != null
        ? String(nested.detail ?? nested.title ?? JSON.stringify(nested))
        : typeof raw === 'string' && raw
          ? raw
          : fallback.message
    const code = body?.code ?? (nested?.code as string | undefined) ?? fallback.code
    const error = new ApiError(resp.status, code, message)
    if (resp.status === 401) requestContext.unauthorizedHandler?.(error)
    throw error
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
  createCase(org: string, payload: CaseCreateRequest): Promise<CaseCreateResponse> {
    return request(
      `/api/v1/organizations/${org}/cases`,
      jsonInit('POST', payload),
    )
  },
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
    reason?: string,
  ): Promise<TransitionResponse> {
    return request(
      `/api/v1/organizations/${org}/cases/${caseId}/transitions`,
      jsonInit('POST', { target, reason }, { 'If-Match': `"${version}"` }),
    )
  },
  createRiskDecision(org: string, caseId: string, payload: RiskDecisionRequest): Promise<RiskDecisionCreateResponse> {
    return request(
      `/api/v1/organizations/${org}/cases/${caseId}/risk-decisions`,
      jsonInit('POST', payload),
    )
  },
  approveRiskDecision(
    org: string,
    caseId: string,
    decisionId: string,
    payload: RiskApprovalRequest,
  ): Promise<RiskApprovalResponse> {
    return request(
      `/api/v1/organizations/${org}/cases/${caseId}/risk-decisions/${decisionId}/approval`,
      jsonInit('POST', payload),
    )
  },
  listRiskDecisions(org: string, caseId: string): Promise<RiskDecisionsResponse> {
    return request(`/api/v1/organizations/${org}/cases/${caseId}/risk-decisions`)
  },
  submitVerification(org: string, caseId: string, payload: Record<string, unknown>): Promise<VerificationSubmitResponse> {
    return request(
      `/api/v1/organizations/${org}/cases/${caseId}/verifications`,
      jsonInit('POST', payload),
    )
  },
  listVerifications(org: string, caseId: string): Promise<VerificationsResponse> {
    return request(`/api/v1/organizations/${org}/cases/${caseId}/verifications`)
  },
  submitSbom(org: string, body: unknown, idempotencyKey: string): Promise<SbomSubmitResponse> {
    return request(
      `/api/v1/organizations/${org}/sboms`,
      jsonInit('POST', body, { 'Idempotency-Key': idempotencyKey }),
    )
  },
  getSbom(org: string, sbomId: string): Promise<SbomResponse> {
    return request(`/api/v1/organizations/${org}/sboms/${sbomId}`)
  },
  getHealthLive(): Promise<{ service: string; version: string }> {
    return request('/health/live')
  },
}
