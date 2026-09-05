import type { components } from './schema'

// Extract the JSON body of a typed response operation from the generated schema.
// Note: get_case / transitions / allowed-transitions are not $ref'd in openapi.yaml
// (schema: {}), so those shapes come from components or the backend handlers directly.
export type CaseDetail = components['schemas']['CaseDetailResponse']
export type TransitionResponse = {
  id: string
  status: string
  version: number
  etag: string
}
export type AllowedTransitionsResponse = {
  case_id: string
  status: string
  allowed: string[]
  current: string
}

export interface CaseListResponse {
  items: CaseDetail[]
  total: number
  page: number
  page_size: number
}
export interface RiskDecisionItem {
  id: string
  case_id: string
  type: string
  status: string
  scope_exposure_ids: string[]
  reason: string
  compensating_controls: string[]
  evidence_ids: string[]
  requested_by: string
  approver: string | null
  approver_role: string | null
  expires_at: string | null
  created_at: string | null
}
export interface VerificationItem {
  id: string
  case_id: string
  method: string
  asserted_result: string | null
  evidence_ids: string[]
  coverage: Record<string, unknown>
  status: string
  created_at: string | null
}
export interface RiskDecisionsResponse { items: RiskDecisionItem[] }
export interface VerificationsResponse { items: VerificationItem[] }
