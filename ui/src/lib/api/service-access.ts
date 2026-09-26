import { apiClient } from '@/lib/api-client'
import { withSubPath } from '@/lib/subpath'

export interface ServiceAccessEntry {
  id: string
  cluster: string
  namespace: string
  kind: 'services' | 'pods'
  name: string
  port: number
  scheme: string
  path: string
  hostname: string
  expiresAt: string | null
  expiresInMinutes: number
  public: boolean
  publicUntil: string | null
  authorized: boolean
}

export const serviceAccessQueryKey = ['service-access'] as const

export function listServiceAccess() {
  return apiClient.get<ServiceAccessEntry[]>('/service-access')
}

export function deleteServiceAccess(id: string) {
  return apiClient.delete(`/service-access/${encodeURIComponent(id)}`)
}

export function updateServiceAccess(
  id: string,
  settings: { expiresInMinutes: number; public: boolean }
) {
  return apiClient.put(`/service-access/${encodeURIComponent(id)}`, settings)
}

export function serviceAccessOpenURL(id: string) {
  return withSubPath(`/api/v1/service-access/${encodeURIComponent(id)}/open`)
}
