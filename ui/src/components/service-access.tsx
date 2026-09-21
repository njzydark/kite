import { useState, type ReactNode } from 'react'
import { useAuth } from '@/contexts/auth-context'
import { IconExternalLink } from '@tabler/icons-react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'

import { apiClient } from '@/lib/api-client'
import {
  getCurrentCluster,
  withCurrentClusterPath,
} from '@/lib/current-cluster'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

interface AccessSession {
  id: string
  namespace: string
  kind: string
  name: string
  port: number
  scheme: string
  expiresAt: string
}

export function ServiceAccess({
  namespace,
  kind,
  name,
  port,
  protocol,
  legacyHref,
  children,
}: {
  namespace?: string
  kind: 'services' | 'pods'
  name: string
  port: number
  protocol?: string
  legacyHref: string
  children: ReactNode
}) {
  const { t } = useTranslation()
  const { capabilities } = useAuth()
  const queryClient = useQueryClient()
  const [open, setOpen] = useState(false)
  const [scheme, setScheme] = useState('http')
  const [path, setPath] = useState('/')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const cluster = getCurrentCluster()
  const endpoint = withCurrentClusterPath('/service-access/sessions', cluster)
  const queryKey = ['service-access', cluster]
  const sessions = useQuery({
    queryKey,
    queryFn: () => apiClient.get<AccessSession[]>(endpoint),
    enabled: open && !!capabilities.serviceAccessEnabled && !!cluster,
    refetchInterval: open ? 15000 : false,
  })
  const matching = (sessions.data ?? []).filter(
    (session) =>
      session.namespace === namespace &&
      session.kind === kind &&
      session.name === name &&
      session.port === port
  )
  const linkClass =
    'app-link inline-flex min-w-0 items-center gap-1 font-mono tabular-nums'
  const label = (
    <>
      <span className="truncate">{children}</span>
      <IconExternalLink className="size-3 shrink-0" />
    </>
  )

  if (protocol && protocol !== 'TCP')
    return <span className="font-mono">{children}</span>
  if (!capabilities.serviceAccessEnabled)
    return (
      <a
        href={legacyHref}
        target="_blank"
        rel="noopener noreferrer"
        className={linkClass}
      >
        {label}
      </a>
    )

  const launch = async () => {
    if (!namespace || !cluster) return
    const popup = window.open('about:blank', '_blank')
    if (!popup) {
      setError(t('serviceAccess.popupBlocked'))
      return
    }
    popup.opener = null
    setBusy(true)
    setError('')
    try {
      const result = await apiClient.post<{ url: string }>(endpoint, {
        namespace,
        kind,
        name,
        port,
        scheme,
        path,
      })
      popup.location.replace(result.url)
      await queryClient.invalidateQueries({ queryKey })
    } catch (error) {
      popup.close()
      setError(
        error instanceof Error ? error.message : t('serviceAccess.failed')
      )
    } finally {
      setBusy(false)
    }
  }
  const close = async (id: string) => {
    setBusy(true)
    setError('')
    try {
      await apiClient.delete(`${endpoint}/${encodeURIComponent(id)}`)
      await queryClient.invalidateQueries({ queryKey })
    } catch (error) {
      setError(
        error instanceof Error ? error.message : t('serviceAccess.failed')
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <button
          type="button"
          className={linkClass}
          title={t('serviceAccess.title')}
          disabled={!namespace || !cluster}
        >
          {label}
        </button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('serviceAccess.title')}</DialogTitle>
          <DialogDescription>
            {t('serviceAccess.description')}
          </DialogDescription>
        </DialogHeader>
        <p className="truncate text-sm font-mono">
          {namespace}/{name}:{port}
        </p>
        <div className="space-y-2">
          <Label htmlFor="service-access-protocol">
            {t('serviceAccess.protocol')}
          </Label>
          <Select value={scheme} onValueChange={setScheme}>
            <SelectTrigger id="service-access-protocol">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="http">HTTP</SelectItem>
              <SelectItem value="https">HTTPS</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-2">
          <Label htmlFor="service-access-path">{t('serviceAccess.path')}</Label>
          <Input
            id="service-access-path"
            value={path}
            onChange={(event) => setPath(event.target.value)}
            placeholder="/"
          />
        </div>
        <Button disabled={busy} onClick={launch}>
          <IconExternalLink className="size-4" />
          {t('serviceAccess.open')}
        </Button>
        {matching.map((session) => (
          <div
            key={session.id}
            className="flex items-center justify-between gap-3 text-sm"
          >
            <span>
              {session.scheme.toUpperCase()} ·{' '}
              {t('serviceAccess.expires', {
                time: new Date(session.expiresAt).toLocaleTimeString(),
              })}
            </span>
            <Button
              variant="outline"
              size="sm"
              disabled={busy}
              onClick={() => close(session.id)}
            >
              {t('serviceAccess.close')}
            </Button>
          </div>
        ))}
        <p className="text-xs text-muted-foreground">
          {t('serviceAccess.lifetime')}
        </p>
        {(error || sessions.isError) && (
          <p role="alert" className="text-sm text-destructive">
            {error || t('serviceAccess.failed')}
          </p>
        )}
      </DialogContent>
    </Dialog>
  )
}
