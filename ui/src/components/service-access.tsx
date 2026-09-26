import { useState, type ReactNode } from 'react'
import { useAuth } from '@/contexts/auth-context'
import { IconExternalLink } from '@tabler/icons-react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'

import { apiClient } from '@/lib/api-client'
import {
  deleteServiceAccess,
  listServiceAccess,
  serviceAccessQueryKey,
  type ServiceAccessEntry,
} from '@/lib/api/service-access'
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
import { Switch } from '@/components/ui/switch'

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
  const { capabilities, user } = useAuth()
  const queryClient = useQueryClient()
  const [open, setOpen] = useState(false)
  const [scheme, setScheme] = useState('http')
  const [schemeEdited, setSchemeEdited] = useState(false)
  const [path, setPath] = useState('/')
  const [pathEdited, setPathEdited] = useState(false)
  const [alias, setAlias] = useState('')
  const [expiresInMinutes, setExpiresInMinutes] = useState('180')
  const [expiryEdited, setExpiryEdited] = useState(false)
  const [isPublic, setIsPublic] = useState(false)
  const [publicEdited, setPublicEdited] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const cluster = getCurrentCluster()
  const endpoint = withCurrentClusterPath('/service-access/sessions', cluster)
  const sessions = useQuery({
    queryKey: serviceAccessQueryKey,
    queryFn: listServiceAccess,
    enabled: open && !!capabilities.serviceAccessEnabled && !!cluster,
    refetchInterval: open ? 15000 : false,
  })
  const matching = (sessions.data ?? []).filter(
    (session) =>
      session.namespace === namespace &&
      session.cluster === cluster &&
      session.kind === kind &&
      session.name === name &&
      session.port === port
  )
  const selectedScheme = schemeEdited ? scheme : (matching[0]?.scheme ?? scheme)
  const selectedPath = pathEdited ? path : (matching[0]?.path ?? path)
  const selectedExpiry = expiryEdited
    ? expiresInMinutes
    : String(matching[0]?.expiresInMinutes ?? expiresInMinutes)
  const selectedPublic = publicEdited
    ? isPublic
    : (matching[0]?.public ?? isPublic)
  const isAdmin = user?.isAdmin() ?? false
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
        scheme: selectedScheme,
        path: selectedPath,
        alias,
        expiresInMinutes: Number(selectedExpiry),
        public: selectedPublic,
      })
      popup.location.replace(result.url)
      await queryClient.invalidateQueries({ queryKey: serviceAccessQueryKey })
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
      await deleteServiceAccess(id)
      await queryClient.invalidateQueries({ queryKey: serviceAccessQueryKey })
    } catch (error) {
      setError(
        error instanceof Error ? error.message : t('serviceAccess.failed')
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next)
        if (!next) {
          setSchemeEdited(false)
          setPathEdited(false)
          setExpiryEdited(false)
          setPublicEdited(false)
        }
      }}
    >
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
      <DialogContent className="max-h-[85vh] overflow-y-auto">
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
          <Label htmlFor="service-access-alias">
            {t('serviceAccess.alias')}
          </Label>
          <Input
            id="service-access-alias"
            value={alias}
            onChange={(event) => setAlias(event.target.value.toLowerCase())}
            placeholder={`${name.replaceAll('.', '-')}-${port}`}
            disabled={matching.length > 0}
          />
          <p className="text-xs text-muted-foreground">
            {matching[0]
              ? t('serviceAccess.aliasExisting', { alias: matching[0].id })
              : t('serviceAccess.aliasHelp')}
          </p>
        </div>
        <div className="space-y-2">
          <Label htmlFor="service-access-protocol">
            {t('serviceAccess.protocol')}
          </Label>
          <Select
            value={selectedScheme}
            onValueChange={(value) => {
              setScheme(value)
              setSchemeEdited(true)
            }}
          >
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
            value={selectedPath}
            onChange={(event) => {
              setPath(event.target.value)
              setPathEdited(true)
            }}
            placeholder="/"
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="service-access-expiry">
            {t('serviceAccess.expirationMinutes')}
          </Label>
          <Input
            id="service-access-expiry"
            type="number"
            min={0}
            max={525600}
            value={selectedExpiry}
            onChange={(event) => {
              setExpiresInMinutes(event.target.value)
              setExpiryEdited(true)
            }}
          />
          <p className="text-xs text-muted-foreground">
            {t('serviceAccess.expirationHelp')}
          </p>
        </div>
        {isAdmin && (
          <div className="flex items-start justify-between gap-3 rounded-md border p-3">
            <div className="space-y-1">
              <Label htmlFor="service-access-public">
                {t('serviceAccess.public')}
              </Label>
              <p className="text-xs text-muted-foreground">
                {t('serviceAccess.publicHelp')}
              </p>
            </div>
            <Switch
              id="service-access-public"
              checked={selectedPublic}
              onCheckedChange={(checked) => {
                setIsPublic(checked)
                setPublicEdited(true)
              }}
            />
          </div>
        )}
        {!isAdmin && matching[0]?.public && (
          <p className="text-sm text-destructive">
            {t('serviceAccess.adminOnly')}
          </p>
        )}
        <Button
          disabled={
            busy ||
            sessions.isLoading ||
            sessions.isError ||
            selectedExpiry.trim() === '' ||
            !Number.isInteger(Number(selectedExpiry)) ||
            Number(selectedExpiry) < 0 ||
            Number(selectedExpiry) > 525600 ||
            (!isAdmin && selectedPublic)
          }
          onClick={launch}
        >
          <IconExternalLink className="size-4" />
          {t('serviceAccess.open')}
        </Button>
        {matching.map((session: ServiceAccessEntry) => (
          <div
            key={session.id}
            className="flex items-center justify-between gap-3 text-sm"
          >
            <span
              className="min-w-0 truncate font-mono text-xs"
              title={session.hostname}
            >
              {session.hostname}
            </span>
            <Button
              variant="outline"
              size="sm"
              disabled={busy}
              onClick={() => close(session.id)}
            >
              {t('serviceAccess.remove')}
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
