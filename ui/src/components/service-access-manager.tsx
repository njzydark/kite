import { useEffect, useState } from 'react'
import { useAuth } from '@/contexts/auth-context'
import { IconExternalLink, IconWorld } from '@tabler/icons-react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'

import {
  deleteServiceAccess,
  listServiceAccess,
  serviceAccessOpenURL,
  serviceAccessQueryKey,
  updateServiceAccess,
  type ServiceAccessEntry,
} from '@/lib/api/service-access'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'

function EntrySettings({
  entry,
  isAdmin,
}: {
  entry: ServiceAccessEntry
  isAdmin: boolean
}) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [expiresInMinutes, setExpiresInMinutes] = useState(
    String(entry.expiresInMinutes)
  )
  const [isPublic, setIsPublic] = useState(entry.public)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    setExpiresInMinutes(String(entry.expiresInMinutes))
    setIsPublic(entry.public)
  }, [entry.expiresInMinutes, entry.public])

  const save = async () => {
    setBusy(true)
    setError('')
    try {
      await updateServiceAccess(entry.id, {
        expiresInMinutes: Number(expiresInMinutes),
        public: isPublic,
      })
      await queryClient.invalidateQueries({ queryKey: serviceAccessQueryKey })
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : t('serviceAccess.failed')
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <details className="mt-3 border-t pt-2">
      <summary className="cursor-pointer text-xs text-muted-foreground">
        {t('serviceAccess.settings')}
      </summary>
      <div className="mt-3 space-y-3">
        <div className="space-y-1">
          <Label htmlFor={`service-access-expiry-${entry.id}`}>
            {t('serviceAccess.expirationMinutes')}
          </Label>
          <Input
            id={`service-access-expiry-${entry.id}`}
            type="number"
            min={0}
            max={525600}
            value={expiresInMinutes}
            onChange={(event) => setExpiresInMinutes(event.target.value)}
          />
          <p className="text-xs text-muted-foreground">
            {t('serviceAccess.expirationHelp')}
          </p>
        </div>
        <div className="flex items-start justify-between gap-3">
          <div className="space-y-1">
            <Label htmlFor={`service-access-public-${entry.id}`}>
              {t('serviceAccess.public')}
            </Label>
            <p className="text-xs text-muted-foreground">
              {t('serviceAccess.publicHelp')}
            </p>
          </div>
          <Switch
            id={`service-access-public-${entry.id}`}
            checked={isPublic}
            disabled={!isAdmin && !isPublic}
            onCheckedChange={setIsPublic}
          />
        </div>
        <Button
          size="sm"
          disabled={
            busy ||
            expiresInMinutes.trim() === '' ||
            !Number.isInteger(Number(expiresInMinutes)) ||
            Number(expiresInMinutes) < 0 ||
            Number(expiresInMinutes) > 525600 ||
            (!isAdmin && isPublic)
          }
          onClick={save}
        >
          {t('serviceAccess.save')}
        </Button>
        {error && (
          <p role="alert" className="text-xs text-destructive">
            {error}
          </p>
        )}
      </div>
    </details>
  )
}

export function ServiceAccessManager() {
  const { t } = useTranslation()
  const { user, capabilities } = useAuth()
  const queryClient = useQueryClient()
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState('')
  const entries = useQuery({
    queryKey: serviceAccessQueryKey,
    queryFn: listServiceAccess,
    enabled: !!user && !!capabilities.serviceAccessEnabled,
    refetchInterval: 30000,
  })

  if (!capabilities.serviceAccessEnabled || !user) return null

  const remove = async (id: string) => {
    setBusy(id)
    setError('')
    try {
      await deleteServiceAccess(id)
      await queryClient.invalidateQueries({ queryKey: serviceAccessQueryKey })
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : t('serviceAccess.failed')
      )
    } finally {
      setBusy(null)
    }
  }

  return (
    <>
      <Button
        variant="ghost"
        size="icon"
        className="relative"
        onClick={() => setOpen(true)}
        title={t('serviceAccess.manage')}
        aria-label={t('serviceAccess.manage')}
      >
        <IconWorld className="size-5" />
        {!!entries.data?.length && (
          <span className="absolute -top-1 -right-1 flex size-4 items-center justify-center rounded-full bg-primary text-[10px] leading-none text-primary-foreground">
            {entries.data.length > 9 ? '9+' : entries.data.length}
          </span>
        )}
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-h-[80vh] overflow-y-auto sm:max-w-xl">
          <DialogHeader>
            <DialogTitle>{t('serviceAccess.manage')}</DialogTitle>
            <DialogDescription>
              {t('serviceAccess.manageDescription')}
            </DialogDescription>
          </DialogHeader>
          {entries.isError && (
            <p role="alert" className="text-sm text-destructive">
              {t('serviceAccess.failed')}
            </p>
          )}
          {!entries.isLoading && !entries.data?.length && !entries.isError && (
            <p className="text-sm text-muted-foreground">
              {t('serviceAccess.empty')}
            </p>
          )}
          <div className="space-y-3">
            {entries.data?.map((entry) => (
              <div key={entry.id} className="rounded-md border p-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0 space-y-1">
                    <p className="font-medium">
                      {entry.name}:{entry.port}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {entry.cluster} / {entry.namespace} / {entry.kind}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {entry.public
                        ? t('serviceAccess.public')
                        : t('serviceAccess.private')}
                      {entry.public &&
                        entry.publicUntil &&
                        ` · ${t('serviceAccess.expires', { time: new Date(entry.publicUntil).toLocaleString() })}`}
                    </p>
                    {!entry.authorized && (
                      <p className="text-xs text-destructive">
                        {t('serviceAccess.noPermission')}
                      </p>
                    )}
                    <p
                      className="truncate font-mono text-xs"
                      title={entry.hostname}
                    >
                      {entry.hostname}
                    </p>
                  </div>
                  <div className="flex shrink-0 gap-1">
                    {entry.authorized ? (
                      <Button variant="outline" size="sm" asChild>
                        <a
                          href={serviceAccessOpenURL(entry.id)}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          <IconExternalLink className="size-4" />
                          {t('serviceAccess.open')}
                        </a>
                      </Button>
                    ) : (
                      <Button variant="outline" size="sm" disabled>
                        {t('serviceAccess.open')}
                      </Button>
                    )}
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={busy === entry.id}
                      onClick={() => remove(entry.id)}
                    >
                      {t('serviceAccess.remove')}
                    </Button>
                  </div>
                </div>
                <EntrySettings entry={entry} isAdmin={user.isAdmin()} />
              </div>
            ))}
          </div>
          {error && (
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
          )}
        </DialogContent>
      </Dialog>
    </>
  )
}
