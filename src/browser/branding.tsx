import { createContext, type ReactNode, useContext, useEffect, useState } from 'react'

import { DEFAULT_BRANDING, parseBrandingConfig, type BrandingConfig } from '../core/branding'

const BrandingContext = createContext<BrandingConfig>(DEFAULT_BRANDING)
const MANAGED_FAVICON_ID = 'onceveil-brand-favicon'

export function BrandingProvider({ children }: Readonly<{ children: ReactNode }>) {
  const [branding, setBranding] = useState<BrandingConfig>(DEFAULT_BRANDING)

  useEffect(() => {
    let active = true

    void fetch('/api/branding', {
      headers: { Accept: 'application/json' },
    })
      .then(async (response) => {
        if (!response.ok) {
          return DEFAULT_BRANDING
        }

        return parseBrandingConfig(await response.json().catch(() => undefined))
      })
      .then((configuration) => {
        if (active) {
          setBranding(configuration)
        }
      })
      .catch(() => {
        if (active) {
          setBranding(DEFAULT_BRANDING)
        }
      })

    return () => {
      active = false
    }
  }, [])

  useEffect(() => {
    document.title = branding.name
    document.documentElement.style.setProperty('--brand-accent', branding.theme.accent)

    document.getElementById(MANAGED_FAVICON_ID)?.remove()
    if (branding.favicon) {
      const favicon = document.createElement('link')
      favicon.id = MANAGED_FAVICON_ID
      favicon.rel = 'icon'
      favicon.href = branding.favicon
      document.head.append(favicon)
    }
  }, [branding])

  return <BrandingContext.Provider value={branding}>{children}</BrandingContext.Provider>
}

export function useBranding(): BrandingConfig {
  return useContext(BrandingContext)
}

export function BrandHeading({ id }: Readonly<{ id: string }>) {
  const branding = useBranding()

  return (
    <>
      {branding.logo ? <img className="brand-logo" src={branding.logo} alt="" /> : null}
      <h1 id={id}>{branding.name}</h1>
    </>
  )
}
