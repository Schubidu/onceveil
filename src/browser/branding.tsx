import { createContext, type ReactNode, useContext } from 'react'

import { DEFAULT_BRANDING, type BrandingConfig } from '../core/branding'

const BrandingContext = createContext<BrandingConfig>(DEFAULT_BRANDING)

export function BrandingProvider({
  branding,
  children,
}: Readonly<{ branding: BrandingConfig; children: ReactNode }>) {
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
