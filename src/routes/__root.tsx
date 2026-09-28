import { HeadContent, Outlet, Scripts, createRootRoute } from '@tanstack/react-router'
import type { CSSProperties, ReactNode } from 'react'

import { BrandingProvider } from '../browser/branding'
import { DEFAULT_BRANDING, type BrandingConfig } from '../core/branding'
import { getDeploymentBranding } from '../server/branding'
import stylesheet from '../styles.css?url'

export const Route = createRootRoute({
  loader: () => getDeploymentBranding(),
  head: ({ loaderData }) => {
    const branding = loaderData ?? DEFAULT_BRANDING

    return {
      meta: [
        { charSet: 'utf-8' },
        {
          name: 'viewport',
          content: 'width=device-width, initial-scale=1',
        },
        {
          title: branding.name,
        },
        {
          name: 'description',
          content: 'Preview-safe one-time secret sharing.',
        },
      ],
      links: [
        { rel: 'stylesheet', href: stylesheet },
        ...(branding.favicon ? [{ rel: 'icon', href: branding.favicon }] : []),
      ],
    }
  },
  component: RootComponent,
})

function RootComponent() {
  const branding = Route.useLoaderData()

  return (
    <RootDocument branding={branding}>
      <BrandingProvider branding={branding}>
        <Outlet />
      </BrandingProvider>
    </RootDocument>
  )
}

function RootDocument({
  branding,
  children,
}: Readonly<{ branding: BrandingConfig; children: ReactNode }>) {
  return (
    <html lang="en" style={{ '--brand-accent': branding.theme.accent } as CSSProperties}>
      <head>
        <HeadContent />
      </head>
      <body>
        {children}
        <Scripts />
      </body>
    </html>
  )
}
