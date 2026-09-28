import { HeadContent, Outlet, Scripts, createRootRoute } from '@tanstack/react-router'
import type { ReactNode } from 'react'

import { BrandingProvider } from '../browser/branding'
import { DEFAULT_BRANDING } from '../core/branding'
import stylesheet from '../styles.css?url'

export const Route = createRootRoute({
  head: () => ({
    meta: [
      { charSet: 'utf-8' },
      {
        name: 'viewport',
        content: 'width=device-width, initial-scale=1',
      },
      {
        title: DEFAULT_BRANDING.name,
      },
      {
        name: 'description',
        content: 'Preview-safe one-time secret sharing.',
      },
    ],
    links: [{ rel: 'stylesheet', href: stylesheet }],
  }),
  component: RootComponent,
})

function RootComponent() {
  return (
    <RootDocument>
      <BrandingProvider>
        <Outlet />
      </BrandingProvider>
    </RootDocument>
  )
}

function RootDocument({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="en">
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
