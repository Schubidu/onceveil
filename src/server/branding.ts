import { createServerFn } from '@tanstack/react-start'
import { getRequest } from '@tanstack/react-start/server'

import { createRequestContext } from '#onceveil-runtime-context'

export const getDeploymentBranding = createServerFn({ method: 'GET' }).handler(() => {
  return createRequestContext(getRequest()).branding
})
