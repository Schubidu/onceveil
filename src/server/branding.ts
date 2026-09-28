import { createServerFn } from '@tanstack/react-start'
import { getBrandingConfig } from '#onceveil-runtime-context'

export const getDeploymentBranding = createServerFn({ method: 'GET' }).handler(() => {
  return getBrandingConfig()
})
