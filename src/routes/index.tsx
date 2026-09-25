import { createFileRoute } from '@tanstack/react-router'

import { PROJECT_NAME, PROJECT_TAGLINE } from '../core/project'

export const Route = createFileRoute('/')({
  component: Home,
})

function Home() {
  return (
    <main className="shell">
      <section className="card" aria-labelledby="onceveil-title">
        <p className="eyebrow">Open source · early development</p>
        <h1 id="onceveil-title">{PROJECT_NAME}</h1>
        <p className="tagline">{PROJECT_TAGLINE}</p>
        <p className="status">
          The project foundation is in place. Secret creation and reveal are intentionally not
          implemented yet.
        </p>
      </section>
    </main>
  )
}
