import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import { ReleaseStore, ReleaseEntry, BuildRecord } from '../../core/network/build-types'

function getReleasePath(): string {
  const dir = path.join(os.homedir(), '.sentinel', 'builds')
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true })
  return path.join(dir, 'releases.json')
}

function getBuildDir(): string {
  return path.join(os.homedir(), '.sentinel', 'builds')
}

function getBuildPath(buildId: string): string {
  return path.join(getBuildDir(), `${buildId}.json`)
}

function loadReleases(): ReleaseStore {
  const rp = getReleasePath()
  if (!fs.existsSync(rp)) return { currentRelease: null, releases: [] }
  try {
    return JSON.parse(fs.readFileSync(rp, 'utf8'))
  } catch {
    return { currentRelease: null, releases: [] }
  }
}

function saveReleases(store: ReleaseStore): void {
  fs.writeFileSync(getReleasePath(), JSON.stringify(store, null, 2), 'utf8')
}

export function loadBuildById(buildId: string): BuildRecord | null {
  const bp = getBuildPath(buildId)
  if (!fs.existsSync(bp)) return null
  try {
    return JSON.parse(fs.readFileSync(bp, 'utf8'))
  } catch {
    return null
  }
}

export function markRelease(buildId: string, tag: string, force: boolean): { success: boolean; error?: string } {
  const store = loadReleases()

  if (store.currentRelease && !force) {
    return {
      success: false,
      error: `Release already set to ${store.currentRelease}. Use --force to overwrite.`,
    }
  }

  const build = loadBuildById(buildId)
  if (!build) {
    return { success: false, error: `Build ${buildId} not found.` }
  }

  const entry: ReleaseEntry = {
    buildId,
    tag,
    timestamp: Date.now(),
  }

  const existingIdx = store.releases.findIndex(r => r.buildId === buildId)
  if (existingIdx >= 0) {
    store.releases[existingIdx] = entry
  } else {
    store.releases.push(entry)
  }

  store.currentRelease = buildId
  saveReleases(store)

  return { success: true }
}

export function getCurrentRelease(): { entry: ReleaseEntry | null; build: BuildRecord | null } {
  const store = loadReleases()
  if (!store.currentRelease) return { entry: null, build: null }

  const entry = store.releases.find(r => r.buildId === store.currentRelease)
  if (!entry) return { entry: null, build: null }

  const build = loadBuildById(entry.buildId)
  if (!build) return { entry: null, build: null }

  return { entry, build }
}

export function listReleases(): ReleaseEntry[] {
  return loadReleases().releases
}

export function renderReleaseStatus(): string {
  const store = loadReleases()
  if (!store.currentRelease) {
    return 'No release baseline set.\nUse `sentinel build mark-release <build-id>` to mark a release.'
  }

  const entry = store.releases.find(r => r.buildId === store.currentRelease)
  if (!entry) return 'Release baseline is set but entry not found.'

  return [
    `Current release: ${entry.tag} (build ${entry.buildId})`,
    `Set: ${new Date(entry.timestamp).toISOString()}`,
    `Total releases in history: ${store.releases.length}`,
  ].join('\n')
}
