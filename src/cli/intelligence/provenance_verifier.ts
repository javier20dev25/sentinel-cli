import { execSync } from 'child_process'

export interface ProvenanceAttestation {
  type: string
  issuer: string
  subject: string
  predicateType: string
  timestamp: string
  slsaLevel?: string
}

export interface ProvenanceResult {
  packageName: string
  version: string
  verified: boolean
  attestations: ProvenanceAttestation[]
  error?: string
}

export class ProvenanceVerifier {
  checkCommandAvailable(): boolean {
    try {
      execSync('npm attestation --help', { encoding: 'utf8', stdio: 'pipe' as const, shell: true as any })
      return true
    } catch {
      return false
    }
  }

  async verify(packageName: string, version?: string): Promise<ProvenanceResult> {
    const pkgSpec = version ? `${packageName}@${version}` : packageName

    try {
      const stdout = execSync(`npm attestation verify ${pkgSpec}`, {
        encoding: 'utf8', stdio: 'pipe' as const, shell: true as any
      })

      const raw = JSON.parse(stdout)
      const items: any[] = Array.isArray(raw) ? raw : [raw]
      const attestations: ProvenanceAttestation[] = []
      let allVerified = true

      for (const item of items) {
        const vr = item.verificationResult || {}
        const results = Array.isArray(vr.results) ? vr.results : []
        const firstResult = results[0] || {}

        const signer = firstResult.signer || item.signer || {}
        const att = item.attestation || {}
        const subjects = Array.isArray(att.subject) ? att.subject : (att.subject ? [att.subject] : [])
        const firstSubject = subjects[0] || {}

        const type = item.type || 'attestation'
        const issuer = signer.issuer || item.issuer || ''
        const subject = typeof firstSubject === 'string' ? firstSubject : (firstSubject.name || '')
        const predicateType = att.predicateType || item.predicateType || ''
        const timestamp = firstResult.timestamp || item.timestamp || ''

        let slsaLevel: string | undefined
        if (predicateType && predicateType.includes('slsa.dev')) {
          const m = predicateType.match(/v(\d+)/)
          if (m) slsaLevel = `SLSA v${m[1]}`
        }

        if (vr.verified !== true) allVerified = false

        attestations.push({ type, issuer, subject, predicateType, timestamp, slsaLevel })
      }

      return {
        packageName,
        version: version || '',
        verified: attestations.length > 0 && allVerified,
        attestations
      }
    } catch (e: any) {
      return {
        packageName,
        version: version || '',
        verified: false,
        attestations: [],
        error: e.stderr || e.stdout || e.message || 'Unknown error'
      }
    }
  }
}
