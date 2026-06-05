import { execSync } from 'child_process'

export interface ReputationFactor {
  name: string
  impact: number
  detail: string
}

export interface ReputationScore {
  packageName: string
  version: string
  score: number
  label: 'TRUSTED' | 'NEUTRAL' | 'SUSPICIOUS' | 'MALICIOUS'
  factors: ReputationFactor[]
}

export class RegistryReputation {
  async score(packageName: string): Promise<ReputationScore> {
    try {
      const data = await this.npmView(packageName)
      return this.calculateScore(packageName, data)
    } catch {
      return {
        packageName,
        version: 'unknown',
        score: 0,
        label: 'NEUTRAL',
        factors: [{ name: 'error', impact: 0, detail: 'Package not found or npm error' }]
      }
    }
  }

  async npmView(packageName: string): Promise<any> {
    const output = execSync(`npm view ${packageName} --json`, { shell: true as any, encoding: 'utf8' })
    return JSON.parse(output)
  }

  private calculateScore(packageName: string, data: any): ReputationScore {
    const factors: ReputationFactor[] = []
    let score = 0
    const version = data['dist-tags']?.latest || 'unknown'
    const now = new Date()

    if (data.time?.created) {
      const created = new Date(data.time.created)
      const days = (now.getTime() - created.getTime()) / 86400000
      if (days < 30) {
        factors.push({ name: 'age', impact: -20, detail: `Package is ${Math.round(days)} days old` })
        score -= 20
      } else if (days < 90) {
        factors.push({ name: 'age', impact: -5, detail: `Package is ${Math.round(days)} days old` })
        score -= 5
      } else if (days > 365) {
        factors.push({ name: 'age', impact: 10, detail: `Package is ${Math.round(days)} days old` })
        score += 10
      }
    }

    const maintainers = data.maintainers
    if (maintainers) {
      const count = maintainers.length
      if (count === 1) {
        factors.push({ name: 'maintainers', impact: -10, detail: `Only ${count} maintainer` })
        score -= 10
      } else if (count >= 4) {
        factors.push({ name: 'maintainers', impact: 5, detail: `${count} maintainers` })
        score += 5
      } else {
        factors.push({ name: 'maintainers', impact: 0, detail: `${count} maintainers` })
      }
    }

    const versionKeys = data.versions ? Object.keys(data.versions) : []
    if (versionKeys.length < 5) {
      factors.push({ name: 'versions', impact: -10, detail: `${versionKeys.length} versions` })
      score -= 10
    } else if (versionKeys.length > 50) {
      factors.push({ name: 'versions', impact: 5, detail: `${versionKeys.length} versions` })
      score += 5
    }

    if (data.versions) {
      const hasDeprecated = Object.values(data.versions).some((v: any) => v.deprecated)
      if (hasDeprecated) {
        factors.push({ name: 'deprecation', impact: -30, detail: 'Package has deprecated versions' })
        score -= 30
      }
    }

    const desc = data.description
    if (!desc || (typeof desc === 'string' && desc.length < 10)) {
      factors.push({ name: 'description', impact: -5, detail: !desc ? 'No description' : 'Description too short' })
      score -= 5
    }

    if (!data.homepage) {
      factors.push({ name: 'homepage', impact: -5, detail: 'No homepage URL' })
      score -= 5
    }

    if (desc && typeof desc === 'string' && desc.length >= 10) {
      factors.push({ name: 'description', impact: 10, detail: 'Description present and adequate' })
      score += 10
    }

    if (data.homepage) {
      factors.push({ name: 'homepage', impact: 10, detail: 'Homepage URL provided' })
      score += 10
    }

    if (data.versions) {
      const hasDeprecated = Object.values(data.versions).some((v: any) => v.deprecated)
      if (!hasDeprecated) {
        factors.push({ name: 'deprecation', impact: 10, detail: 'No deprecated versions' })
        score += 10
      }
    }

    return {
      packageName,
      version,
      score,
      label: this.getLabel(score),
      factors
    }
  }

  getLabel(score: number): 'TRUSTED' | 'NEUTRAL' | 'SUSPICIOUS' | 'MALICIOUS' {
    if (score >= 50) return 'TRUSTED'
    if (score >= 0) return 'NEUTRAL'
    if (score >= -30) return 'SUSPICIOUS'
  return 'MALICIOUS'
  }
}
