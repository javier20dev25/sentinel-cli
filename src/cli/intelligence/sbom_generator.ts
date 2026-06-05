import { LockfileParser, LockfileEntry } from './lockfile_parser'

export interface SbomComponent {
  type: string
  name: string
  version: string
  purl: string
  properties?: { name: string, value: string }[]
}

export interface SbomResult {
  format: string
  bomFormat: string
  specVersion: string
  serialNumber: string
  version: number
  metadata: any
  components: SbomComponent[]
}

export class SbomGenerator {
  private parser: LockfileParser

  constructor() {
    this.parser = new LockfileParser()
  }

  generate(lockfilePath: string): SbomResult {
    const result = this.parser.parse(lockfilePath)
    return this.generateFromEntries(result.entries, result.format)
  }

  generateFromEntries(entries: LockfileEntry[], format: string): SbomResult {
    return this.toCycloneDx(entries)
  }

  toCycloneDx(entries: LockfileEntry[]): SbomResult {
    const components: SbomComponent[] = entries.map(entry => {
      const component: SbomComponent = {
        type: 'library',
        name: entry.name,
        version: entry.version,
        purl: this.toPurl(entry.name, entry.version),
      }
      if (entry.integrity) {
        component.properties = [
          { name: 'integrity', value: entry.integrity },
        ]
      }
      return component
    })

    return {
      format: 'cyclonedx',
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: this.generateSerial(),
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        tools: [
          { name: 'sentinel-cli', vendor: 'Sentinel' },
        ],
      },
      components,
    }
  }

  toPurl(name: string, version: string): string {
    const encoded = name.replace(/^@/, '%40')
    return `pkg:npm/${encoded}@${version}`
  }

  private generateSerial(): string {
    const hex = (len: number) =>
      Array.from({ length: len }, () => Math.floor(Math.random() * 16).toString(16)).join('')
    return `urn:uuid:${hex(8)}-${hex(4)}-4${hex(3)}-${hex(4)}-${hex(12)}`
  }
}
