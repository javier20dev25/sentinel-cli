export interface HomoglyphMatch {
  packageName: string;
  target: string;
  distance: number;
  homoglyphs: string[];
  severity: 'LOW' | 'MEDIUM' | 'HIGH';
}

export interface HomoglyphResult {
  packageName: string;
  isSuspicious: boolean;
  matches: HomoglyphMatch[];
  confidence: number;
}

const HOMOGLYPH_MAP: Record<string, string[]> = {
  'a': ['а', 'à', 'á', 'â', 'ã', 'ä', 'å'],
  'e': ['е', 'è', 'é', 'ê', 'ë', 'ė'],
  'o': ['о', 'ò', 'ó', 'ô', 'õ', 'ö', 'ø', '0'],
  'c': ['с', 'ç', 'č', 'ć'],
  'p': ['р', 'þ'],
  'y': ['у', 'ÿ', 'ý'],
  'x': ['х', '×'],
  'i': ['і', 'ì', 'í', 'î', 'ï', 'í', '1', 'l'],
  's': ['ѕ', 'ś', 'š'],
  'b': ['ь', 'ъ'],
  'k': ['κ', 'к'],
  'm': ['м', 'rn'],
  'n': ['п', 'ñ'],
  'r': ['г', 'ř'],
  't': ['т', 'ŧ'],
  'u': ['υ', 'ù', 'ú', 'û'],
  'd': ['ԁ', 'ɗ'],
  'h': ['һ', 'ḥ'],
  'w': ['ԝ', 'ŵ'],
};

const REVERSE_MAP: Record<string, string> = {};
for (const [latin, homoglyphs] of Object.entries(HOMOGLYPH_MAP)) {
  for (const h of homoglyphs) {
    REVERSE_MAP[h] = latin;
  }
}

const DEFAULT_TOP_PACKAGES: string[] = [
  'lodash', 'chalk', 'react', 'express', 'axios', 'uuid', 'moment',
  'typescript', 'webpack', 'babel', 'eslint', 'prettier', 'tslib',
  'date-fns', 'dotenv', 'commander', 'body-parser', 'nodemon',
  'socket.io', 'passport', 'mongoose', 'koa', 'fastify', 'morgan',
  'cors', 'helmet', 'joi', 'yup', 'zod', 'ioredis', 'pg', 'mysql2',
  'sequelize', 'prisma', 'typeorm', 'graphql', 'apollo', 'next',
  'nuxt', 'gatsby', 'astro', 'svelte', 'vue', 'angular', 'jquery',
  'bootstrap', 'tailwindcss', 'sass', 'less', 'postcss', 'autoprefixer',
  'browserify', 'gulp', 'grunt', 'rollup', 'vite', 'esbuild', 'swc',
  'ava', 'jest', 'mocha', 'jasmine', 'cypress', 'playwright', 'puppeteer',
  'cheerio', 'jsdom', 'dompurify', 'sanitize-html', 'marked',
  'highlight.js', 'prismjs', 'd3', 'chart.js', 'echarts', 'three',
  'animejs', 'gsap', 'lodash-es', 'ramda', 'rxjs', 'immer', 'redux',
  'mobx', 'zustand', 'valtio', 'jotai', 'recoil', 'react-router',
  'react-query', 'swr', 'react-hook-form', 'formik', 'final-form',
  'i18next', 'react-i18next', 'react-intl', 'faker', 'chance',
  'nanoid', 'ulid', 'crypto-js', 'bcrypt', 'argon2', 'jsonwebtoken',
  'passport-jwt', 'multer', 'sharp', 'jimp', 'gm', 'pdfkit',
  'aws-sdk', 'firebase-admin', 'firebase', 'stripe',
  'nodemailer', 'sendgrid', 'twilio', 'socket.io-client',
  'ws', 'compression', 'serve-static', 'express-session',
  'cookie-parser', 'csurf', 'rate-limiter-flexible',
  'express-rate-limit', 'hpp', 'xss', 'csp',
  'winston', 'pino', 'bunyan', 'log4js', 'signale', 'consola',
  'debug', 'rimraf', 'fs-extra', 'globby', 'del', 'make-dir',
  'semver', 'validate-npm-package-name',
  'got', 'node-fetch', 'undici', 'ky', 'superagent',
  'follow-redirects', 'tough-cookie', 'http-proxy-agent',
  'cli-table3', 'ora', 'listr2', 'progress', 'log-update',
  'ansi-styles', 'supports-color', 'color-convert', 'color-name',
  'has-flag', 'escape-string-regexp', 'strip-ansi', 'ansi-regex',
  'wrap-ansi', 'string-width', 'is-fullwidth-code-point',
  'yargs', 'yargs-parser', 'cliui', 'get-caller-file',
  'glob', 'safe-buffer', 'readable-stream', 'string_decoder',
  'mime-types', 'mime-db', 'etag', 'depd',
  'http-errors', 'statuses', 'content-type', 'accepts',
  'bytes', 'compressible', 'methods', 'merge-descriptors',
  'source-map', 'source-map-js', 'terser', 'uglify-js',
  'jiti', 'tsup', 'unbuild', 'pkgroll', 'tsx',
];

function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost
      );
    }
  }
  return dp[m][n];
}

function findHomoglyphs(a: string, b: string): string[] {
  const found: string[] = [];
  let i = 0;
  let j = 0;

  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) {
      i++;
      j++;
      continue;
    }

    let matched = false;

    for (const [latin, homoglyphs] of Object.entries(HOMOGLYPH_MAP)) {
      for (const h of homoglyphs) {
        if (h.length > 1 && a.substring(i, i + h.length) === h && b[j] === latin) {
          found.push(`${h}→${latin}`);
          i += h.length;
          j++;
          matched = true;
          break;
        }
        if (h.length > 1 && b.substring(j, j + h.length) === h && a[i] === latin) {
          found.push(`${latin}→${h}`);
          i++;
          j += h.length;
          matched = true;
          break;
        }
      }
      if (matched) break;
    }
    if (matched) continue;

    const reverseA = REVERSE_MAP[a[i]];
    const reverseB = REVERSE_MAP[b[j]];

    if (reverseA === b[j]) {
      found.push(`${a[i]}→${b[j]}`);
      i++;
      j++;
      continue;
    }
    if (reverseB === a[i]) {
      found.push(`${b[j]}→${a[i]}`);
      i++;
      j++;
      continue;
    }

    i++;
    j++;
  }

  return found;
}

function generateVariants(name: string): string[] {
  const variants: string[] = [];

  for (let i = 0; i < name.length; i++) {
    const char = name[i];
    const homoglyphs = HOMOGLYPH_MAP[char] || [];
    for (const h of homoglyphs) {
      if (h.length === 1) {
        variants.push(name.substring(0, i) + h + name.substring(i + 1));
      }
    }
  }

  for (let i = 0; i < name.length; i++) {
    for (const [latin, homoglyphs] of Object.entries(HOMOGLYPH_MAP)) {
      for (const h of homoglyphs) {
        if (h.length > 1 && name.substring(i, i + h.length) === h) {
          variants.push(name.substring(0, i) + latin + name.substring(i + h.length));
        }
        if (h.length > 1 && name.substring(i, i + 1) === latin && name.substring(i + 1, i + h.length) === h.substring(1)) {
          const fullSeq = name.substring(i, i + h.length);
          if (fullSeq !== h && h.length <= name.length - i) {
            const seq = name.substring(i, i + h.length);
            if (seq === h) {
              variants.push(name.substring(0, i) + latin + name.substring(i + h.length));
            }
          }
        }
      }
    }
  }

  return [...new Set(variants)];
}

export function detectHomoglyph(packageName: string, topPackages?: string[]): HomoglyphResult {
  const topList = topPackages || DEFAULT_TOP_PACKAGES;
  const lowerName = packageName.toLowerCase().replace(/^@/, '');

  if (!lowerName) {
    return { packageName, isSuspicious: false, matches: [], confidence: 0 };
  }

  if (topList.includes(lowerName)) {
    return { packageName, isSuspicious: false, matches: [], confidence: 0 };
  }

  const matches: HomoglyphMatch[] = [];
  const variants = generateVariants(lowerName);

  for (const target of topList) {
    const lowerTarget = target.toLowerCase().replace(/^@/, '');

    if (variants.includes(lowerTarget)) {
      const homoglyphs = findHomoglyphs(lowerName, lowerTarget);
      matches.push({
        packageName,
        target,
        distance: 0,
        homoglyphs,
        severity: 'HIGH',
      });
      continue;
    }

    const dist = levenshtein(lowerName, lowerTarget);
    if (dist > 2) continue;

    const homoglyphs = findHomoglyphs(lowerName, lowerTarget);
    const severity = dist === 1 ? 'MEDIUM' : 'LOW';

    matches.push({
      packageName,
      target,
      distance: dist,
      homoglyphs,
      severity,
    });
  }

  matches.sort((a, b) => a.distance - b.distance);

  const isSuspicious = matches.length > 0;
  const confidence = isSuspicious
    ? Math.round((1 - (matches[0].distance / Math.max(lowerName.length, matches[0].target.length))) * 100) / 100
    : 0;

  return { packageName, isSuspicious, matches: matches.slice(0, 5), confidence };
}
