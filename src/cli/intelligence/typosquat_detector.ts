/**
 * Sentinel Typosquatting Detector (v5.0)
 *
 * Detects typosquatting attacks against popular npm packages
 * using Levenshtein distance and homoglyph character substitution.
 */

export interface TyposquatResult {
    isSuspicious: boolean;
    matches: TyposquatMatch[];
}

export interface TyposquatMatch {
    target: string;
    distance: number;
    homoglyphs: string[];
}

const HOMOGLYPHS: Record<string, string[]> = {
    'a': ['а', 'à', 'á', 'â', 'ã', 'ä', 'å', 'ɑ'],
    'b': ['Ь', 'ъ', 'ḅ'],
    'c': ['с', 'ç', 'ĉ', 'ċ', 'č'],
    'd': ('ԁ' + 'ɗ' + 'ɖ' + 'ḑ').split(''),
    'e': ['е', 'è', 'é', 'ê', 'ë', 'ĕ', 'ė', 'ę', 'ě'],
    'f': ['ſ', 'ḟ'],
    'g': ['ɡ', 'ĝ', 'ğ', 'ġ', 'ģ'],
    'h': ['һ', 'ĥ', 'ħ'],
    'i': ['і', 'ì', 'í', 'î', 'ï', 'ĩ', 'ī', 'ĭ', 'į'],
    'j': ['ј', 'ĵ'],
    'k': ['κ', 'ķ', 'ĸ'],
    'l': ('ӏ' + 'ḷ' + 'ḹ' + 'ḻ' + 'ḽ').split(''),
    'm': ('ṃ' + 'ṁ' + 'ḿ').split(''),
    'n': ['п', 'ñ', 'ń', 'ņ', 'ň', 'ṅ', 'ṇ'],
    'o': ['о', 'ò', 'ó', 'ô', 'õ', 'ö', 'ō', 'ŏ', 'ő', 'σ'],
    'p': ['р', 'ṗ', 'ṕ'],
    'q': ['ԛ'],
    'r': ('ԁ' + 'ŕ' + 'ŗ' + 'ř' + 'ṙ' + 'ṛ').split(''),
    's': ['ѕ', 'ş', 'ŝ', 'š', 'ṡ', 'ṣ'],
    't': ('ṭ' + 'ṫ' + 'ţ' + 'ŧ' + 'ť').split(''),
    'u': ['у', 'ù', 'ú', 'û', 'ü', 'ũ', 'ū', 'ŭ', 'ů', 'ű'],
    'v': ['ν', 'ѵ'],
    'w': ('ẇ' + 'ẅ' + 'ẉ' + 'ŵ').split(''),
    'x': ['х', '×', 'ẋ', 'ẍ'],
    'y': ['у', 'ÿ', 'ŷ', 'ẏ', 'ỹ'],
    'z': ['z', 'ź', 'ż', 'ž', 'ẓ', 'ẕ'],
    '0': ['о', 'Ο', 'Ο', 'Օ'],
    '1': ['l', '|', 'I', '¡'],
    '2': ['ƻ'],
    '3': ['З'],
    '4': [],
    '5': [],
    '6': [],
    '7': [],
    '8': [],
    '9': [],
};

// Top 200 most-downloaded npm packages — common typosquatting targets
const POPULAR_PACKAGES = [
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
    'puppeteer-core', 'playwright-core', 'selenium-webdriver',
    'aws-sdk', '@aws-sdk/client-s3', 'google-cloud/storage',
    'firebase-admin', 'firebase', 'stripe', 'paypal-rest-sdk',
    'nodemailer', 'sendgrid', 'twilio', 'socket.io-client',
    'ws', 'uws', 'engine.io', 'compression', 'serve-static',
    'express-session', 'cookie-parser', 'csurf', 'rate-limiter-flexible',
    'express-rate-limit', 'hpp', 'xss', 'csp', 'csurf',
    'winston', 'pino', 'bunyan', 'log4js', 'signale', 'consola',
    'debug', 'rimraf', 'fs-extra', 'globby', 'del', 'make-dir',
    'cosmiconfig', 'configstore', 'conf', 'env-paths', 'xdg-basedir',
    'semver', 'validate-npm-package-name', 'normalize-url',
    'got', 'node-fetch', 'undici', 'ky', 'superagent', 'request',
    'follow-redirects', 'tough-cookie', 'http-proxy-agent',
    'https-proxy-agent', 'socks-proxy-agent', 'tunnel-agent',
    'cli-table3', 'ora', 'listr2', 'progress', 'log-update',
    'ansi-styles', 'supports-color', 'color-convert', 'color-name',
    'has-flag', 'escape-string-regexp', 'strip-ansi', 'ansi-regex',
    'wrap-ansi', 'string-width', 'is-fullwidth-code-point',
    'yargs', 'yargs-parser', 'cliui', 'get-caller-file',
    'require-directory', 'require-main-filename',
    'set-blocking', 'which-module', 'y18n',
    '@angular/core', '@angular/common', '@angular/compiler',
    '@babel/core', '@babel/preset-env', '@babel/types',
    '@types/node', '@types/react', '@types/express',
    '@testing-library/react', '@testing-library/jest-dom',
    'util-deprecate', 'inherits', 'once', 'wrappy',
    'minimatch', 'brace-expansion', 'concat-map',
    'balanced-match', 'minimist', 'mkdirp', 'inflight',
    'glob', 'safe-buffer', 'readable-stream', 'string_decoder',
    'isarray', 'core-util-is', 'process-nextick-args',
    'use-strict', 'asap', 'promise', 'asynckit',
    'form-data', 'combined-stream', 'delayed-stream',
    'mime-types', 'mime-db', 'range-parser', 'fresh',
    'etag', 'on-finished', 'ee-first', 'depd',
    'http-errors', 'statuses', 'setprototypeof', 'toidentifier',
    'content-type', 'accepts', 'negotiator', 'type-is',
    'bytes', 'compressible', 'on-headers', 'vary',
    'methods', 'parseurl', 'path-to-regexp', 'qs',
    'merge-descriptors', 'destroy', 'send', 'encodeurl',
    'escape-html', 'array-flatten', 'path-is-absolute',
    '@sentry/node', '@sentry/react', '@sentry/tracing',
    'enhanced-resolve', 'watchpack', 'schema-utils',
    'tapable', 'graceful-fs', 'json-parse-even-better-errors',
    'json5', 'acorn', 'source-map', 'source-map-js',
    'source-map-support', 'terser', 'uglify-js',
    'jiti', 'tsup', 'unbuild', 'pkgroll', 'tsx',
];

export class TyposquatDetector {
    private popularSet: Set<string>;

    constructor() {
        this.popularSet = new Set(POPULAR_PACKAGES.map(p => p.toLowerCase()));
    }

    /**
     * Check a package name for typosquatting against popular packages.
     */
    public check(name: string): TyposquatResult {
        const lower = name.toLowerCase().replace(/^@/, '');
        const matches: TyposquatMatch[] = [];

        // 1. Exact match check
        if (this.popularSet.has(lower)) {
            return { isSuspicious: false, matches: [] };
        }

        // 2. Levenshtein distance against all popular packages
        for (const popular of POPULAR_PACKAGES) {
            const pLower = popular.toLowerCase();
            const dist = this.levenshtein(lower, pLower);
            const maxLen = Math.max(lower.length, pLower.length);

            // Distance <= 2 for short names, <= 3 for longer ones
            const threshold = maxLen <= 5 ? 1 : maxLen <= 10 ? 2 : 3;
            if (dist > 0 && dist <= threshold) {
                const homoglyphs = this.findHomoglyphs(lower, pLower);
                matches.push({
                    target: popular,
                    distance: dist,
                    homoglyphs
                });
            }
        }

        // Sort by distance (closest match first)
        matches.sort((a, b) => a.distance - b.distance);

        return {
            isSuspicious: matches.length > 0,
            matches: matches.slice(0, 3)  // Top 3 closest matches
        };
    }

    /**
     * Levenshtein distance between two strings.
     */
    private levenshtein(a: string, b: string): number {
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

    /**
     * Find homoglyph characters between two strings.
     */
    private findHomoglyphs(a: string, b: string): string[] {
        const found: string[] = [];
        const len = Math.min(a.length, b.length);
        for (let i = 0; i < len; i++) {
            if (a[i] !== b[i]) {
                const aHomoglyphs = HOMOGLYPHS[a[i]] || [];
                const bHomoglyphs = HOMOGLYPHS[b[i]] || [];
                if (aHomoglyphs.includes(b[i]) || bHomoglyphs.includes(a[i])) {
                    found.push(`${a[i]}→${b[i]}`);
                }
            }
        }
        return found;
    }
}
