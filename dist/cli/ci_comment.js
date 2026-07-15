"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.detectCiEnv = detectCiEnv;
exports.postPrComment = postPrComment;
function detectCiEnv() {
    const repo = process.env.GITHUB_REPOSITORY;
    const token = process.env.GITHUB_TOKEN;
    const prEnv = process.env.GITHUB_PR_NUMBER;
    const ghRef = process.env.GITHUB_REF;
    if (!repo || !token) {
        return { isCi: false };
    }
    let prNumber;
    if (prEnv) {
        prNumber = parseInt(prEnv, 10);
    }
    else if (ghRef) {
        const match = ghRef.match(/refs\/pull\/(\d+)\/merge/);
        if (match) {
            prNumber = parseInt(match[1], 10);
        }
    }
    if (!prNumber || isNaN(prNumber)) {
        return { isCi: false };
    }
    return { isCi: true, repo, prNumber, token };
}
function postPrComment(config) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const url = `https://api.github.com/repos/${config.repo}/issues/${config.prNumber}/comments`;
            const response = yield fetch(url, {
                method: 'POST',
                headers: {
                    Authorization: `Bearer ${config.token}`,
                    'Content-Type': 'application/json',
                    'User-Agent': 'sentinel-cli/4.0',
                },
                body: JSON.stringify({ body: config.markdownReport }),
            });
            if (response.status === 201) {
                const data = yield response.json();
                return { posted: true, url: data.html_url };
            }
            const errorBody = yield response.text().catch(() => 'Unknown error');
            return { posted: false, error: `GitHub API returned ${response.status}: ${errorBody}` };
        }
        catch (err) {
            return { posted: false, error: err instanceof Error ? err.message : String(err) };
        }
    });
}
