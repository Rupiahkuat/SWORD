"use strict";

const $ = (selector) => document.querySelector(selector);

/* =========================================================
   01 — PASSWORD GENERATOR
   ========================================================= */
const passwordLength = $("#password-length");
const passwordLengthValue = $("#password-length-value");
const passwordStrength = $("#password-strength");
const includeSymbols = $("#include-symbols");
const passwordOutput = $("#password-output");

const LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const NUMBERS = "0123456789";
const SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?";

function randomIndex(max) {
    if (crypto && crypto.getRandomValues) {
        const data = new Uint32Array(1);
        crypto.getRandomValues(data);
        return data[0] % max;
    }
    return Math.floor(Math.random() * max);
}

function generatePassword() {
    const length = Number(passwordLength.value);
    let chars = LETTERS + NUMBERS;

    if (includeSymbols.checked) {
        chars += SYMBOLS;
    }

    let result = "";
    for (let i = 0; i < length; i++) {
        result += chars[randomIndex(chars.length)];
    }

    passwordOutput.value = result;
    passwordLengthValue.textContent = length;
    updatePasswordStrength(length);
}

function updatePasswordStrength(length) {
    if (length < 8) {
        passwordStrength.textContent = "Weak password";
        passwordStrength.dataset.level = "weak";
    } else if (length <= 12) {
        passwordStrength.textContent = "Moderate password";
        passwordStrength.dataset.level = "medium";
    } else if (includeSymbols.checked) {
        passwordStrength.textContent = "Strong password";
        passwordStrength.dataset.level = "strong";
    } else {
        passwordStrength.textContent = "Good length — add symbols for more strength";
        passwordStrength.dataset.level = "medium";
    }
}

/* =========================================================
   COPY HELPER
   ========================================================= */
async function copyText(value, button) {
    if (!value) return;

    try {
        await navigator.clipboard.writeText(value);
        const oldText = button.textContent;
        button.textContent = "Copied!";
        setTimeout(() => { button.textContent = oldText; }, 1200);
    } catch {
        button.textContent = "Copy failed";
        setTimeout(() => { button.textContent = "Copy"; }, 1200);
    }
}

/* =========================================================
   02 — TEXT UTILITY
   ========================================================= */
const textInput = $("#text-input");
const characterCount = $("#character-count");
const wordCount = $("#word-count");

function updateTextStats() {
    const text = textInput.value;
    const trimmed = text.trim();
    characterCount.textContent = text.length;
    wordCount.textContent = trimmed ? trimmed.split(/\s+/).length : 0;
}

function removeDuplicates() {
    const lines = textInput.value.split(/\r?\n/);
    const unique = [...new Set(lines)];
    textInput.value = unique.join("\n");
    updateTextStats();
}

/* =========================================================
   03 — URL SECURITY CHECK
   ========================================================= */
const urlInput = $("#url-input");
const urlResult = $("#url-result");

function checkURL() {
    const value = urlInput.value.trim();
    if (!value) {
        urlResult.textContent = "⚠️ Masukkan URL terlebih dahulu.";
        return;
    }

    let url;
    try {
        url = new URL(value);
    } catch {
        urlResult.textContent = "❌ Format URL tidak valid.";
        return;
    }

    if (!["http:", "https:"].includes(url.protocol)) {
        urlResult.textContent = "⚠️ Skema URL harus HTTP atau HTTPS.";
        return;
    }

    const suspiciousPatterns = [
        /javascript:/i, /data:/i, /vbscript:/i, /%00/i, /\.\.\//, /<script/i
    ];
    const suspicious = suspiciousPatterns.some((pattern) => pattern.test(value));

    if (suspicious) {
        urlResult.textContent = `⚠️ URL valid, tetapi memiliki pola mencurigakan. Domain: ${url.hostname}`;
        return;
    }
    urlResult.textContent = `✅ URL terlihat valid. Domain: ${url.hostname}`;
}

/* =========================================================
   04 — BASE64 CONVERTER
   ========================================================= */
const base64Input = $("#base64-input");
const base64Output = $("#base64-output");
const base64Result = $("#base64-result");

function encodeBase64() {
    try {
        const bytes = new TextEncoder().encode(base64Input.value);
        let binary = "";
        bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
        base64Output.value = btoa(binary);
        base64Result.textContent = "✅ Encoding berhasil.";
    } catch {
        base64Result.textContent = "❌ Encoding gagal.";
    }
}

function decodeBase64() {
    try {
        const binary = atob(base64Input.value.trim());
        const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
        base64Output.value = new TextDecoder().decode(bytes);
        base64Result.textContent = "✅ Decoding berhasil.";
    } catch {
        base64Result.textContent = "❌ Format Base64 tidak valid / rusak.";
    }
}

/* =========================================================
   05 — HASH GENERATOR
   ========================================================= */
const hashInput = $("#hash-input");
const md5Output = $("#md5-output");
const sha256Output = $("#sha256-output");

async function updateSHA256(text) {
    const data = new TextEncoder().encode(text);
    const hash = await crypto.subtle.digest("SHA-256", data);
    sha256Output.value = [...new Uint8Array(hash)]
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("");
}

function md5(input) {
    function rotateLeft(value, amount) {
        return (value << amount) | (value >>> (32 - amount));
    }
    function add(x, y) {
        return (x + y) >>> 0;
    }

    const encoder = new TextEncoder();
    const bytes = Array.from(encoder.encode(input));
    const bitLength = bytes.length * 8;

    bytes.push(0x80);
    while (bytes.length % 64 !== 56) bytes.push(0);

    for (let i = 0; i < 8; i++) {
        bytes.push((bitLength / 2 ** (8 * i)) & 255);
    }

    let a0 = 0x67452301;
    let b0 = 0xefcdab89;
    let c0 = 0x98badcfe;
    let d0 = 0x10325476;

    const shifts = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    ];

    const constants = Array.from({ length: 64 }, (_, i) =>
        Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0
    );

    for (let offset = 0; offset < bytes.length; offset += 64) {
        const words = new Uint32Array(16);
        for (let i = 0; i < 16; i++) {
            const p = offset + i * 4;
            words[i] = bytes[p] | (bytes[p + 1] << 8) | (bytes[p + 2] << 16) | (bytes[p + 3] << 24);
        }

        let a = a0, b = b0, c = c0, d = d0;
        for (let i = 0; i < 64; i++) {
            let f, g;
            if (i < 16) { f = (b & c) | (~b & d); g = i; }
            else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) % 16; }
            else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) % 16; }
            else { f = c ^ (b | ~d); g = (7 * i) % 16; }

            const temp = d;
            d = c;
            c = b;

            const sum = add(add(a, f), add(constants[i], words[g]));
            b = add(b, rotateLeft(sum, shifts[i]));
            a = temp;
        }
        a0 = add(a0, a);
        b0 = add(b0, b);
        c0 = add(c0, c);
        d0 = add(d0, d);
    }

    return [a0, b0, c0, d0].map((word) =>
        [0, 1, 2, 3].map((i) => ((word >>> (8 * i)) & 255).toString(16).padStart(2, "0")).join("")
    ).join("");
}

async function updateHashes() {
    const value = hashInput.value;
    md5Output.value = md5(value);
    await updateSHA256(value);
}

/* =========================================================
   06 — JSON FORMATTER
   ========================================================= */
const jsonInput = $("#json-input");
const jsonResult = $("#json-result");

function formatJSON() {
    try {
        const parsed = JSON.parse(jsonInput.value);
        jsonInput.value = JSON.stringify(parsed, null, 4);
        jsonResult.textContent = "✅ JSON berhasil diformat.";
    } catch (error) {
        jsonResult.textContent = `❌ JSON tidak valid: ${error.message}`;
    }
}

/* =========================================================
   07 — HTML ESCAPER / UNESCAPER
   ========================================================= */
const htmlInput = $("#html-input");
const htmlOutput = $("#html-output");
const htmlResult = $("#html-result");

function escapeHTML() {
    const value = htmlInput.value;
    htmlOutput.value = value
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
    htmlResult.textContent = "✅ HTML berhasil di-escape.";
}

function unescapeHTML() {
    const value = htmlInput.value;
    const parser = new DOMParser();
    const documentFragment = parser.parseFromString(`<body>${value}</body>`, "text/html");
    htmlOutput.value = documentFragment.body.textContent || "";
    htmlResult.textContent = "✅ HTML berhasil di-unescape.";
}

/* =========================================================
   08 — UNIX TIMESTAMP CONVERTER
   ========================================================= */
const timestampInput = $("#timestamp-input");
const timestampResult = $("#timestamp-result");

function convertTimestamp() {
    const raw = timestampInput.value.trim();
    if (!raw) {
timestampResult.textContent = "⚠️ Masukkan timestamp terlebih dahulu.";
return;
}
const timestamp = Number(raw);
if (!Number.isFinite(timestamp)) {
timestampResult.textContent = "❌ Timestamp tidak valid.";
return;
}
const milliseconds = Math.abs(timestamp) < 1e11 ? timestamp * 1000 : timestamp;
const date = new Date(milliseconds);
if (Number.isNaN(date.getTime())) {
timestampResult.textContent = "❌ Timestamp menghasilkan tanggal tidak valid.";
return;
}
const localDate = date.toLocaleString("id-ID", { dateStyle: "full", timeStyle: "medium" });
const utcDate = date.toISOString();
timestampResult.textContent = Local: ${localDate}\nUTC: ${utcDate};
timestampResult.style.whiteSpace = "pre-line";
}
function useCurrentTimestamp() {
const timestamp = Math.floor(Date.now() / 1000);
timestampInput.value = timestamp;
convertTimestamp();
}
/* =========================================================
09 — URL ENCODER / DECODER
========================================================= */
const urlEncodeInput = $("#url-encode-input");
const urlEncodeOutput = $("#url-encode-output");
const urlEncodeResult = $("#url-result");
function encodeURL() {
const value = urlEncodeInput.value;
if (!value) {
urlEncodeResult.textContent = "⚠️ Masukkan data URL terlebih dahulu.";
return;
}
try {
urlEncodeOutput.value = encodeURIComponent(value);
urlEncodeResult.textContent = "✅ URL berhasil di-encode.";
} catch {
urlEncodeResult.textContent = "❌ Data URL tidak dapat di-encode.";
}
}
function decodeURL() {
const value = urlEncodeInput.value;
if (!value) {
urlEncodeResult.textContent = "⚠️ Masukkan data URL terlebih dahulu.";
return;
}
try {
urlEncodeOutput.value = decodeURIComponent(value);
urlEncodeResult.textContent = "✅ URL berhasil di-decode.";
} catch {
urlEncodeResult.textContent = "❌ Format URL encoded tidak valid / rusak.";
}
}
/* =========================================================
EVENT LISTENERS
========================================================= */
$("#generate-password").addEventListener("click", generatePassword);
passwordLength.addEventListener("input", generatePassword);
includeSymbols.addEventListener("change", generatePassword);
$("#copy-password").addEventListener("click", () => copyText(passwordOutput.value, $("#copy-password")));
textInput.addEventListener("input", updateTextStats);
$("#uppercase-text").addEventListener("click", () => { textInput.value = textInput.value.toUpperCase(); updateTextStats(); });
$("#lowercase-text").addEventListener("click", () => { textInput.value = textInput.value.toLowerCase(); updateTextStats(); });
$("#remove-duplicates").addEventListener("click", removeDuplicates);
$("#clear-text").addEventListener("click", () => { textInput.value = ""; updateTextStats(); });
$("#check-url").addEventListener("click", checkURL);
$("#base64-encode").addEventListener("click", encodeBase64);
$("#base64-decode").addEventListener("click", decodeBase64);
$("#copy-base64").addEventListener("click", () => copyText(base64Output.value, $("#copy-base64")));
hashInput.addEventListener("input", updateHashes);
$("#format-json").addEventListener("click", formatJSON);
$("#escape-html").addEventListener("click", escapeHTML);
$("#unescape-html").addEventListener("click", unescapeHTML);
$("#copy-html").addEventListener("click", () => copyText(htmlOutput.value, $("#copy-html")));
$("#convert-timestamp").addEventListener("click", convertTimestamp);
$("#current-timestamp").addEventListener("click", useCurrentTimestamp);
$("#encode-url").addEventListener("click", encodeURL);
$("#decode-url").addEventListener("click", decodeURL);
$("#copy-url-output").addEventListener("click", () => copyText(urlEncodeOutput.value, $("#copy-url-output")));
/* =========================================================
INITIAL STATE
========================================================= */
generatePassword();
updateTextStats();
updateHashes();
