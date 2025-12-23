const fs = require('fs');
const path = require('path');

// Base directory for de4js
const DE4JS_DIR = path.join(__dirname, 'de4js');
const LIB_DIR = path.join(DE4JS_DIR, 'lib');

function loadScript(filePath) {
    const content = fs.readFileSync(filePath, 'utf8');
    // Basic shim for `self` if scripts use it (common in workers)
    const self = global;
    try {
        // Indirect eval to execute in global scope
        (0, eval)(content);
    } catch (e) {
        console.error(`Error loading script ${filePath}:`, e);
    }
}

// Load Utils Global
loadScript(path.join(LIB_DIR, 'utils.js'));

// Load Decoders
loadScript(path.join(DE4JS_DIR, 'third_party/js-beautify/unpackers/p_a_c_k_e_r_unpacker.js'));

const DECODERS = {
    'evaldecode': { path: 'lib/evaldecode.js', fn: (s) => EvalDecode(s) },
    '_numberencode': { path: 'lib/numberdecode.js', fn: (s) => _NumberDecode(s) },
    'arrayencode': { path: 'lib/arraydecode.js', fn: (s) => ArrayDecode(s, {}) },
    'jsfuck': { path: 'lib/jsfuckdecode.js', fn: (s) => JSFuckDecode(s) },
    'obfuscatorio': { path: 'lib/obfuscatorio.js', fn: (s) => ObfuscatorIO(s, {}) },
    'cleansource': { path: 'lib/cleansource.js', fn: (s) => CleanSource(s, {}) },
    'p_a_c_k_e_r': { external: true, fn: (s) => P_A_C_K_E_R.unpack(s) },
};

function detect(source) {
    if (typeof P_A_C_K_E_R !== 'undefined' && P_A_C_K_E_R.detect(source)) {
        // console.error("Detected p_a_c_k_e_r");
        return 'p_a_c_k_e_r';
    } else if (/^var\s_\d{4};[\s\n]*var\s_\d{4}\s?=/.test(source)) {
        return '_numberencode';
    } else if (source.indexOf("/｀ｍ´）ﾉ ~┻━┻   //*´∇｀*/ ['_'];") !== -1) {
        return 'aaencode';
    } else if (source.indexOf('$={___:++$,$$$$:(![]+"")[$]') !== -1) {
        return 'jjencode';
    } else if (source.replace(/[[\]()!+]/gm, '').trim() === '') {
        return 'jsfuck';
    } else if (
        source.indexOf(' ') === -1 &&
        (source.indexOf('%2') !== -1 || source.replace(/[^%]+/g, '').length > 3)
    ) {
        return 'urlencode';
    } else if (
        /((?![^_a-zA-Z$])[\w$]*)\(-?('|")(0x[a-f\d]+|\\x30\\x78[\\xa-f\d]+)\2(\s*,\s*('|").+?\5)?\)/i.test(source) ||
        /((?![^_a-zA-Z$])[\w$]*)\(0x[a-f\d]+\)/i.test(source)
    ) {
        return 'obfuscatorio';
    } else if (/^var\s+((?![^_a-zA-Z$])[\w$]*)\s*=\s*\[.*?\];/.test(source)) {
        return 'arrayencode';
    } else if (
        source.startsWith('//Protected by WiseLoop PHP JavaScript Obfuscator') ||
        source.includes(';eval(function(w,i,s,e)')
    ) {
        return 'wisefunction';
    } else if (source.indexOf('eval(') !== -1) {
        if (/\b(window|document|console)\.\b/i.test(source)) return null;
        return 'evalencode';
    }
    return null;
}

// Main execution
const source = fs.readFileSync(0, 'utf8'); // Read from stdin

try {
    const type = detect(source);
    console.error("DEBUG: Detected type:", type);
    if (type && DECODERS[type]) {
        if (!DECODERS[type].external) {
            // If path starts with lib/, assume relative to root (fix for my previous mistake if any)
            // But my previous mistake put 'lib/' in the value.
            // Let's just use DE4JS_DIR
            loadScript(path.join(DE4JS_DIR, DECODERS[type].path));
        }
        const result = DECODERS[type].fn(source);
        console.log(result);
    } else {
        // console.error("Obfuscation type not detected or supported:", type);
        console.log(source);
    }
} catch (e) {
    console.error("Deobfuscation failed:", e);
    console.log(source); // Fallback to original
}
