import { lib, enc, mode, format, pad, AES } from "crypto-js"
import HmacSHA256 from "crypto-js/hmac-sha256";
import Base64 from "crypto-js/enc-base64";
import { KEYUTIL } from "jsrsasign";
import { binary_to_base58, base58_to_binary } from 'base58-js'
import elliptic from "elliptic";

const EC = elliptic.ec;

const CURVE_TYPE = "secp256k1";

const ecc = new EC(CURVE_TYPE);

import { Platform } from "react-native";
const isWeb = Platform.OS === "web";
var crypto = isWeb ? require('crypto-browserify') : null;
var randomBytes = !isWeb ? require('react-native-randombytes') : null;

function readKey(publicKey, publicKeyFile) {
    if (publicKey) {
        return publicKey;
    } else {
        try {
            var fs = require("fs");
            return fs.readFileSync(publicKeyFile).toString('utf8');
        } catch (e) {
            console.log(e);
        }
    }
}

function wordToByteArray(arr) {
    const byteArray = new Int8Array(arr.words.length * 4);
    var k = 0;
    for (var i = 0; i < arr.words.length; ++i) {
        const word = arr.words[i];
        for (var j = 3; j >= 0; --j) {
            byteArray[k++] = (word >> 8 * j) & 0xFF;
        }
    }
    return byteArray;
}

function toHex(arr) {
    let res = "";
    for (var i = 0; i < arr.length; ++i) {
        const x = arr[i];
        const v = (x < 0 ? 256 + x : x).toString(16);
        if (v.length === 1) res += "0";
        res += v;
    }
    return res;
}

function fromHex(key, length) {
    const k = key.length % 2 === 1 ? "0" + key : key;
    const len = length != null ? length : k.length / 2;
    let result = new Int8Array(len);
    for (let i = 0; i < len - k.length / 2; i++) {
        result[i] = 0;
    }
    for (var i = 0; i < k.length / 2; ++i) {
        const w = parseInt(k.substring(i * 2, i * 2 + 2), 16);
        if (isNaN(w)) {
            result = null;
            break;
        }
        result[i + len - k.length / 2] = w;
    }
    return result;
}

function fromHexU(key, length) {
    const k = key.length % 2 === 1 ? "0" + key : key;
    const len = length != null ? length : k.length / 2;
    let result = new Uint8Array(len);
    for (let i = 0; i < len - k.length / 2; i++) {
        result[i] = 0;
    }
    for (let i = 0; i < k.length / 2; ++i) {
        const w = parseInt(k.substring(i * 2, i * 2 + 2), 16);
        if (isNaN(w)) {
            result = null;
            break;
        }
        result[i + len - k.length / 2] = w;
    }
    return result;
}

function strToUtf8Uint8Array(str) {
    let binaryArray = new Uint8Array(str.length);
    Array.prototype.forEach.call(binaryArray, function (el, idx, arr) { arr[idx] = str.charCodeAt(idx) });
    return binaryArray;
}

function decodePKCS8PublicKey(serverPubHex) {
    return KEYUTIL.getKey(serverPubHex, null, "pkcs8pub").pubKeyHex;
}

class KeyExchange {

    encrypt(secretKey, data, seed, iv) {
        const wkey = enc.Hex.parse(toHex(secretKey));
        var s = new Int8Array(iv.length);
        for (let i = 0; i < s.length; i++) {
            s[i] = iv[i] ^ seed[i % seed.length];
        }
        const wseed = enc.Hex.parse(toHex(s));

        return Buffer.from(AES.encrypt(data, wkey, {
            iv: wseed,
            mode: mode.CBC,
            padding: pad.Pkcs7,
        }).toString(), "base64");
    }

    decrypt(secretKey, data, seed, iv) {
        const wdata =  enc.Hex.parse(toHex(data))
        const wkey = enc.Hex.parse(toHex(secretKey));
        var s = new Int8Array(iv.length);
        for (let i = 0; i < s.length; i++) {
            s[i] = iv[i] ^ seed[i % seed.length];
        }
        const wseed = enc.Hex.parse(toHex(s));

        let encrypted = lib.CipherParams.create({
            ciphertext: wdata,
            formatter: format.OpenSSL
        });
        const decrypted = AES.decrypt(encrypted, wkey, {
            iv: wseed,
            mode: mode.CBC,
            padding: pad.Pkcs7,
        });
        return wordToByteArray(decrypted);
    }

    signHTTP(secret, url, apiKey, nonce, data) {
        const body = data.toString();
        const toSign = url + "\n" + apiKey + "\n" + nonce + "\n" + (body != null ? body : "{}");
        return this.signRequest(secret, toSign);
    }

    signWS(secret, data) {
        const toSign = data["x-api-key"] +
                 "\n" + (data["nonce"] || "null")+
                 "\n" + (data["signature"] || "null") +
                 "\n" + (data["organization"] || "null") +
                 "\n" + (data["account"] || "null") +
                 "\n" + (data["scope"] || "null") +
                 "\n" + (data["table"] || "null");
        return this.signRequest(secret, toSign);
    }

    signRequest(secret, toSign) {
        return HmacSHA256(
            lib.WordArray.create(new Buffer(toSign)),
            lib.WordArray.create(new Buffer(secret))
        ).toString(Base64);
    }
}

const getRandomValues = function getRandomValues(arr) {
    if (window.crypto) {
        window.crypto.getRandomValues(arr);
    } else {
        let orig = arr;
        if (arr.byteLength !== arr.length) {
            arr = new Uint8Array(arr.buffer)
        }
        const bytes = (randomBytes || crypto).randomBytes(arr.length);
        for (var i = 0; i < bytes.length; i++) {
            arr[i] = bytes[i]
        }

        return orig;
    }
}



const encodeString = (plaintext, key, iv) => {
    if (!key) {
        key = new Int8Array(32);
        getRandomValues(key);
    }

    if (!iv) {
        iv = new Int8Array(16);
        getRandomValues(iv);
    }

    const wkey = enc.Hex.parse(typeof key === "string" ? key : toHex(key))
    const wiv = enc.Hex.parse(typeof iv === "string" ? iv : toHex(iv));

    const encoded = AES.encrypt(plaintext.trim(), wkey, {
        iv: wiv,
        mode: mode.CBC,
        padding: pad.Pkcs7,
    }).toString();

    return { encoded, key, iv };
}

const decodeString = (encoded, key, iv) => {
    const wkey = enc.Hex.parse(typeof key === "string" ? key : toHex(key))
    const wiv = enc.Hex.parse(typeof iv === "string" ? iv : toHex(iv));

    const cipher = Buffer.from(encoded, "base64");
    let encrypted = lib.CipherParams.create({
        ciphertext: enc.Hex.parse(toHex(cipher)),
        formatter: format.OpenSSL
    });
    const decrypted = AES.decrypt(encrypted, wkey, {
        iv: wiv,
        mode: mode.CBC,
        padding: pad.Pkcs7,
    });
    const result = new TextDecoder().decode(new Uint8Array(wordToByteArray(decrypted))).trim();
    var end = result.length;
    for (; end > 0; end--) {
        if (result.charCodeAt(end - 1) > 31) {
            break;
        }
    }
    return end != result.length ? result.substr(0, end) : result;
}

const encodeStringFor = (plaintext, fromPrivateKey, toPubKey, iv) => {
    if (!iv) {
        iv = new Int8Array(16);
        getRandomValues(iv);
    }

    let pubKey;
    if (typeof toPubKey === "string") {
        if (toPubKey.startsWith("weave")) {
            pubKey = base58_to_binary(toPubKey.substr(5));
        } else if (toPubKey.startsWith("0x") || toPubKey.startsWith("0X")) {
            pubKey = fromHex(toPubKey.substr(2));
        } else {
            pubKey = base58_to_binary(toPubKey);
        }
    } else {
        pubKey = toPubKey;
    }
    const pub = ecc.keyFromPublic(pubKey);
    const bytes = typeof fromPrivateKey === "string" ? (fromPrivateKey.startsWith("0x") ? fromHex(fromPrivateKey.substr(2)) : base58_to_binary(fromPrivateKey)) : fromPrivateKey;
    const clientKeys = ecc.keyFromPrivate(bytes.length === 33 ? bytes.subarray(1) : bytes)
    const secretKey = fromHexU(clientKeys.derive(pub.getPublic()).toString(16), 32)

    const wkey = enc.Hex.parse(toHex(secretKey))
    const wiv = enc.Hex.parse(typeof iv === "string" ? iv : toHex(iv));

    const encoded = AES.encrypt(plaintext, wkey, {
        iv: wiv,
        mode: mode.CBC,
        padding: pad.Pkcs7,
    }).toString();

    return { encoded, secretKey, iv, pubKey };
}

const decodeStringFrom = (encoded, fromPubKey, toPrivateKey, iv) => {
    const wkey = enc.Hex.parse(typeof fromPubKey === "string" ? fromPubKey : toHex(fromPubKey))
    const wiv = enc.Hex.parse(typeof iv === "string" ? iv : toHex(iv));

    let pubKey;
    if (typeof fromPubKey === "string") {
        if (fromPubKey.startsWith("weave")) {
            pubKey = base58_to_binary(fromPubKey.substr(5));
        } else if (fromPubKey.startsWith("0x") || fromPubKey.startsWith("0X")) {
            pubKey = fromHex(fromPubKey.substr(2));
        } else {
            pubKey = base58_to_binary(fromPubKey);
        }
    } else {
        pubKey = fromPubKey;
    }
    const pub = ecc.keyFromPublic(pubKey);
    const bytes = typeof toPrivateKey === "string" ? (toPrivateKey.startsWith("0x") ? fromHex(fromPubKey.substr(2)) : base58_to_binary(toPrivateKey)) : toPrivateKey;
    const clientKeys = ecc.keyFromPrivate(bytes.length === 33 ? bytes.subarray(1) : bytes)
    const secretKey = fromHexU(clientKeys.derive(pub.getPublic()).toString(16), 32)
    console.log(pub)
    console.log(bytes)
    console.log(secretKey)

    const cipher = Buffer.from(encoded, "base64");
    let encrypted = lib.CipherParams.create({
        ciphertext: enc.Hex.parse(toHex(cipher)),
        formatter: format.OpenSSL
    });
    const decrypted = AES.decrypt(encrypted, wkey, {
        iv: wiv,
        mode: mode.CBC,
        padding: pad.Pkcs7,
    });
    const result = new TextDecoder().decode(new Uint8Array(wordToByteArray(decrypted))).trim();
    var end = result.length;
    for (; end > 0; end--) {
        if (result.charCodeAt(end - 1) > 31) {
            break;
        }
    }
    return end != result.length ? result.substr(0, end) : result;
}

const keys = {
    CURVE_TYPE,

    readKey,
    getRandomValues,

    decodePKCS8PublicKey,

    wordToByteArray,
    strToUtf8Uint8Array,
    toHex,
    fromHex,
    fromHexU,
    encodeString,
    encodeStringFor,
    decodeString,
    decodeStringFrom,

    KeyExchange
}

export default keys;