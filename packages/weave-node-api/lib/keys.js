import HmacSHA256 from "crypto-js/hmac-sha256.js";
import Base64 from "crypto-js/enc-base64.js";
import { KEYUTIL } from "jsrsasign";
import { Buffer } from "buffer";

import crypto from "crypto-js";
import crypt from "crypto";

const CURVE_TYPE = "secp256k1";

function readKey(publicKey, publicKeyFile) {
    if (publicKey) {
        return publicKey;
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
        const wkey = crypto.enc.Hex.parse(toHex(secretKey));
        var s = new Int8Array(iv.length);
        for (let i = 0; i < s.length; i++) {
            s[i] = iv[i] ^ seed[i % seed.length];
        }
        const wseed = crypto.enc.Hex.parse(toHex(s));

        return Buffer.from(crypto.AES.encrypt(data, wkey, {
            iv: wseed,
            mode: crypto.mode.CBC,
            padding: crypto.pad.Pkcs7,
        }).toString(), "base64");
    }

    decrypt(secretKey, data, seed, iv) {
        const wdata = crypto.enc.Hex.parse(toHex(data))
        const wkey = crypto.enc.Hex.parse(toHex(secretKey));
        var s = new Int8Array(iv.length);
        for (let i = 0; i < s.length; i++) {
            s[i] = iv[i] ^ seed[i % seed.length];
        }
        const wseed = crypto.enc.Hex.parse(toHex(s));

        let encrypted = crypto.lib.CipherParams.create({
            ciphertext: wdata,
            formatter: crypto.format.OpenSSL
        });
        const decrypted = crypto.AES.decrypt(encrypted, wkey, {
            iv: wseed,
            mode: crypto.mode.CBC,
            padding: crypto.pad.Pkcs7,
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
            crypto.lib.WordArray.create(new Buffer(toSign)),
            crypto.lib.WordArray.create(new Buffer(secret))
        ).toString(Base64);
    }
}

const getRandomValues = function getRandomValues(arr) {
    let orig = arr;
    if (arr.byteLength !== arr.length) {
        arr = new Uint8Array(arr.buffer)
    }
    const bytes = crypt.randomBytes(arr.length);
    for (var i = 0; i < bytes.length; i++) {
        arr[i] = bytes[i]
    }

    return orig;
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

    KeyExchange
}

export default keys;