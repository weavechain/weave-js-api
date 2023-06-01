import keys from "./keys";
import { binary_to_base58, base58_to_binary } from 'base58-js'

const MAX_B58_LEN = 55;

const CURVE_TYPE = "secp256k1";

const Buffer = require("buffer").Buffer
const EC = require("elliptic").ec;
const ec = new EC(CURVE_TYPE);

var EdDSA = require('elliptic').eddsa;
const ed = new EdDSA("ed25519");

const Random = require('java-random');

class ApiContext {
    constructor(
        seed,
        seedHex,
        serverPublicKey,
        clientPublicKey,
        clientPrivateKey
    ) {
        this.seed = seed
        this.seedHex = seedHex

        this.initKeys(serverPublicKey, clientPublicKey, clientPrivateKey);
    }

    byteArrayToLong = function(byteArray, size) {
        var value = 0;
        for (var i = 0; i < size; i++) {
            value =  value * 256 + byteArray[i];
        }
        return value;
    };

    initKeys(serverPublicKey, clientPublicKey, clientPrivateKey) {
        const clientKeys = ApiContext.unpackKeys(clientPrivateKey);
        if (!clientKeys) {
            throw(new Error("Invalid keys"))
        }

        this.publicKey = clientPublicKey
        this.clientPublicKey = new Int8Array(clientKeys.getPublic(false, "bytes"));
        this.clientPrivateKey = keys.fromHexU(clientKeys.getPrivate("hex"), 32);

        let pub = null;
        if (serverPublicKey.startsWith("weave")) {
            pub = ec.keyFromPublic(ApiContext.deserializePublic(serverPublicKey), "bytes");
            this.serverPublicKey = new Int8Array(pub.getPublic(false, "bytes"));
        } else {
            const serverPubBytes = ApiContext.deserializePublic(serverPublicKey);
            const serverPubHex = keys.toHex(serverPubBytes);
            this.serverPublicKey = ApiContext.deserializePublic(keys.decodePKCS8PublicKey(serverPubHex));
            pub = ec.keyFromPublic(ApiContext.deserializePublic(this.serverPublicKey), "bytes");
        }
        this.deriveSigKeys(clientKeys);

        this.secretKey = keys.fromHexU(clientKeys.derive(pub.getPublic()).toString(16), 32);
    }

    deriveSigKeys(clientKeys) {
        const seed = this.byteArrayToLong(this.clientPrivateKey, 6);
        const rng = new Random(seed);
        const bytes = new Uint8Array(32);
        for (let i = 0, len = bytes.length; i < len;) {
            for (let rnd = rng.nextInt(), n = Math.min(len - i, 4); n-- > 0; rnd >>= 8)
                bytes[i++] = rnd;
        }
        for (let i = 0; i < 32; i++) {
            bytes[i] ^= this.clientPrivateKey[i];
        }
        this.sigKeys = ed.keyFromSecret(bytes);
        this.sigKey = binary_to_base58(this.sigKeys.pubBytes())
    }

    createEd25519Signature(data) {
        const encoded = new Buffer(data).toString("hex");
        return binary_to_base58(this.sigKeys.sign(encoded).toBytes());
    }

    verifyEd25519Signature(publicKey, signature, data) {
        const sigKey = publicKey != null ? ed.keyFromPublic(keys.toHex(base58_to_binary(publicKey)), 'bytes') : this.apiContext.sigKeys;
        const sig = keys.toHex(base58_to_binary(signature));
        const encoded = new Buffer(data).toString("hex");
        return sigKey.verify(encoded, sig);
    }

    static unpackKeys(privateKey) {
        if (privateKey == null) return null;

        const bytes = ApiContext.deserializePrivate(privateKey, null);

        if (bytes.length <= 33) {
            return ec.keyFromPrivate(bytes.length === 33 ? bytes.subarray(1) : bytes);
        } else {
            return null;
        }
    }

    static deriveKeys(privateKey) {
        if (privateKey == null) return null;

        const bytes = ApiContext.deserializePrivate(privateKey, null);

        try {
            const data = keys.decodeX962PrivateKey(bytes);
            const key = ec.keyFromPrivate(data.length === 33 ? data.subarray(1) : data);
            return ApiContext.encodeKey(key);
        } catch (e) {
            if (bytes.length <= 33) {
                const key = ec.keyFromPrivate(bytes.length === 33 ? bytes.subarray(1) : bytes);
                return ApiContext.encodeKey(key);
            } else {
                return null;
            }
        }
    }

    static generateKeys() {
        const key = ec.genKeyPair();
        return ApiContext.encodeKey(key)
    }

    static encodeKey(key) {
        const publicKey = "weave" + binary_to_base58(keys.fromHexU(key.getPublic(true, 'hex')));
        const privateKey = binary_to_base58(keys.fromHexU(key.getPrivate('hex')));
        return [ publicKey, privateKey ];
    }

    static verifyKey(key) {
        try {
            const keys = ApiContext.deriveKeys(key);
            return keys != null ? null : "Invalid Private Key Format";
        } catch (e) {
            console.log(e)
            return "Invalid Private Key Format";
        }
    }

    static deserialize(key) {
        try {
            let result = keys.fromHex(key);
            if (result == null) {
                if (key.length < MAX_B58_LEN) { //TODO: maybe drop PEM format support to remove hacky check
                    return base58_to_binary(key);
                } else {
                    try {
                        return new Int8Array(base58_to_binary(key))
                    } catch (ex) {
                        return new Int8Array(Buffer.from(key, 'base64')); //new Int8Array(atob(key).split("").map(function(c) { return c.charCodeAt(0); }));
                    }
                }
            } else {
                return result;
            }
        } catch (e) {
            console.log(e);
            return null;
        }
    }

    static deserializePublic(key) {
        try {
            if (key.length > 5 && key.startsWith("weave")) {
                return base58_to_binary(key.substr(5));
            } else {
                return ApiContext.deserialize(key);
            }
        } catch (e) {
            console.log(e);
            return null;
        }
    }

    static deserializePrivate(key, password) {
        try {
            return ApiContext.deserialize(key);
        } catch (e) {
            console.log(e);
            return null;
        }
    }
}

export default ApiContext;