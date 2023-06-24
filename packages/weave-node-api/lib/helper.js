import Records from "./records.js";
import Record from "./record.js";
import Options from "./options.js";
import { Filter, FilterOp, Order } from "./filter.js";
import ApiContext from "./apicontext.js";
import keys from "./keys.js";

export const generateKeys = () => {
    return ApiContext.generateKeys();
}

export const toHex = (arg) => {
    return keys.toHex(arg);
}

export const fromHex = (arg) => {
    return keys.fromHex(arg);
}

export const fromHexU = (arg) => {
    return keys.fromHexU(arg);
}

export const getConfig = (sideChain, pub, pvk, encrypted) => {
    if (sideChain == null) return null;

    //TODO: handle default ports if not specified
    const idx = sideChain.indexOf("://");
    if (idx < 0) return null;
    const lidx = sideChain.lastIndexOf("/");

    const protocol = sideChain.substring(0, idx);
    const idxp = sideChain.lastIndexOf(":");
    const host = sideChain.substring(idx + 3, idxp);
    const port = sideChain.substring(idxp + 1, lidx);
    const seed = sideChain.substring(lidx + 1);

    const cfg = {
        apiVersion: 1,

        seed: seed,
        privateKey: pvk,
        publicKey: pub, //generate pub from pvk
        encrypted: encrypted != null ? !!encrypted : protocol === "http"
    };

    if (protocol === "http" || protocol === "https") {
        cfg["http"] = {
            host: host,
            port: port,
            useHttps: protocol === "https",
        };
    } else if (protocol === "ws" || protocol === "wss") {
        cfg["websocket"] = {
            host: host,
            port: port,
            useWss: protocol === "wss",
        };
    }

    //console.log(cfg)
    return cfg;
};

export const convert = (val, type) => {
    if (type === "LONG" || type === "TIMESTAMP") {
        if (isNaN(val)) {
            return val;
        }
        if (typeof val === "string") {
            return parseInt(val);
        }
        return val;
    }
    if (type === "DOUBLE") {
        if (isNaN(val)) {
            return val;
        }
        if (typeof val === "string") {
            return parseFloat(val);
        }
        return val;
    }
    if (type === "STRING") {
        return val !== null ? val + "" : null;
    }
}

export const standardizeRecord = (record, layout) => {
    if (!layout) { // if no layout, return without normalizing
        return record;
    }

    for (let i = 0; i < layout.length; i++) {
        if (i < record.length) {
            record[i] = convert(record[i], layout[i].type)
        } else {
            record[i] = null;
        }
    }
    return record;
}

export const standardizeWithoutOwner = (record, layout, ownerColumnIndex) => {
    if (!layout) { // if no layout, return without normalizing
        return record;
    }

    for (let i = 0; i < layout.length; i++) {
        if (i < record.length) {
            if (ownerColumnIndex == null || i != ownerColumnIndex) {
                record[i] = convert(record[i], layout[i].type)
            } else {
                record[i] = null;
            }
        } else {
            record[i] = null;
        }
    }
    return record;
}

export const getCachedTableDefinition = async (session, scope, table, client) => {
    let key = scope + ":" + table;
    if (session.tableLayoutCache[key]) {
        return session.tableLayoutCache[key];
    }
    let def;
    try {
        def = await client.getTableDefinition(session, scope, table);
    } catch(e) {
        console.log(e)
        return null;
    }
    if (!def.data) {
        console.log("Received no table definition for " + key);
        return null;
    }
    session.tableLayoutCache[key] = JSON.parse(def.data)?.layout;
    return session.tableLayoutCache[key];
}

export const encodeString = (plaintext, key = null, iv = null) => {
    return keys.encodeString(plaintext, key, iv);
}

export const decodeString = (encrypted, key, iv) => {
    return keys.decodeString(encrypted, key, iv);
}

export const encodeStringFor = (plaintext, fromPrivateKey, toPubKey, iv = null) => {
    return keys.encodeStringFor(plaintext, fromPrivateKey, toPubKey, iv);
}

export const decodeStringFrom = (encrypted, fromPubKey, toPrivateKey, iv) => {
    return keys.decodeStringFrom(encrypted, fromPubKey, toPrivateKey, iv);
}

export const addIntegritySignature = (records, session, scope, client) => {
    return getCachedTableDefinition(session, scope, records.table, client).then((tableDefinition) => {
        let idBuffer = '';
        let hashBuffer = '';
        let recordsArray = records.records;

        const idColumn = tableDefinition?.idColumnIndex;
        const ownerColumn = tableDefinition?.ownerColumnIndex;
        const layout = tableDefinition?.columns;

        let first = true;
        for (let i = 0; i < recordsArray.length; i++) {
            let record = standardizeWithoutOwner(recordsArray[i], layout, ownerColumn);
            // hash of single record
            let data = JSON.stringify(record);
            //console.log(data)
            let hash = client.keyExchange.signRequest(client.apiContext.seedHex, data);

            // append to buffers
            if (first) {
                first = false;
            } else {
                idBuffer += " ";
                hashBuffer += "\n";
            }
            idBuffer = idBuffer + (!idColumn || !record[idColumn] ? "null" : (record[idColumn]));
            hashBuffer = hashBuffer + hash;
        }

        let toSign = idBuffer + "\n" + hashBuffer;
        //console.log(toSign)
        let hashOfHashes = client.keyExchange.signRequest(client.apiContext.seedHex, toSign);

        const key = scope + ":" + records.table;
        const prevRecordsData = session.prevRecordsData[key];
        const count = prevRecordsData?.count || 1;

        let integrity = {
            recordsHash: hashOfHashes,
            count: count + "",
            pubKey: client.config.publicKey
        };

        if (prevRecordsData) {
            integrity.prevRecordsHash = prevRecordsData.hash;
        }
        session.prevRecordsData[key] = { hash: hashOfHashes, count: count + 1 };

        const serialization = JSON.stringify(integrity, Object.keys(integrity).sort());
        let signature = client.apiContext.createEd25519Signature(serialization);

        let integrityCheck = {...integrity, sig: signature};
        console.log(integrityCheck)
        return [ { sig: integrityCheck} ];
    });
}

const WeaveHelper = {
    getConfig,
    generateKeys,
    toHex,
    fromHex,
    fromHexU,
    standardizeRecord,
    standardizeWithoutOwner,
    addIntegritySignature,
    encodeString,
    encodeStringFor,
    decodeString,
    decodeStringFrom,
    Records,
    Record,
    Options,
    Filter,
    FilterOp,
    Order
};

export default WeaveHelper;