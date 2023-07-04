import keys from './keys'
import ApiContext from './apicontext'
import Session from "./session"
import { addIntegritySignature } from "./helper"

import { enc } from "crypto-js"
import { v4 } from "uuid"

const RECONNECT_INTERVAL_MS = 1000;

class ClientWs {

    constructor(
        config
    ) {
        this.config = config;
        this.websocket = null;
        this.keyExchange = new keys.KeyExchange();
    }

    async init(resetHandlers = true, remotePublicKey) {
        const cfg = this.config.websocket;

        this.apiUrl = (cfg.useWss ? "wss" : "ws") + "://" + cfg.host + ":" + cfg.port;

        if (resetHandlers) {
            this.pendingRequests = {};
            this.subscriptionHandlers = {};
        }
        this.websocket = new WebSocket(this.apiUrl);

        this.websocket.onmessage= this.on_message;
        this.websocket.onerror = this.on_error;
        this.websocket.onclose = this.on_close;
        this.websocket.onopen = this.on_open;

        this.waitForConnection(
            () => this.initKeys(remotePublicKey),
            RECONNECT_INTERVAL_MS
        );

        let counter = 0;
        while (!this.websocket.readyState || !this.apiContext) {
            if (counter > 250) break;
            counter += 1;
            await new Promise(r => setTimeout(r, 10));
        }
    }

    on_message = (msg) => {
        if (msg.isTrusted) {
            try {
                //console.log(msg.data);
                const data = JSON.parse(msg.data);
                const id = data.id;

                const req = this.pendingRequests[id];
                if (req) {
                    let reply = data.reply;

                    if (reply.res === "fwd") {
                        const r = JSON.parse(reply.data);
                        const data = Buffer.from(r.msg, "base64");
                        const decrypted = this.keyExchange.decrypt(this.apiContext.secretKey, data, this.apiContext.seed, keys.fromHex(r["x-iv"]));
                        const msg = new Uint8Array(decrypted).reduce(
                            function (data, byte) {
                                return byte > 31 ? data + String.fromCharCode(byte) : data;
                            },
                            ''
                        );
                        reply = JSON.parse(msg);
                        //console.log(reply)
                    }

                    if (reply && reply.target && reply.target.operationType && reply.target.operationType.toLowerCase() === "login") {
                        if (reply.res === "err") {
                            console.log(reply)
                            req.resolve(null);
                        } else {
                            const sdata = JSON.parse(reply.data);
                            const secret = keys.wordToByteArray(enc.Hex.parse(sdata.secret)); //TODO: reduce the number of transformations (also in decrypt)
                            const decryptedSecret = this.keyExchange.decrypt(this.apiContext.secretKey, secret, this.apiContext.seed, keys.fromHex(sdata["x-iv"]));
                            // eslint-disable-next-line no-control-regex
                            const b64sec = new Buffer(decryptedSecret).toString("ascii").replace(/[!^\x00-\x19]/g, ""); // String.fromCharCode()
                            const decodedSecret = Buffer.from(b64sec, "base64");

                            sdata.secret = undefined;
                            const session = new Session(sdata, decodedSecret);
                            req.resolve(session);
                        }
                    }  else {
                        req.resolve(reply);
                    }
                } else if (data.event_id && data.sub_id) {
                    const handler = this.subscriptionHandlers[data.sub_id];
                    if (handler != null) {
                        handler(data);
                    } else {
	                    //console.log("Unknown request " + id);
                	}
                }

            } catch (e) {
                console.log(e);
            }
        }
    }

    on_error = (e) => {
        console.log(e);
    }

    on_close = (e) => {
        console.log("websocket closed");
        this.init(false);
    }

    on_open = (e) => {
        this.websocket = e.currentTarget;
    }

    waitForConnection = (callback, interval) => {
        const that = this;
        if (this.websocket.readyState === 1) {
            callback();
        } else {
            setTimeout(function () {
                that.waitForConnection(callback, interval);
            }, interval);
        }
    }

    async initKeys(remotePublicKey) {
        const cfg = this.config;

        const pubKey = remotePublicKey ? { data: remotePublicKey } : await this.publicKey(); //TODO: error handling
        this.remotePublicKey = remotePublicKey;
        this.serverPublicKey = pubKey.data;
        this.clientPublicKey = keys.readKey(cfg.publicKey, cfg.publicKeyFile);
        this.clientPrivateKey = keys.readKey(cfg.privateKey, cfg.privateKeyFile);

        const seed = keys.wordToByteArray(enc.Hex.parse(cfg.seed));
        this.apiContext = new ApiContext(
            seed,
            cfg.seed,
            this.serverPublicKey,
            this.clientPublicKey,
            this.clientPrivateKey
        );

        //console.log(this.apiContext)
    }

    version() {
        return this.sendRequest({"type": "version"}, false);
    }

    ping() {
        return this.sendRequest({"type": "ping"}, false);
    }

    publicKey() {
        return this.sendRequest({"type": "public_key"}, false);
    }

    sigKey(account = null) {
        return this.sendRequest(account ? {"type": "sig_key", "account": account} : {"type": "sig_key"}, false);
    }

    sendRequest(data, isAuth = true) {
        const id = v4().replace("-", "");
        data.id = id;

        var resolve, reject;
        const future = new Promise(function(res, rej){
            resolve = res;
            reject = rej;
        });
        this.pendingRequests[id] = { resolve, reject };

        const msg = JSON.stringify(data);
        console.log("Sending: " + msg);

        try {
            if (isAuth && this.config.encrypted) {
                var iv = new Int8Array(16);
                keys.getRandomValues(iv);
                const encrypted = this.keyExchange.encrypt(this.apiContext.secretKey, msg, this.apiContext.seed, iv).toString("base64");

                const request = {
                    "id": id,
                    "type": "enc",
                    "x-enc": encrypted,
                    "x-iv": keys.toHex(iv),
                    "x-key": this.apiContext.publicKey
                }
                this.websocket.send(JSON.stringify(request));
            } else {
                this.websocket.send(msg);
            }
        } catch (e) {
            console.log(e);
            console.log("Reconnecting");
            //TODO: restore pendingRequests and subscriptionHandlers
            this.init(false);
        }

        return future;
    }

    signString(toSign, iv) {
        const signed = this.keyExchange.encrypt(this.apiContext.secretKey, toSign, this.apiContext.seed, iv);
        return keys.toHex(signed);
    }

    login(organization, account, scopes, credentials = null) {
        var iv = new Int8Array(16);
        keys.getRandomValues(iv);

        const toSign = organization + "\n" + this.clientPublicKey + "\n" + scopes;
        const signature = this.signString(toSign, iv);

        return this.sendRequest({
            "type": "login",
            "organization": organization,
            "account": account,
            "scopes": scopes,
            "credentials": credentials,
            "signature": signature,
            "x-iv": keys.toHex(iv),
            "x-key": this.apiContext.publicKey,
            "x-sig-key": this.apiContext.sigKey,
            "x-dlg-sig": this.apiContext.createEd25519Signature(this.serverPublicKey),
            "x-own-sig": this.apiContext.createEd25519Signature(this.apiContext.publicKey)
        })
    }

    authPost(session, data) {
        data["x-api-key"] = session.apiKey;
        data["x-nonce"] = session.getNonce();
        data["x-sig"] = this.keyExchange.signWS(session.secret, data);

        return this.sendRequest(data)
    }

    logout(session) {
        return this.authPost(session, {
            "type": "logout",
            "organization": session.organization,
            "account": session.account
        });
    }

    status(session) {
        return this.authPost(session, {
            "type": "status",
            "organization": session.organization,
            "account": session.account
        });
    }

    terms(session, options) {
        return this.authPost(session, {
            "type": "terms",
            "organization": session.organization,
            "account": session.account,
            "options": options.toJson()
        });
    }

    createTable(session, scope, table, createOptions) {
        return this.authPost(session, {
            "type": "create",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table,
            "options": createOptions.toJson()
        });
    }

    dropTable(session, scope, table, dropOptions) {
        return this.authPost(session, {
            "type": "drop",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table,
            "options": dropOptions.toJson()
        });
    }

    write(session, scope, records, writeOptions) {
        const buildAndSendMessage = () => {
            let data = {
                "type": "write",
                "organization": session.organization,
                "account": session.account,
                "scope": scope,
                "table": records.table,
                "enc": "json",
                "records": records.toJson(),
                "options": writeOptions.toJson()
            };
            return this.authPost(session, data);
        }

        if (session.integrityChecks) {
            return addIntegritySignature(records, session, scope, this).then(integrity => {
                records.integrity = integrity;
                return buildAndSendMessage();
            });
        } else {
	        return buildAndSendMessage();
    	}
    }

    read(session, scope, table, filter, readOptions) {
        const data = {
            "type": "read",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table,
            "options": readOptions.toJson()
        };

        if (filter) {
            data["filter"] = filter.toJson();
        }
        return this.authPost(session, data);
    }

    count(session, scope, table, filter, readOptions) {
        const data = {
            "type": "count",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table,
            "options": readOptions.toJson()
        };

        if (filter) {
            data["filter"] = filter.toJson();
        }
        return this.authPost(session, data);
    }

    delete(session, scope, table, filter, deleteOptions) {
        const data = {
            "type": "delete",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table,
            "options": deleteOptions.toJson()
        };

        if (filter) {
            data["filter"] = filter.toJson();
        }
        return this.authPost(session, data);
    }

    hashes(session, scope, table, filter, readOptions) {
        const data = {
            "type": "hashes",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table,
            "options": readOptions.toJson()
        };

        if (filter) {
            data["filter"] = filter.toJson();
        }
        return this.authPost(session, data);
    }

    hashCheckpoint(session, enable) {
        const data = {
            "type": "hash_checkpoint",
            "organization": session.organization,
            "account": session.account,
            "enable": enable
        };
        return this.authPost(session, data);
    }

    downloadTable(session, scope, table, filter, format, readOptions) {
        const data = {
            "type": "download_table",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table,
            "format": format,
            "options": readOptions.toJson()
        };

        if (filter) {
            data["filter"] = filter.toJson();
        }
        return this.authPost(session, data);
    }

    downloadDataset(session, did, readOptions) {
        const data = {
            "type": "download_dataset",
            "organization": session.organization,
            "account": session.account,
            "did": did,
            "options": readOptions.toJson()
        };

        return this.authPost(session, data);
    }

    publishDataset(session, did, name, description, license, metadata, weave, fullDescription, logo, category, scope, table, filter, format, price, token, pageorder, publishOptions) {
        const data = {
            "type": "publish_dataset",
            "organization": session.organization,
            "account": session.account,
            "did": did,
            "name": name,
            "description": description,
            "license": license,
            "metadata": metadata,
            "weave": weave,
            "full_description": fullDescription,
            "logo": logo,
            "category": category,
            "scope": scope,
            "table": table,
            "format": format,
            "price": price,
            "token": token,
            "pageorder": pageorder,
            "options": publishOptions.toJson()
        };

        if (filter) {
            data["filter"] = filter.toJson();
        }
        return this.authPost(session, data);
    }

    enableProduct(session, did, productType, active) {
        const data = {
            "type": "enable_product",
            "organization": session.organization,
            "account": session.account,
            "did": did,
            "productType": productType,
            "active": active
        };

        return this.authPost(session, data);
    }

    runTask(session, did, computeOptions) {
        const data = {
            "type": "run_task",
            "organization": session.organization,
            "account": session.account,
            "did": did,
            "options": computeOptions.toJson()
        };

        return this.authPost(session, data);
    }

    publishTask(session, did, name, description, license, metadata, weave, fullDescription, logo, category, task, price, token, pageorder, publishOptions) {
        const data = {
            "type": "publish_task",
            "organization": session.organization,
            "account": session.account,
            "did": did,
            "name": name,
            "description": description,
            "license": license,
            "metadata": metadata,
            "weave": weave,
            "full_description": fullDescription,
            "logo": logo,
            "category": category,
            "task": task,
            "price": price,
            "token": token,
            "pageorder": pageorder,
            "options": publishOptions.toJson()
        };

        return this.authPost(session, data);
    }

    async subscribe(session, scope, table, filter, subscribeOptions, updateHandler) {
        const data = {
            "type": "subscribe",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table,
            "options": subscribeOptions.toJson()
        };

        if (filter) {
            data["filter"] = filter.toJson();
        }
        const reply = await this.authPost(session, data);
        if (reply.res === "ok" && reply.data) {
            this.subscriptionHandlers[reply.data] = updateHandler;
        }
        return reply;
    }

    unsubscribe(session, subscriptionId) {
        const data = {
            "type": "unsubscribe",
            "organization": session.organization,
            "account": session.account,
            "subscriptionId": subscriptionId
        };

        this.subscriptionHandlers[subscriptionId] = null;

        return this.authPost(session, data);
    }

    compute(session, image, options) {
        const data = {
            "type": "compute",
            "organization": session.organization,
            "account": session.account,
            "image": image,
            "options": options.toJson()
        };

        return this.authPost(session, data);
    }

    flearn(session, image, options) {
        const data = {
            "type": "flearn",
            "organization": session.organization,
            "account": session.account,
            "image": image,
            "options": options.toJson()
        };

        return this.authPost(session, data);
    }

    forwardApi(session, feedId, params) {
        const data = {
            "type": "forward_api",
            "organization": session.organization,
            "account": session.account,
            "feedId": feedId,
            "params": typeof params === "string" ? params : JSON.stringify(params)
        };

        return this.authPost(session, data);
    }

    uploadApi(session, params) {
        const data = {
            "type": "upload_api",
            "organization": session.organization,
            "account": session.account,
            "params": typeof params === "string" ? params : JSON.stringify(params)
        };

        return this.authPost(session, data);
    }

    heGetInputs(session, datasources, args) {
        const data = {
            "type": "he_get_inputs",
            "organization": session.organization,
            "account": session.account,
            "datasources": datasources,
            "args": args
        };

        return this.authPost(session, data);
    }

    heGetOutputs(session, encoded, args) {
        const data = {
            "type": "he_get_outputs",
            "organization": session.organization,
            "account": session.account,
            "encoded": encoded,
            "args": args
        };

        return this.authPost(session, data);
    }

    heEncode(session, items) {
        const data = {
            "type": "he_encode",
            "organization": session.organization,
            "account": session.account,
            "items": items
        };

        return this.authPost(session, data);
    }

    mpc(session, scope, table, algo, fields, filter, options) {
        const data = {
            "type": "mpc",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table,
            "algo": algo,
            "fields": typeof fields === "string" ? fields : JSON.stringify(fields),
            "options": options.toJson()
        };

        if (filter) {
            data["filter"] = filter.toJson();
        }
        return this.authPost(session, data);
    }

    storageProof(session, scope, table, filter, challenge, options) {
        const data = {
            "type": "storage_proof",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table,
            "challenge": challenge,
            "options": options.toJson()
        };

        if (filter) {
            data["filter"] = filter.toJson();
        }
        return this.authPost(session, data);
    }

    zkStorageProof(session, scope, table, filter, challenge, options) {
        const data = {
            "type": "zk_storage_proof",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table,
            "challenge": challenge,
            "options": options.toJson()
        };

        if (filter) {
            data["filter"] = filter.toJson();
        }
        return this.authPost(session, data);
    }

    merkleTree(session, scope, table, filter, salt, digest, options) {
        const data = {
            "type": "merkle_tree",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table,
            "salt": salt,
            "digest": digest,
            "options": options.toJson()
        };

        if (filter) {
            data["filter"] = filter.toJson();
        }
        return this.authPost(session, data);
    }

    merkleProof(session, scope, table, hash) {
        const data = {
            "type": "merkle_proof",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table,
            "hash": hash
        };

        return this.authPost(session, data);
    }

    zkMerkleTree(session, scope, table, filter, salt, digest, rounds, seed, options) {
        const data = {
            "type": "zk_merkle_tree",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table,
            "salt": salt,
            "digest": digest,
            "rounds": rounds,
            "seed": seed,
            "options": options.toJson()
        };

        if (filter) {
            data["filter"] = filter.toJson();
        }
        return this.authPost(session, data);
    }

    rootHash(session, scope, table) {
        const data = {
            "type": "root_hash",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table
        };

        return this.authPost(session, data);
    }

    mimcHash(session, data, rounds, seed) {
        const pdata = {
            "type": "mimc_hash",
            "organization": session.organization,
            "account": session.account,
            "data": data,
            "rounds": rounds,
            "seed": seed
        };

        return this.authPost(session, pdata);
    }

    proofsLastHash(session, scope, table) {
        const pdata = {
            "type": "proofs_last_hash",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table
        };

        return this.authPost(session, pdata);
    }

    updateProofs(session, data, rounds, seed) {
        const pdata = {
            "type": "update_proofs",
            "organization": session.organization,
            "account": session.account,
            "rounds": rounds,
            "seed": seed
        };

        return this.authPost(session, pdata);
    }

    verifyMerkleHash(session, tree, hash, digest) {
        const data = {
            "type": "verify_merkle_hash",
            "tree": tree,
            "hash": hash,
            "digest": digest
        };

        return this.authPost(session, data);
    }

    getSidechainDetails(session) {
        const data = {
            "type": "get_sidechain_details",
        };
        return this.authPost(session, data);
    }

    getUserDetails(session, publicKey) {
        const data = {
            "type": "get_user_details",
            publicKey,
        };
        return this.authPost(session, data);
    }

    getNodes(session) {
        const data = {
            "type": "get_nodes",
        };
        return this.authPost(session, data);
    }

    getScopes(session) {
        const data = {
            "type": "get_scopes",
        };
        return this.authPost(session, data);
    }

    getTables(session, scope) {
        const data = {
            "type": "get_tables",
            "scope": scope
        };
        return this.authPost(session, data);
    }

    getTableDefinition(session, scope, table) {
        const data = {
            "type": "get_table_definition",
            "scope": scope,
            "table": table
        };
        return this.authPost(session, data);
    }

    getNodeConfig(session, nodePublicKey) {
        const data = {
            "type": "get_node_config",
            "nodePublicKey": nodePublicKey
        };
        return this.authPost(session, data);
    }

    getAccountNotifications(session) {
        const data = {
            "type": "get_account_notifications",
        };
        return this.authPost(session, data);
    }

    updateLayout(session, scope, table, layout) {
        const data = {
            "type": "update_layout",
            "scope": scope,
            "table": table,
            "layout": layout
        };
        return this.authPost(session, data);
    }

    updateConfig(session, path, values) {
        const data = {
            "type": "get_node_config",
            "path": path,
            "values": values ? JSON.stringify(values) : null
        };
        return this.authPost(session, data);
    }

    grantRole(session, account, roles) {
        const data = {
            "type": "grant_role",
            "targetAccount": account,
            "roles": typeof roles === "string" ? roles : JSON.stringify(roles)
        };
        return this.authPost(session, data);
    }

    balance(session, accountAddress, scope, token) {
        var iv = new Int8Array(16);
        keys.getRandomValues(iv);

        const toSign = session.organization + "\n" + this.clientPublicKey + "\n" + accountAddress + "\n" + scope + "\n" + token;
        const signature = this.signString(toSign, iv);

        const data = {
            "type": "balance",
            "accountAddress": accountAddress,
            "scope": scope,
            "token": token,
            "signature": signature,
            "x-iv": keys.toHex(iv),
            "x-sig-key": this.apiContext.sigKey
        };
        return this.authPost(session, data);
    }

    transfer(session, accountAddress, scope, token, amount) {
        var iv = new Int8Array(16);
        keys.getRandomValues(iv);

        const toSign = session.organization + "\n" + this.clientPublicKey + "\n" + accountAddress + "\n" + scope + "\n" + token + "\n" + amount;
        const signature = this.signString(toSign, iv);

        const data = {
            "type": "transfer",
            "accountAddress": accountAddress,
            "scope": scope,
            "token": token,
            "amount": amount,
            "signature": signature,
            "x-iv": keys.toHex(iv),
            "x-sig-key": this.apiContext.sigKey
        };
        return this.authPost(session, data);
    }

    call(session, contractAddress, scope, fn, args) {
        var iv = new Int8Array(16);
        keys.getRandomValues(iv);

        const serialized = new Buffer(args).toString("base64")
        const toSign = session.organization + "\n" + this.clientPublicKey + "\n" + contractAddress + "\n" + scope + "\n" + fn + "\n" + serialized;
        const signature = this.signString(toSign, iv);

        const data = {
            "type": "call",
            "contractAddress": contractAddress,
            "scope": scope,
            "function": fn,
            "data": serialized,
            "signature": signature,
            "x-iv": keys.toHex(iv),
            "x-sig-key": this.apiContext.sigKey
        };
        return this.authPost(session, data);
    }

    updateFees(session, scope, fees) {
        var iv = new Int8Array(16);
        keys.getRandomValues(iv);

        const toSign = session.organization + "\n" + this.clientPublicKey + "\n" + scope + "\n" + fees;
        const signature = this.signString(toSign, iv);

        const data = {
            "type": "update_fees",
            "scope": scope,
            "fees": fees,
            "signature": signature,
            "x-iv": keys.toHex(iv),
            "x-sig-key": this.apiContext.sigKey
        };
        return this.authPost(session, data);
    }

    contractState(session, contractAddress, scope) {
        var iv = new Int8Array(16);
        keys.getRandomValues(iv);

        const toSign = session.organization + "\n" + this.clientPublicKey + "\n" + contractAddress + "\n" + scope;
        const signature = this.signString(toSign, iv);

        const data = {
            "type": "contract_state",
            "contractAddress": contractAddress,
            "scope": scope,
            "signature": signature,
            "x-iv": keys.toHex(iv),
            "x-sig-key": this.apiContext.sigKey
        };
        return this.authPost(session, data);
    }

    sign(data) {
        return this.apiContext.createEd25519Signature(data)
    }

    verifyKeySignature(publicKey, signature, data) {
        return this.apiContext.verifyEd25519Signature(publicKey, signature, data)
    }

    zkProof(session, scope, table, gadgetType, params, fields, filter, options) {
        const data = {
            "type": "zk_proof",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table,
            "gadget": gadgetType,
            "params": params,
            "fields": typeof fields === "string" ? fields : JSON.stringify(fields),
            "options": options.toJson()
        };

        if (filter) {
            data["filter"] = filter.toJson();
        }
        return this.authPost(session, data);
    }

    zkDataProof(session, gadgetType, params, values, options) {
        const data = {
            "type": "zk_data_proof",
            "organization": session.organization,
            "account": session.account,
            "gadget": gadgetType,
            "params": params,
            "values": values,
            "options": options.toJson()
        };

        return this.authPost(session, data);
    }

    verifyZkProof(session, proof, gadgetType, params, commitment, nGenerators) {
        const data = {
            "type": "zk_data_proof",
            "organization": session.organization,
            "account": session.account,
            "gadget": gadgetType,
            "params": params,
            "commitment": commitment,
            "nGenerators": nGenerators
        };

        return this.authPost(session, data);
    }

    taskLineage(session, taskId) {
        const data = {
            "type": "task_lineage",
            "organization": session.organization,
            "account": session.account,
            "taskId": taskId
        };

        return this.authPost(session, data);
    }

    verifyTaskLineage(session, lineageData) {
        const data = {
            "type": "verify_task_lineage",
            "organization": session.organization,
            "account": session.account,
            "metadata": lineageData
        };

        return this.authPost(session, data);
    }

    taskOutputData(session, taskId, options) {
        const data = {
            "type": "task_output_data",
            "organization": session.organization,
            "account": session.account,
            "taskId": taskId,
            "options": options.toJson()
        };

        return this.authPost(session, data);
    }

    history(session, scope, table, filter, historyOptions) {
        const data = {
            "type": "history",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table,
            "options": historyOptions.toJson()
        };

        if (filter) {
            data["filter"] = filter.toJson();
        }
        return this.authPost(session, data);
    }

    writers(session, scope, table, filter) {
       const data = {
           "type": "writers",
           "organization": session.organization,
           "account": session.account,
           "scope": scope,
           "table": table,
       };

       if (filter) {
           data["filter"] = filter.toJson();
       }
       return this.authPost(session, data);
    }

    tasks(session, scope, table, filter) {
       const data = {
           "type": "tasks",
           "organization": session.organization,
           "account": session.account,
           "scope": scope,
           "table": table,
       };

       if (filter) {
           data["filter"] = filter.toJson();
       }
       return this.authPost(session, data);
    }

    lineage(session, scope, table, filter) {
       const data = {
           "type": "lineage",
           "organization": session.organization,
           "account": session.account,
           "scope": scope,
           "table": table,
       };

       if (filter) {
           data["filter"] = filter.toJson();
       }
       return this.authPost(session, data);
    }

    deployOracle(session, oracleType, targetBlockchain, source, options) {
        const data = {
            "type": "deploy_oracle",
            "organization": session.organization,
            "account": session.account,
            "oracleType": oracleType,
            "targetBlockchain": targetBlockchain,
            "source": source,
            "options": options.toJson()
        };

        return this.authPost(session, data);
    }

    deployFeed(session, image, options) {
        const data = {
            "type": "deploy_feed",
            "organization": session.organization,
            "account": session.account,
            "image": image,
            "options": options.toJson()
        };

        return this.authPost(session, data);
    }

    removeFeed(session, feedId) {
        const data = {
            "type": "remove_feed",
            "organization": session.organization,
            "account": session.account,
            "feedId": feedId
        };

        return this.authPost(session, data);
    }

    startFeed(session, feedId, options) {
        const data = {
            "type": "start_feed",
            "organization": session.organization,
            "account": session.account,
            "feedId": feedId,
            "options": options.toJson()
        };

        return this.authPost(session, data);
    }

    stopFeed(session, feedId) {
        const data = {
            "type": "stop_feed",
            "organization": session.organization,
            "account": session.account,
            "feedId": feedId
        };

        return this.authPost(session, data);
    }

    issueCredentials(session, issuer, holder, credentials, options) {
        const data = {
            "type": "issue_credentials",
            "organization": session.organization,
            "account": session.account,
            "issuer": issuer,
            "holder": holder,
            "credentials": credentials,
            "options": options.toJson()
        };

        return this.authPost(session, data);
    }

    verifyCredentials(session, credentials, options) {
        const data = {
            "type": "verify_credentials",
            "organization": session.organization,
            "account": session.account,
            "credentials": credentials,
            "options": options.toJson()
        };

        return this.authPost(session, data);
    }

    createPresentation(session, credentials, subject, options) {
        const data = {
            "type": "create_presentation",
            "organization": session.organization,
            "account": session.account,
            "credentials": credentials,
            "subject": subject,
            "options": options.toJson()
        };

        return this.authPost(session, data);
    }

    signPresentation(session, presentation, domain, challenge, options) {
        const data = {
            "type": "sign_presentation",
            "organization": session.organization,
            "account": session.account,
            "presentation": presentation,
            "domain": domain,
            "challenge": challenge,
            "options": options.toJson()
        };

        return this.authPost(session, data);
    }

    verifyPresentation(session, signedPresentation, domain, challenge, options) {
        const data = {
            "type": "verify_presentation",
            "organization": session.organization,
            "account": session.account,
            "presentation": signedPresentation,
            "domain": domain,
            "challenge": challenge,
            "options": options.toJson()
        };

        return this.authPost(session, data);
    }

    verifyDataSignature(session, signer, signature, toSign) {
        const data = {
            "type": "verify_data_signature",
            "organization": session.organization,
            "account": session.account,
            "signer": signer,
            "signature": signature,
            "data": toSign
        };

        return this.authPost(session, data);
    }

    postMessage(session, targetInboxKey, message, options) {
        const data = {
            "type": "post_message",
            "organization": session.organization,
            "account": session.account,
            "targetInboxKey": targetInboxKey,
            "message": message,
            "options": options.toJson()
        };

        return this.authPost(session, data);
    }

    pollMessages(session, inboxKey, options) {
        const data = {
            "type": "poll_messages",
            "organization": session.organization,
            "account": session.account,
            "inboxKey": inboxKey,
            "options": options.toJson()
        };

        return this.authPost(session, data);
    }

    createAccount(session, path, values) {
        const data = {
            "type": "create_user_account",
            "path": path,
            "values": values ? JSON.stringify(values) : null
        };
        return this.authPost(session, data);
    }

    updateFee(session, path, scope, fee) {
		var iv = new Int8Array(16);
        keys.getRandomValues(iv);

        fee.scope = scope.name;

        const toSign = session.organization
            + "\n" + scope.creatorPublicKey
            + "\n" + scope.name 
            + "\n" + JSON.stringify(fee);
        const signature = this.signString(toSign, iv);

        scope.fee = fee;
        const data = {
            "type": "update_fees",
            "path": path,
            "scope": scope.name,
            "fees" : JSON.stringify(fee),
            "values": scope ? JSON.stringify(scope) : null,
            "signature": signature,
            "x-iv": keys.toHex(iv)
        };
        return this.authPost(session, data);
    }
    
    resetConfig(session) {
        const data = {
            "type": "reset_config",
        };
        return this.authPost(session, data);
    }

    withdraw(session, token, amount) {
        const data = {
            "type": "withdraw",
            "token": token,
            "amount": amount
        };
        return this.authPost(session, data);
    }

    withdrawAuthorize(session, token, address) {
        const toSign = token + "\n" + address;
        const data = {
            "type": "withdraw_auth",
            "token": token,
            "address": address,
            "signature": this.apiContext.createEd25519Signature(toSign)
        };
        return this.authPost(session, data);
    }

    pluginCall(session, plugin, request, args, timeout) {
        const data = {
            "plugin": plugin,
            "request": request,
            "args": JSON.stringify(args),
            "timeout": timeout
        };
        return this.authPost(session, data);
    }

    emailAuth(org, clientPubKey, targetWebUrl, email) {
        let toSign = clientPubKey + "\n" + email
        let signature =this.apiContext.createEd25519Signature(toSign)

        let data = {
            "organization": org,
            "clientPubKey": clientPubKey,
            "targetEmail": email,
            "targetWebUrl": targetWebUrl,
            "signature": signature,
            "x-sig-key": this.apiContext.sigKey
        }
        let encodedData = btoa(JSON.stringify(data))
        let body = {"encodedData": encodedData}
        this.sendRequest(body, false)
    }
}

export default ClientWs;