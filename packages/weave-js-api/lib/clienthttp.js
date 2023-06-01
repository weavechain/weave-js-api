import keys from './keys'
import ApiContext from './apicontext'
import Session from "./session"
import { addIntegritySignature } from "./helper"

import { enc } from "crypto-js"

const Buffer = require("buffer").Buffer

class ClientHttp {

    constructor(
        config
    ) {
        this.version = "v1";

        this.config = config;
        this.keyExchange = new keys.KeyExchange();
    }

    async init(remotePublicKey) {
        const cfg = this.config.http;

        //TODO: async calls
        this.apiUrl = (cfg.useHttps ? "https" : "http") + "://" + cfg.host + ":" + cfg.port;

        await this.initKeys(remotePublicKey);
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
        return fetch(this.apiUrl + "/version", {
            method: "GET"
        });
    }

    get(call) {
        console.log(this.apiUrl + "/" + this.version + "/" + call)
        return fetch(this.apiUrl + "/" + this.version + "/" + call, {
            method: "GET"
        }).then((response) => {
            if (!response.ok) {
                console.log(response);
                return null;
            } else {
                return response.json();
            }
        });
    }

    post(call, body, headers) {
        if (this.config.encrypted) {
            const toSend = JSON.stringify({
                call,
                body,
                headers
            });

            var iv = new Int8Array(16);
            keys.getRandomValues(iv);
            const encrypted = this.keyExchange.encrypt(this.apiContext.secretKey, toSend, this.apiContext.seed, iv).toString("base64");

            const request = {
                "x-enc": encrypted,
                "x-iv": keys.toHex(iv),
                "x-key": this.apiContext.publicKey
            }

            return fetch(this.apiUrl + "/" + this.version + "/enc", {
                method: "POST",
                body: JSON.stringify(request),
            }).then((response) => {
                if (!response.ok) {
                    console.log(response);
                    return null;
                } else {
                    return response.json().then((r) => {
                        const reply = JSON.parse(r.data);
                        const data = Buffer.from(reply.msg, "base64");
                        const decrypted = this.keyExchange.decrypt(this.apiContext.secretKey, data, this.apiContext.seed, keys.fromHex(reply["x-iv"]));
                        const msg = new Uint8Array(decrypted).reduce(
                            function (data, byte) {
                                return byte > 31 ? data + String.fromCharCode(byte) : data;
                            },
                            ''
                        );
                        const result = JSON.parse(msg);
                        return result;
                    });
                }
            });
        } else {
            return fetch(this.apiUrl + "/" + this.version + "/" + call, {
                method: "POST",
                body: body,
                headers: headers != null ? new Headers(headers) : undefined,
            }).then((response) => {
                if (!response.ok) {
                    console.log(response);
                    return null;
                } else {
                    return response.json();
                }
            });
        }
    }

    ping() {
        return this.get("ping");
    }

    publicKey() {
        return this.get("public_key");
    }

    sigKey() {
        return this.get("sig_key");
    }

    signString(toSign, iv) {
        const signed = this.keyExchange.encrypt(this.apiContext.secretKey, toSign, this.apiContext.seed, iv);
        return keys.toHex(signed);
    }

    async login(organization, account, scopes, credentials = null) {
        var iv = new Int8Array(16);
        keys.getRandomValues(iv);

        const toSign = organization + "\n" + this.clientPublicKey + "\n" + scopes;
        const signature = this.signString(toSign, iv);

        const data = {
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
        };
        const body = JSON.stringify(data);
        const reply = await this.post("login", body, null);

        if (reply.data && reply.res !== "err") {
            const sdata = JSON.parse(reply.data);
            const secret = keys.wordToByteArray(enc.Hex.parse(sdata.secret)); //TODO: reduce the number of transformations (also in decrypt)
            const decryptedSecret = this.keyExchange.decrypt(this.apiContext.secretKey, secret, this.apiContext.seed, keys.fromHex(sdata["x-iv"]));
            // eslint-disable-next-line no-control-regex
            const b64sec = new Buffer(decryptedSecret).toString("ascii").replace(/[!^\x00-\x19]/g, ""); // String.fromCharCode()
            const decodedSecret = Buffer.from(b64sec, "base64");

            sdata.secret = undefined;
            return new Session(sdata, decodedSecret);
        } else {
            console.log(reply);
            return { error: reply };
        }
    }

    authPost(session, call, data) {
        data["organization"] = session.organization
        data["account"] = session.account

        const body = JSON.stringify(data);
        const nonce = session.getNonce().toString();
        const signature = this.keyExchange.signHTTP(
            session.secret,
            "/" + this.version + "/" + call,
            session.apiKey,
            nonce,
            body
        );

        const headers = {
            "x-api-key": session.apiKey,
            "x-nonce": nonce,
            "x-sig": signature
        };

        return this.post(call, body, headers);
    }

    logout(session) {
        return this.authPost(session, "logout", {});
    }

    status(session) {
        return this.authPost(session, "status", {});
    }

    terms(session, options) {
        return this.authPost(session, "terms",  {
            "options": options.toJson()
        });
    }

    createTable(session, scope, table, createOptions) {
        return this.authPost(session, "create",  {
            "scope": scope,
            "table": table,
            "options": createOptions.toJson()
        });
    }

    dropTable(session, scope, table, dropOptions) {
        return this.authPost(session, "drop",  {
            "scope": scope,
            "table": table,
            "options": dropOptions.toJson()
        });
    }

    write(session, scope, records, writeOptions) {
        const buildAndSendMessage = () => {
            let body = {
                "scope": scope,
                "table": records.table,
                "enc": "json",
                "records": records.toJson(),
                "options": writeOptions.toJson()
            };
            return this.authPost(session, "write", body);
        };

        if (session.integrityChecks) {
            return addIntegritySignature(records, session, scope, this).then(integrity => {
                records.integrity = integrity;
                buildAndSendMessage();
            });
        } else {
	        return buildAndSendMessage();
    	}
    }

    read(session, scope, table, filter, readOptions) {
        const data = {
            "scope": scope,
            "table": table,
            "options": readOptions.toJson()
        };

        if (filter) {
            data["filter"] = filter.toJson();
        }
        return this.authPost(session, "read", data);
    }

    count(session, scope, table, filter, readOptions) {
        const data = {
            "scope": scope,
            "table": table,
            "options": readOptions.toJson()
        };

        if (filter) {
            data["filter"] = filter.toJson();
        }
        return this.authPost(session, "count", data);
    }

    delete(session, scope, table, filter, deleteOptions) {
        const data = {
            "scope": scope,
            "table": table,
            "options": deleteOptions.toJson()
        };

        if (filter) {
            data["filter"] = filter.toJson();
        }
        return this.authPost(session, "delete", data);
    }

    hashes(session, scope, table, filter, readOptions) {
        const data = {
            "scope": scope,
            "table": table,
            "options": readOptions.toJson()
        };

        if (filter) {
            data["filter"] = filter.toJson();
        }
        return this.authPost(session, "hashes", data);
    }

    hashCheckpoint(session, enable) {
        const data = {
            "enable": enable
        };

        return this.authPost(session, "hash_checkpoint", data);
    }

    downloadTable(session, scope, table, filter, format, readOptions) {
        const data = {
            "scope": scope,
            "table": table,
            "format": format,
            "options": readOptions.toJson()
        };

        if (filter) {
            data["filter"] = filter.toJson();
        }
        return this.authPost(session, "download_table", data);
    }

    downloadDataset(session, did, readOptions) {
        const data = {
            "did": did,
            "options": readOptions.toJson()
        };
        return this.authPost(session, "download_dataset", data);
    }

    publishDataset(session, did, name, description, license, metadata, weave, fullDescription, logo, category, scope, table, filter, format, price, token, pageorder, publishOptions) {
        const data = {
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
        return this.authPost(session, "publish_dataset", data);
    }

    enableProduct(session, did, productType, active) {
        const data = {
            "did": did,
            "productType": productType,
            "active": active
        };

        return this.authPost(session, "enable_product", data);
    }

    runTask(session, did, computeOptions) {
        const data = {
            "did": did,
            "options": computeOptions.toJson()
        };
        return this.authPost(session, "run_task", data);
    }

    publishTask(session, did, name, description, license, metadata, weave, fullDescription, logo, category, task, price, token, pageorder, publishOptions) {
        const data = {
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

        return this.authPost(session, "publish_task", data);
    }

    subscribe(session, scope, table, filter, subscribeOptions, updateHandler) {
        const data = {
            "scope": scope,
            "table": table,
            "options": subscribeOptions.toJson()
        };

        if (filter) {
            data["filter"] = filter.toJson();
        }
        return this.authPost(session, "subscribe", data);
    }

    unsubscribe(session, subscriptionId) {
        const data = {
            "subscriptionId": subscriptionId
        };

        return this.authPost(session, "unsubscribe", data);
    }

    compute(session, image, options) {
        const data = {
            "image": image,
            "options": options.toJson()
        };

        return this.authPost(session, "compute", data);
    }

    flearn(session, image, options) {
        const data = {
            "image": image,
            "options": options.toJson()
        };

        return this.authPost(session, "flearn", data);
    }

    forwardApi(session, feedId, params) {
        const data = {
            "feedId": feedId,
            "params": typeof params === "string" ? params : JSON.stringify(params)
        };

        return this.authPost(session, "forward_api", data);
    }

    uploadApi(session, params) {
        const data = {
            "params": typeof params === "string" ? params : JSON.stringify(params)
        };

        return this.authPost(session, "upload_api", data);
    }

    heGetInputs(session, datasources, args) {
        const data = {
            "datasources": datasources,
            "args": args
        };

        return this.authPost(session, "he_get_inputs", data);
    }

    heGetOutputs(session, encoded, args) {
        const data = {
            "encoded": encoded,
            "args": args
        };

        return this.authPost(session, "he_get_outputs", data);
    }

    heEncode(session, items) {
        const data = {
            "items": items
        };

        return this.authPost(session, "he_encode", data);
    }

    mpc(session, scope, table, algo, fields, filter, options) {
        const data = {
            "scope": scope,
            "table": table,
            "algo": algo,
            "fields": typeof fields === "string" ? fields : JSON.stringify(fields),
            "options": options.toJson()
        };

        if (filter) {
            data["filter"] = filter.toJson();
        }

        return this.authPost(session, "mpc", data);
    }

    storageProof(session, scope, table, filter, challenge, options) {
        const data = {
            "scope": scope,
            "table": table,
            "challenge": challenge,
            "options": options.toJson()
        };

        if (filter) {
            data["filter"] = filter.toJson();
        }

        return this.authPost(session, "storage_proof", data);
    }

    zkStorageProof(session, scope, table, filter, challenge, options) {
        const data = {
            "scope": scope,
            "table": table,
            "challenge": challenge,
            "options": options.toJson()
        };

        if (filter) {
            data["filter"] = filter.toJson();
        }

        return this.authPost(session, "zk_storage_proof", data);
    }

    merkleTree(session, scope, table, filter, salt, digest, options) {
        const data = {
            "scope": scope,
            "table": table,
            "salt": salt,
            "digest": digest,
            "options": options.toJson()
        };

        if (filter) {
            data["filter"] = filter.toJson();
        }

        return this.authPost(session, "merkle_tree", data);
    }

    merkleProof(session, scope, table, hash) {
        const data = {
            "scope": scope,
            "table": table,
            "hash": hash
        };

        return this.authPost(session, "merkle_proof", data);
    }

    zkMerkleTree(session, scope, table, filter, salt, digest, rounds, seed, options) {
        const data = {
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

        return this.authPost(session, "zk_merkle_tree", data);
    }

    rootHash(session, scope, table) {
        const data = {
            "scope": scope,
            "table": table
        };

        return this.authPost(session, "root_hash", data);
    }

    mimcHash(session, data, rounds, seed) {
        const pdata = {
            "data": data,
            "rounds": rounds,
            "seed": seed
        };

        return this.authPost(session, "mimc_hash", pdata);
    }

    proofsLastHash(session, scope, table) {
        const pdata = {
            "scope": scope,
            "table": table
        };

        return this.authPost(session, "proofs_last_hash", pdata);
    }

    updateProofs(session, data, rounds, seed) {
        const pdata = {
            "rounds": rounds,
            "seed": seed
        };

        return this.authPost(session, "update_proofs", pdata);
    }

    verifyMerkleHash(session, tree, hash, digest) {
        const data = {
            "tree": tree,
            "hash": hash,
            "digest": digest
        };

        return this.authPost(session, "verify_merkle_hash", data);
    }

    getSidechainDetails(session) {
        const data = {};
        return this.authPost(session, "get_sidechain_details", data);
    }

    getUserDetails(session, publicKey) {
        const data = { publicKey };
        return this.authPost(session, "get_user_details", data);
    }

    getNodes(session) {
        const data = {};
        return this.authPost(session, "get_nodes", data);
    }

    getScopes(session) {
        const data = {};
        return this.authPost(session, "get_scopes", data);
    }

    getTables(session, scope) {
        const data = {
            "scope": scope
        };

        return this.authPost(session, "get_tables", data);
    }

    getTableDefinition(session, scope, table) {
        const data = {
            "scope": scope,
            "table": table
        };

        return this.authPost(session, "get_table_definition", data);
    }

    getNodeConfig(session, nodePublicKey) {
        const data = {
            "nodePublicKey": nodePublicKey
        };

        return this.authPost(session, "get_node_config", data);
    }

    getAccountNotifications(session) {
        const data = {};
        return this.authPost(session, "get_account_notifications", data);
    }

    updateLayout(session, scope, table, layout) {
        const data = {
            "scope": scope,
            "table": table,
            "layout": layout
        };

        return this.authPost(session, "update_layout", data);
    }

    updateConfig(session, path, values) {
        const data = {
            "path": path,
            "values": values ? JSON.stringify(values) : null
        };

        return this.authPost(session, "update_config", data);
    }

    grantRole(session, account, roles) {
        const data = {
            "targetAccount": account,
            "roles": typeof roles === "string" ? roles : JSON.stringify(roles)
        };

        return this.authPost(session, "grant_role", data);
    }

    balance(session, accountAddress, scope, token) {
        var iv = new Int8Array(16);
        keys.getRandomValues(iv);

        const toSign = session.organization + "\n" + this.clientPublicKey + "\n" + accountAddress + "\n" + scope + "\n" + token;
        const signature = this.signString(toSign, iv);

        const data = {
            "accountAddress": accountAddress,
            "scope": scope,
            "token": token,
            "signature": signature,
            "x-iv": keys.toHex(iv),
            "x-sig-key": this.apiContext.sigKey
        };

        return this.authPost(session, "balance", data);
    }

    transfer(session, accountAddress, scope, token, amount) {
        var iv = new Int8Array(16);
        keys.getRandomValues(iv);

        const toSign = session.organization + "\n" + this.clientPublicKey + "\n" + accountAddress + "\n" + scope + "\n" + token + "\n" + amount;
        const signature = this.signString(toSign, iv);

        const data = {
            "accountAddress": accountAddress,
            "scope": scope,
            "token": token,
            "amount": amount,
            "signature": signature,
            "x-iv": keys.toHex(iv),
            "x-sig-key": this.apiContext.sigKey
        };

        return this.authPost(session, "transfer", data);
    }

    call(session, contractAddress, scope, fn, args) {
        var iv = new Int8Array(16);
        keys.getRandomValues(iv);

        const serialized = new Buffer(args).toString("base64")
        const toSign = session.organization + "\n" + this.clientPublicKey + "\n" + contractAddress + "\n" + scope + "\n" + fn + "\n" + serialized;
        const signature = this.signString(toSign, iv);

        const data = {
            "accountAddress": contractAddress,
            "scope": scope,
            "function": fn,
            "data": serialized,
            "signature": signature,
            "x-iv": keys.toHex(iv),
            "x-sig-key": this.apiContext.sigKey
        };

        return this.authPost(session, "call", data);
    }

    updateFees(session, scope, fees) {
        var iv = new Int8Array(16);
        keys.getRandomValues(iv);

        const toSign = session.organization + "\n" + this.clientPublicKey + "\n" + scope + "\n" + fees;
        const signature = this.signString(toSign, iv);

        const data = {
            "scope": scope,
            "fees": fees,
            "signature": signature,
            "x-iv": keys.toHex(iv),
            "x-sig-key": this.apiContext.sigKey
        };

        return this.authPost(session, "update_fees", data);
    }

    contractState(session, contractAddress, scope) {
        var iv = new Int8Array(16);
        keys.getRandomValues(iv);

        const toSign = session.organization + "\n" + this.clientPublicKey + "\n" + contractAddress + "\n" + scope;
        const signature = this.signString(toSign, iv);

        const data = {
            "contractAddress": contractAddress,
            "scope": scope
        };

        return this.authPost(session, "contract_state", data);
    }

    sign(data) {
        return this.apiContext.createEd25519Signature(data)
    }

    verifyKeySignature(publicKey, signature, data) {
        return this.apiContext.verifyEd25519Signature(publicKey, signature, data)
    }

    zkProof(session, scope, table, gadgetType, params, fields, filter, options) {
        const data = {
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

        return this.authPost(session, "zk_proof", data);
    }

    zkDataProof(session, gadgetType, params, values, options) {
        const data = {
            "gadget": gadgetType,
            "params": params,
            "values": values,
            "options": options.toJson()
        };

        return this.authPost(session, "zk_data_proof", data);
    }

    verifyZkProof(session, proof, gadgetType, params, commitment, nGenerators) {
        const data = {
            "proof": proof,
            "gadget": gadgetType,
            "params": params,
            "commitment": commitment,
            "nGenerators": nGenerators
        };

        return this.authPost(session, "verify_zk_proof", data);
    }

    taskLineage(session, taskId) {
        const data = {
            "taskId": taskId
        };

        return this.authPost(session, "task_lineage", data);
    }

    verifyTaskLineage(session, lineageData) {
        const data = {
            "metadata": lineageData
        };

        return this.authPost(session, "verify_task_lineage", data);
    }

    taskOutputData(session, taskId, options) {
        const data = {
            "taskId": taskId,
            "options": options.toJson()
        };

        return this.authPost(session, "task_output_data", data);
    }

    history(session, scope, table, filter, historyOptions) {
        const data = {
            "scope": scope,
            "table": table,
            "options": historyOptions.toJson()
        };

        if (filter) {
            data["filter"] = filter.toJson();
        }
        return this.authPost(session, "history", data);
    }

    writers(session, scope, table, filter) {
        const data = {
            "scope": scope,
            "table": table,
        };

        if (filter) {
            data["filter"] = filter.toJson();
        }
        return this.authPost(session, "writers", data);
    }

    tasks(session, scope, table, filter) {
        const data = {
            "scope": scope,
            "table": table,
        };

        if (filter) {
            data["filter"] = filter.toJson();
        }
        return this.authPost(session, "tasks", data);
    }

    lineage(session, scope, table, filter) {
        const data = {
            "scope": scope,
            "table": table,
        };

        if (filter) {
            data["filter"] = filter.toJson();
        }
        return this.authPost(session, "lineage", data);
    }

    deployOracle(session, oracleType, targetBlockchain, source, options) {
        const data = {
            "oracleType": oracleType,
            "targetBlockchain": targetBlockchain,
            "source": source,
            "options": options.toJson()
        };

        return this.authPost(session, "deploy_oracle", data);
    }

    deployFeed(session, image, options) {
        const data = {
            "image": image,
            "options": options.toJson()
        };

        return this.authPost(session, "deploy_feed", data);
    }

    removeFeed(session, feedId) {
        const data = {
            "feedId": feedId
        };

        return this.authPost(session, "remove_feed", data);
    }

    startFeed(session, feedId, options) {
        const data = {
            "feedId": feedId,
            "options": options.toJson()
        };

        return this.authPost(session, "start_feed", data);
    }

    stopFeed(session, feedId) {
        const data = {
            "feedId": feedId
        };

        return this.authPost(session, "stop_feed", data);
    }

    issueCredentials(session, issuer, holder, credentials, options) {
        const data = {
            "issuer": issuer,
            "holder": holder,
            "credentials": credentials,
            "options": options.toJson()
        };

        return this.authPost(session, "issue_credentials", data);
    }

    verifyCredentials(session, credentials, options) {
        const data = {
            "credentials": credentials,
            "options": options.toJson()
        };

        return this.authPost(session, "verify_credentials", data);
    }

    createPresentation(session, credentials, subject, options) {
        const data = {
            "credentials": credentials,
            "subject": subject,
            "options": options.toJson()
        };

        return this.authPost(session, "create_presentation", data);
    }

    signPresentation(session, presentation, domain, challenge, options) {
        const data = {
            "presentation": presentation,
            "domain": domain,
            "challenge": challenge,
            "options": options.toJson()
        };

        return this.authPost(session, "sign_presentation", data);

    }

    verifyPresentation(session, signedPresentation, domain, challenge, options) {
        const data = {
            "presentation": signedPresentation,
            "domain": domain,
            "challenge": challenge,
            "options": options.toJson()
        };

        return this.authPost(session, "verify_presentation", data);
    }

    verifyDataSignature(session, signer, signature, toSign) {
        const data = {
            "signer": signer,
            "signature": signature,
            "data": toSign
        };

        return this.authPost(session, "verify_data_signature", data);
    }

    postMessage(session, targetInboxKey, message, options) {
        const data = {
            "targetInboxKey": targetInboxKey,
            "message": message,
            "options": options.toJson()
        };

        return this.authPost(session, "post_message", data);
    }

    pollMessages(session, inboxKey, options) {
        const data = {
            "inboxKey": inboxKey,
            "options": options.toJson()
        };

        return this.authPost(session, "poll_messages", data);
    }

    createAccount(session, path, values) {
        const data = {
            "path": path,
            "values": values ? JSON.stringify(values) : null
        };

        return this.authPost(session, "create_user_account", data);
    }

    updateFee(session, path, scope, fee) {
        // generate signature
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
            "path": path,
            "scope": scope.name,
            "fees" : JSON.stringify(fee),
            "values": scope ? JSON.stringify(scope) : null,
            "signature": signature,
            "x-iv": keys.toHex(iv)
        };

        return this.authPost(session, "update_fees", data);
    }
    
    resetConfig(session) {
        const data = {};
        return this.authPost(session, "reset_config", data);
    }

    withdraw(session, token, amount) {
        const data = {
            "token": token,
            "amount": amount
        };
        return this.authPost(session, "withdraw", data);
    }

    withdrawAuthorize(session, token, address) {
        const toSign = token + "\n" + address;
        const data = {
            "token": token,
            "address": address,
            "signature": this.apiContext.createEd25519Signature(toSign)
        };
        return this.authPost(session, "withdraw_auth", data);
    }

    pluginCall(session, plugin, request, args, timeout) {
        const data = {
            "plugin": plugin,
            "request": request,
            "args": JSON.stringify(args),
            "timeout": timeout
        };
        return this.authPost(session, "plugin_call", data);
    }
}

export default ClientHttp;