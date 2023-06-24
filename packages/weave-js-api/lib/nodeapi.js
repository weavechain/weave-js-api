import keys from './keys.js'
import options from './options'
import ApiContext from './apicontext'
import ClientHttp from './clienthttp'
import ClientWs from './clientws'

class NodeApi {

    constructor(
        config
    ) {
        this.config = config;
    }

    static fromJson(json) {
        const data = (typeof json === 'string' || json instanceof String) ? JSON.parse(json) : json;

        const nodeApi = new NodeApi(data.config);
        nodeApi.init(data.remotePublicKey);
        return nodeApi;
    }

    toJson() {
        return JSON.stringify({
            config: this.config,
            remotePublicKey: this.client?.serverPublicKey
        });
    }

    async init(remotePublicKey = null) {
        let cfg = this.config;

        this.clientPublicKey = keys.readKey(cfg.publicKey, cfg.publicKeyFile);

        if (cfg.websocket != null) {
            this.client = new ClientWs(cfg);
        } else if (cfg.http != null) {
            this.client = new ClientHttp(cfg);
        }

        if (this.client) {
            await this.client.init(remotePublicKey);
        }
    }

    version() {
        return this.client.version();
    }

    ping() {
        return this.client.ping();
    }

    generateKeys() {
        return ApiContext.generateKeys();
    }

    getClientPublicKey() {
        return this.clientPublicKey;
    }

    publicKey() {
        return this.client.publicKey();
    }

    sigKey(account = null) {
        return this.client.sigKey(account);
    }

    status(session) {
        return this.client.status(session);
    }

    login(organization, account, scopes, credentials = null) {
        return this.client.login(organization, account, scopes, credentials);
    }

    logout(session) {
        return this.client.logout(session);
    }

    checkSession(session, credentials = null) {
        if (session != null && session.nearExpiry()) {
            return this.login(session.organization, session.account, session.scopes, credentials);
        } else {
            return session;
        }
    }

    terms(session, options) {
        return this.client.terms(session, options);
    }

    createTable(session, scope, table, createOptions) {
        return this.client.createTable(session, scope, table, createOptions);
    }

    dropTable(session, scope, table, dropOptions) {
        return this.client.dropTable(session, scope, table, dropOptions);
    }

    write(session, scope, records, writeOptions) {
        return this.client.write(session, scope, records, writeOptions);
    }

    read(session, scope, table, filter, readOptions) {
        return this.client.read(session, scope, table, filter, readOptions);
    }

    count(session, scope, table, filter, readOptions) {
        return this.client.count(session, scope, table, filter, readOptions);
    }

    delete(session, scope, table, filter, deleteOptions) {
        return this.client.delete(session, scope, table, filter, deleteOptions);
    }

    hashes(session, scope, table, filter, readOptions) {
        return this.client.hashes(session, scope, table, filter, readOptions);
    }

    hashCheckpoint(session, enable = true) {
        return this.client.hashCheckpoint(session, enable);
    }

    downloadTable(session, scope, table, filter, format, readOptions) {
        return this.client.downloadTable(session, scope, table, filter, format, readOptions);
    }

    publishDataset(session,
                   did, name, description, license, metadata, weave, fullDescription, logo, category,
                   scope, table, filter, format, price, token, pageorder, publishOptions) {
        return this.client.publishDataset(session, did, name, description, license, metadata, weave, fullDescription, logo, category, scope, table, filter, format, price, token, pageorder, publishOptions);
    }

    enableProduct(session, did, productType, active) {
        return this.client.enableProduct(session, did, productType, active);
    }

    downloadDataset(session, did, readOptions) {
        return this.client.downloadDataset(session, did, readOptions);
    }

    publishTask(session,
                did, name, description, license, metadata, weave, fullDescription, logo, category,
                task, price, token, pageorder, publishOptions) {
        return this.client.publishTask(session, did, name, description, license, metadata, weave, fullDescription, logo, category, task, price, token, pageorder, publishOptions);
    }

    runTask(session, did, computeOptions) {
        return this.client.runTask(session, did, computeOptions);
    }

    subscribe(session, scope, table, filter, subscribeOptions, updateHandler) {
        return this.client.subscribe(session, scope, table, filter, subscribeOptions, updateHandler);
    }

    unsubscribe(session, subscriptionId) {
        return this.client.unsubscribe(session, subscriptionId);
    }

    compute(session, image, options) {
        return this.client.compute(session, image, options);
    }

    flearn(session, image, options) {
        return this.client.flearn(session, image, options);
    }

    forwardApi(session, feedId, params) {
        return this.client.forwardApi(session, feedId, params);
    }

    uploadApi(session, params) {
        return this.client.uploadApi(session, params);
    }

    heGetInputs(session, datasources, args) {
        return this.client.heGetInputs(session, datasources, args);
    }

    heGetOutputs(session, encoded, args) {
        return this.client.heGetOutputs(session, encoded, args);
    }

    heEncode(session, items) {
        return this.client.heEncode(session, items);
    }

    mpc(session, scope, table, algo, fields, filter, options) {
        return this.client.mpc(session, scope, table, algo, fields, filter, options);
    }

    storageProof(session, scope, table, filter, challenge, options) {
        return this.client.storageProof(session, scope, table, filter, challenge, options);
    }

    zkStorageProof(session, scope, table, filter, challenge, options) {
        return this.client.zkStorageProof(session, scope, table, filter, challenge, options);
    }

    merkleTree(session, scope, table, filter, salt, digest, options) {
        return this.client.merkleTree(session, scope, table, filter, salt, digest, options);
    }

    merkleProof(session, scope, table, hash) {
        return this.client.merkleProof(session, scope, table, hash);
    }

    zkMerkleTree(session, scope, table, filter, salt, digest, rounds, seed, options) {
        return this.client.zkMerkleTree(session, scope, table, filter, salt, digest, rounds, seed, options);
    }

    rootHash(session, scope, table) {
        return this.client.rootHash(session, scope, table);
    }

    mimcHash(session, data, rounds, seed) {
        return this.client.mimcHash(session, data, rounds, seed);
    }

    proofsLastHash(session, scope, table) {
        return this.client.proofsLastHash(session, scope, table);
    }

    updateProofs(session, scope, table) {
        return this.client.updateProofs(session, scope, table);
    }

    verifyMerkleHash(session, tree, hash, digest) {
        //using remote function for now, could be local
        return this.client.verifyMerkleHash(session, tree, hash, digest);
    }

    sign(data) {
        return this.client.sign(data);
    }

    verifyKeySignature(publicKey, signature, data) {
        return this.client.verifyKeySignature(publicKey, signature, data);
    }

    zkProof(session, scope, table, gadgetType, params, fields, filter, options) {
        return this.client.zkProof(session, scope, table, gadgetType, params, fields, filter, options);
    }

    zkDataProof(session, gadgetType, params, values, options) {
        return this.client.zkDataProof(session, gadgetType, params, values, options);
    }

    verifyZkProof(session, proof, gadgetType, params, commitment = options.DEFAULT_COMMITMENT, nGenerators = options.DEFAULT_GENERATORS) {
        return this.client.verifyZkProof(session, proof, gadgetType, params, commitment, nGenerators);
    }

    taskLineage(session, taskId) {
        return this.client.taskLineage(session, taskId);
    }

    verifyTaskLineage(session, lineageData) {
        return this.client.verifyTaskLineage(session, lineageData);
    }

    taskOutputData(session, taskId, options) {
        return this.client.taskOutputData(session, taskId, options);
    }

    history(session, scope, table, filter, historyOptions) {
        return this.client.history(session, scope, table, filter, historyOptions);
    }

    writers(session, scope, table, filter) {
        return this.client.writers(session, scope, table, filter);
    }

    tasks(session, scope, table, filter) {
        return this.client.tasks(session, scope, table, filter);
    }

    lineage(session, scope, table, filter, historyOptions) {
        return this.client.lineage(session, scope, table, filter);
    }

    deployOracle(session, oracleType, targetBlockchain, source, options) {
        return this.client.deployOracle(session, oracleType, targetBlockchain, source, options);
    }

    deployFeed(session, image, options) {
        return this.client.deployFeed(session, image, options);
    }

    removeFeed(session, feedId) {
        return this.client.removeFeed(session, feedId);
    }

    startFeed(session, feedId, options) {
        return this.client.startFeed(session, feedId, options);
    }

    stopFeed(session, feedId) {
        return this.client.stopFeed(session, feedId);
    }

    issueCredentials(session, issuer, holder, credentials, options) {
        return this.client.issueCredentials(session, issuer, holder, credentials, options);
    }

    verifyCredentials(session, credentials, options) {
        return this.client.verifyCredentials(session, credentials, options);
    }

    createPresentation(session, credentials, subject, options) {
        return this.client.createPresentation(session, credentials, subject, options);
    }

    signPresentation(session, presentation, domain, challenge, options) {
        return this.client.signPresentation(session, presentation, domain, challenge, options);
    }

    verifyPresentation(session, signedPresentation, domain, challenge, options) {
        return this.client.verifyPresentation(session, signedPresentation, domain, challenge, options);
    }

    verifyDataSignature(session, signer, signature, toSign) {
        return this.client.verifyDataSignature(session, signer, signature, toSign);
    }

    postMessage(session, targetInboxKey, message, options) {
        return this.client.postMessage(session, targetInboxKey, message, options);
    }

    pollMessages(session, inboxKey, options) {
        return this.client.pollMessages(session, inboxKey, options);
    }

    getSidechainDetails(session) {
        return this.client.getSidechainDetails(session);
    }

    getUserDetails(session, publicKey) {
        return this.client.getUserDetails(session, publicKey);
    }

    getNodes(session) {
        return this.client.getNodes(session);
    }

    getScopes(session) {
        return this.client.getScopes(session);
    }

    getTables(session, scope) {
        return this.client.getTables(session, scope);
    }

    getTableDefinition(session, scope, table) {
        return this.client.getTableDefinition(session, scope, table);
    }

    getNodeConfig(session, nodePublicKey) {
        return this.client.getNodeConfig(session, nodePublicKey);
    }

    getAccountNotifications(session) {
        return this.client.getAccountNotifications(session);
    }

    createAccount(session, path, values) {
        return this.client.createAccount(session, path, values);
    }

    updateLayout(session, scope, table, layout) {
        return this.client.updateLayout(session, scope, table, layout);
    }

    updateConfig(session, path, values) {
        return this.client.updateConfig(session, path, values);
    }

    grantRole(session, account, roles) {
        return this.client.grantRole(session, account, roles);
    }

    balance(session, accountAddress, scope, token) {
        return this.client.balance(session, accountAddress, scope, token);
    }

    transfer(session, accountAddress, scope, token, amount) {
        return this.client.transfer(session, accountAddress, scope, token, amount);
    }

    call(session, contractAddress, scope, fn, data) {
        return this.client.call(session, contractAddress, scope, fn, data);
    }

    updateFees(session, scope, fees) {
        return this.client.updateFees(session, scope, fees);
    }

    contractState(session, contractAddress, scope) {
        return this.client.contractState(session, contractAddress, scope);
    }

    updateFee(session, path, scope, fee) {
        return this.client.updateFee(session, path, scope, fee);
    }
    
    resetConfig(session) {
        return this.client.resetConfig(session);
    }

    withdraw(session, token, amount) {
        return this.client.withdraw(session, token, amount);
    }

    withdrawAuthorize(session, token, address) {
        return this.client.withdrawAuthorize(session, token, address);
    }

    pluginCall(session, plugin, request, args, timeout) {
        return this.client.pluginCall(session, plugin, request, args, timeout);
    }

    emailAuth(org, clientPubKey, targetWebUrl, email) {
        return this.client.emailAuth(org, clientPubKey, targetWebUrl, email)
    }
}

export default NodeApi;