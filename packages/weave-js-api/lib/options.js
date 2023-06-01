export class TermsOptions {

    constructor(
        agreeTerms,
        agreePrivacyPolicy
    ) {
        this.agreeTerms = agreeTerms != null ? agreeTerms : false;
        this.agreePrivacyPolicy = agreePrivacyPolicy != null ? agreePrivacyPolicy : false;
    }

    toJson() {
        return JSON.stringify({
            "agreeTerms": this.agreeTerms,
            "agreePrivacyPolicy": this.agreePrivacyPolicy
        });
    }
}

const TERMS_AGREE = new TermsOptions(true, true);
const TERMS_DISAGREE = new TermsOptions(false, false);

const DEFAULT_CREATE_TIMEOUT_SEC = 300;

export class CreateOptions {

    constructor(
        failIfExists,
        replicate,
        layout,
        createTimeoutSec
    ) {
        this.failIfExists = failIfExists != null ? failIfExists : true;
        this.replicate = replicate != null ? replicate : true;
        this.layout = layout;
        this.createTimeoutSec = createTimeoutSec || DEFAULT_CREATE_TIMEOUT_SEC;
    }

    toJson() {
        return JSON.stringify({
            "failIfExists": this.failIfExists,
            "replicate": this.replicate,
            "layout": this.layout,
            "createTimeoutSec": this.createTimeoutSec
        });
    }
}

const CREATE_DEFAULT = new CreateOptions(true, true, null, DEFAULT_CREATE_TIMEOUT_SEC);
const CREATE_FAILSAFE = new CreateOptions(false, true, null, DEFAULT_CREATE_TIMEOUT_SEC);

export class HistoryOptions {
    constructor(operationTypes) {
        this.operationTypes = operationTypes != null ? operationTypes : null;
    }
}

const HISTORY_DEFAULT = new HistoryOptions(["read", "delete", "write"]);

export class DropOptions {

    constructor(
        failIfNotExists,
        replicate,
        dropTimeoutSec
    ) {
        this.failIfNotExists = failIfNotExists != null ? failIfNotExists : true;
        this.replicate = replicate != null ? replicate : null;
        this.dropTimeoutSec = dropTimeoutSec || DEFAULT_CREATE_TIMEOUT_SEC;
    }

    toJson() {
        return JSON.stringify({
            "failIfNotExists": this.failIfNotExists,
            "replicate": this.replicate,
            "dropTimeoutSec": this.dropTimeoutSec
        });
    }
}

const DROP_DEFAULT = new DropOptions(true, true, DEFAULT_CREATE_TIMEOUT_SEC);
const DROP_FAILSAFE = new DropOptions(false, true, DEFAULT_CREATE_TIMEOUT_SEC);

export class DeleteOptions {
    constructor(
        allowDistribute,
        correlationUuid,
        thresholdMultisigContext
    ) {
        this.allowDistribute = allowDistribute != null ? allowDistribute : null;
        this.correlationUuid = correlationUuid != null ? correlationUuid : null;
        this.thresholdMultisigContext = thresholdMultisigContext != null ? thresholdMultisigContext : null;
    }

    toJson() {
        return JSON.stringify(this);
    }
}

const DELETE_DEFAULT = new DeleteOptions(true, null, null);

export class ReadOptions {

    constructor(
        verifyHash,
        readTimeoutSec,
        peersConsensus,
        enableMux,
        getBatchHashes
    ) {
        this.verifyHash = verifyHash != null ? verifyHash : null;
        this.readTimeoutSec = readTimeoutSec || DEFAULT_READ_TIMEOUT_SEC;
        this.peersConsensus = peersConsensus != null ? peersConsensus : 0;
        this.enableMux = enableMux != null ? enableMux : false;
        this.getBatchHashes = getBatchHashes != null ? getBatchHashes : false;
    }

    toJson() {
        return JSON.stringify({
            "verifyHash": this.verifyHash,
            "readTimeoutSec": this.readTimeoutSec,
            "peersConsensus": this.peersConsensus,
            "enableMux": this.enableMux,
            "getBatchHashes": this.getBatchHashes
        });
    }
}

const DEFAULT_READ_TIMEOUT_SEC = 300

const READ_DEFAULT = new ReadOptions(true, DEFAULT_READ_TIMEOUT_SEC, 0, false, false)
const READ_DEFAULT_NO_CHAIN = new ReadOptions(false, DEFAULT_READ_TIMEOUT_SEC, 0, false, false)

export class SubscribeOptions {

    constructor(
        verifyHash,
        initialSnapshot,
        readTimeoutSec,
        externalUpdates,
        batchingOptions
    ) {
        this.verifyHash = verifyHash != null ? verifyHash : null;
        this.initialSnapshot = initialSnapshot != null ? initialSnapshot : true;
        this.readTimeoutSec = readTimeoutSec || DEFAULT_READ_TIMEOUT_SEC;
        this.externalUpdates = externalUpdates != null ? externalUpdates : false;
        this.batchingOptions = batchingOptions;
    }

    toJson() {
        return JSON.stringify({
            "verifyHash": this.verifyHash,
            "initialSnapshot": this.initialSnapshot,
            "readTimeoutSec": this.readTimeoutSec,
            "externalUpdates": this.externalUpdates,
            "batchingOptions": this.batchingOptions
        });
    }
}

const SUBSCRIBE_DEFAULT = new SubscribeOptions(true, true, DEFAULT_READ_TIMEOUT_SEC, false, null)
const SUBSCRIBE_DEFAULT_NO_CHAIN = new SubscribeOptions(false, true, DEFAULT_READ_TIMEOUT_SEC, false, null)

export class WriteOptions {

    constructor(
        guaranteed,
        minAcks,
        inMemoryAcks,
        minHashAcks,
        writeTimeoutSec,
        allowDistribute,
        signOnChain,
        syncSigning
    ) {
        this.guaranteed = guaranteed || DEFAULT_GUARANTEED_DELIVERY;
        this.minAcks = minAcks || DEFAULT_MIN_ACKS;
        this.inMemoryAcks = inMemoryAcks || DEFAULT_MEMORY_ACKS;
        this.minHashAcks = minHashAcks || DEFAULT_HASH_ACKS;
        this.writeTimeoutSec = writeTimeoutSec || DEFAULT_WRITE_TIMEOUT_SEC;
        this.allowDistribute = allowDistribute != null ? allowDistribute : true;
        this.signOnChain = signOnChain != null ? signOnChain : true;
        this.syncSigning = syncSigning != null ? syncSigning : false;
    }

    toJson() {
        return JSON.stringify({
            "guaranteed": this.guaranteed,
            "minAcks": this.minAcks,
            "inMemoryAcks": this.inMemoryAcks,
            "minHashAcks": this.minHashAcks,
            "writeTimeoutSec": this.writeTimeoutSec,
            "allowDistribute": this.allowDistribute,
            "signOnChain": this.signOnChain,
            "syncSigning": this.syncSigning
        });
    }
}

const DEFAULT_GUARANTEED_DELIVERY = true
const DEFAULT_MIN_ACKS = 1
const DEFAULT_MEMORY_ACKS = false
const DEFAULT_HASH_ACKS = 1
const DEFAULT_WRITE_TIMEOUT_SEC = 300

const WRITE_DEFAULT = new WriteOptions(
        DEFAULT_GUARANTEED_DELIVERY,
        DEFAULT_MIN_ACKS,
        DEFAULT_MEMORY_ACKS,
        DEFAULT_HASH_ACKS,
        DEFAULT_WRITE_TIMEOUT_SEC,
        true,
        true,
        false
)

const WRITE_DEFAULT_ASYNC = new WriteOptions(
        false,
        DEFAULT_MIN_ACKS,
        true,
        0,
        DEFAULT_WRITE_TIMEOUT_SEC,
        true,
        true,
        false
)
const WRITE_DEFAULT_NO_CHAIN = new WriteOptions(
        DEFAULT_GUARANTEED_DELIVERY,
        DEFAULT_MIN_ACKS,
        DEFAULT_MEMORY_ACKS,
        0,
        DEFAULT_WRITE_TIMEOUT_SEC,
        true,
        false,
        false
)

export class MPCOptions {

    constructor(
        verifyHash,
        readTimeoutSec,
        sources
    ) {
        this.verifyHash = verifyHash != null ? verifyHash : true;
        this.readTimeoutSec = readTimeoutSec || DEFAULT_READ_TIMEOUT_SEC;
        this.sources = sources;
    }

    toJson() {
        return JSON.stringify({
            "verifyHash": this.verifyHash,
            "readTimeoutSec": this.readTimeoutSec,
            "sources": this.sources
        });
    }
}

const DEFAULT_COMPUTE_TIMEOUT_SEC = 300

const ALL_ACTIVE_PEERS = 2147483647;

export class ComputeOptions {

    constructor(
        sync,
        timeoutSec,
        peersConsensus,
        scopes,
        params
    ) {
        this.sync = sync != null ? sync : true;
        this.timeoutSec = timeoutSec || DEFAULT_COMPUTE_TIMEOUT_SEC;
        this.peersConsensus = peersConsensus || 0;
        this.scopes = scopes;
        this.params = params;
    }

    toJson() {
        return JSON.stringify({
            "sync": this.sync,
            "timeoutSec": this.timeoutSec,
            "peersConsensus": this.peersConsensus,
            "scopes": this.scopes,
            "params": this.params
        });
    }
}

const COMPUTE_DEFAULT = new ComputeOptions(true, DEFAULT_COMPUTE_TIMEOUT_SEC, 0, null, null);

export class CredentialsOptions {

    constructor(
        opTimeoutSec,
        proofType,
        expirationTimestampGMT
    ) {
        this.opTimeoutSec = opTimeoutSec || DEFAULT_COMPUTE_TIMEOUT_SEC;
        this.proofType = proofType || "json-ld";
        this.expirationTimestampGMT = expirationTimestampGMT;
    }

    toJson() {
        return JSON.stringify({
            "opTimeoutSec": this.opTimeoutSec,
            "proofType": this.proofType,
            "expirationTimestampGMT": this.expirationTimestampGMT
        });
    }
}

const VC_DEFAULT = new CredentialsOptions(DEFAULT_READ_TIMEOUT_SEC, "json-ld", null);

export class ZKOptions {

    constructor(
        verifyHash,
        readTimeoutSec,
        sources,
        generators,
        commitment
    ) {
        this.verifyHash = verifyHash != null ? verifyHash : true;
        this.readTimeoutSec = readTimeoutSec || DEFAULT_READ_TIMEOUT_SEC;
        this.sources = sources;
        this.generators = generators || DEFAULT_GENERATORS;
        this.commitment = commitment || DEFAULT_COMMITMENT;
    }

    toJson() {
        return JSON.stringify({
            "verifyHash": this.verifyHash,
            "readTimeoutSec": this.readTimeoutSec,
            "sources": this.sources,
            "generators": this.generators,
            "commitment": this.commitment
        });
    }
}

const ALL_ACTIVE_NODES = [ "*" ]
const MPC_DEFAULT = new MPCOptions(true, DEFAULT_READ_TIMEOUT_SEC, ALL_ACTIVE_NODES);
const MPC_DEFAULT_NO_CHAIN = new MPCOptions(false, DEFAULT_READ_TIMEOUT_SEC, ALL_ACTIVE_NODES);

const DEFAULT_GENERATORS = 128;
const DEFAULT_COMMITMENT = "GGumV86X6FZzHRo8bLvbW2LJ3PZ45EqRPWeogP8ufcm3";

const ZK_DEFAULT = new ZKOptions(true, DEFAULT_READ_TIMEOUT_SEC, ALL_ACTIVE_NODES, DEFAULT_GENERATORS, DEFAULT_COMMITMENT);
const ZK_DEFAULT_NO_CHAIN = new ZKOptions(false, DEFAULT_READ_TIMEOUT_SEC, ALL_ACTIVE_NODES, DEFAULT_GENERATORS, DEFAULT_COMMITMENT);

export class PublishOptions {

    constructor(
        type,
        rollingUnit,
        rollingCount,
        verifyHash,
        readTimeoutSec,
        peersConsensus,
        enableMux
    ) {
        this.type = type || "snapshot";
        this.rollingUnit = rollingUnit;
        this.rollingCount = rollingCount;
        this.verifyHash = verifyHash != null ? verifyHash : true;
        this.readTimeoutSec = readTimeoutSec != null ? readTimeoutSec : DEFAULT_READ_TIMEOUT_SEC;
        this.peersConsensus = peersConsensus != null ? peersConsensus : 0;
        this.enableMux = enableMux != null ? enableMux : false;
    }

    toJson() {
        return JSON.stringify({
            "type": this.type,
            "rollingUnit": this.rollingUnit,
            "rollingCount": this.rollingCount,
            "verifyHash": this.verifyHash,
            "readTimeoutSec": this.readTimeoutSec,
            "peersConsensus": this.peersConsensus,
            "enableMux": this.enableMux
        });
    }
}

const PUBLISH_DEFAULT = new PublishOptions("snapshot", null, null, true, DEFAULT_READ_TIMEOUT_SEC, 0, false);

export class PublishTaskOptions {

    constructor(
        computeTimeoutSec,
        params,
        allowCustomParams = false
    ) {
        this.computeTimeoutSec = computeTimeoutSec;
        this.params = params;
        this.allowCustomParams = allowCustomParams;
    }

    toJson() {
        return JSON.stringify({
            "computeTimeoutSec": this.computeTimeoutSec,
            "params": this.params,
            "allowCustomParams": this.allowCustomParams
        });
    }
}

const PUBLISH_TASK_DEFAULT = new PublishTaskOptions(DEFAULT_COMPUTE_TIMEOUT_SEC, null, false);

const options = {
    CreateOptions,
    ReadOptions,
    SubscribeOptions,
    WriteOptions,
    ComputeOptions,
    MPCOptions,
    CredentialsOptions,
    PublishOptions,
    PublishTaskOptions,
    ZKOptions,

    CREATE_DEFAULT,
    CREATE_FAILSAFE,

    DROP_DEFAULT,
    DROP_FAILSAFE,

    DEFAULT_READ_TIMEOUT_SEC,
    DEFAULT_CREATE_TIMEOUT_SEC,

    DEFAULT_COMPUTE_TIMEOUT_SEC,
    ALL_ACTIVE_PEERS,

    READ_DEFAULT,
    READ_DEFAULT_NO_CHAIN,

    SUBSCRIBE_DEFAULT,
    SUBSCRIBE_DEFAULT_NO_CHAIN,

    DEFAULT_GUARANTEED_DELIVERY,
    DEFAULT_MIN_ACKS,
    DEFAULT_MEMORY_ACKS,
    DEFAULT_HASH_ACKS,
    DEFAULT_WRITE_TIMEOUT_SEC,

    WRITE_DEFAULT,
    WRITE_DEFAULT_ASYNC,
    WRITE_DEFAULT_NO_CHAIN,

    HISTORY_DEFAULT,

    MPC_DEFAULT,
    MPC_DEFAULT_NO_CHAIN,

    ZK_DEFAULT,
    ZK_DEFAULT_NO_CHAIN,

    COMPUTE_DEFAULT,

    VC_DEFAULT,

    PUBLISH_DEFAULT,
    PUBLISH_TASK_DEFAULT,

    DEFAULT_GENERATORS,
    DEFAULT_COMMITMENT,

    ALL_ACTIVE_NODES
};

export default options;