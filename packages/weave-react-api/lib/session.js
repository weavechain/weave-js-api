class Session {

    constructor(
        data,
        decryptedSecret
    ) {
        this.organization = data["organization"];
        this.account = data["account"];
        this.publicKey = data["publicKey"];
        this.scopes = data["scopes"];
        this.apiKey = data["apiKey"];

        this.secret = decryptedSecret;
        this.secretExpireUTC = data["secretExpireUTC"];
        this.integrityChecks = data["integrityChecks"];
        this.nonce = 0.0;
        this.tableLayoutCache = {};
        this.prevRecordsData = {};

        this.expiryCushionSec = 10;
    }

    toJson() {
        return JSON.stringify({
            organization: this.organization,
            account: this.account,
            publicKey: this.publicKey,
            scopes: this.scopes,
            apiKey: this.apiKey,
            secret: this.secret,
            secretExpireUTC: this.secretExpireUTC,
            integrityChecks: this.integrityChecks,
            nonce: this.nonce,
            prevRecordsData: this.prevRecordsData,
            tableLayoutCache: this.tableLayoutCache
        });
    }

    static fromJson(json) {
        const data = (typeof json === 'string' || json instanceof String) ? JSON.parse(json) : json;

        const session = new Session({});

        session.organization = data["organization"];
        session.account = data["account"];
        session.publicKey = data["publicKey"];
        session.scopes = data["scopes"];
        session.apiKey = data["apiKey"];

        session.secret = data["secret"];
        session.secretExpireUTC = data["secretExpireUTC"];
        session.integrityChecks = data["integrityChecks"];
        session.nonce = data["nonce"];
        session.tableLayoutCache = {};
        session.prevRecordsData = data["prevRecordsData"];

        return session;
    }

    getNonce() {
        this.nonce += 1.0;
        return this.nonce;
    }

    nearExpiry() {
        return this.secretExpireUTC != null
            && new Date().getTime() / 1000 + this.expiryCushionSec > this.secretExpireUTC;
    }
}

export default Session;