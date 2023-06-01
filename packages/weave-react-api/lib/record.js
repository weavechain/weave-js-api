class Record {

    constructor(
        id,
        data
    ) {
        this.id = id;
        this.data = data;
    }

    toJson() {
        return [
            this.id,
            this.data
        ];
    }
}

export default Record;