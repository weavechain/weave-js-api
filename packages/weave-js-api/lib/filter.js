const DEFAULT_CREATE_TIMEOUT_SEC = 300;

export class Filter {

    constructor(
        op,
        order,
        limit,
        collapsing,
        columns,
        postFilterOp
    ) {
        this.op = op;
        this.order = order; //sorting is position sensitive, using Map preserves insertion order
        this.limit = limit;
        this.collapsing = collapsing;
        this.columns = columns;
        this.postFilterOp = postFilterOp;
    }

    toJson() {
        return JSON.stringify({
            "op": this.op,
            "order": this.order,
            "limit": this.limit,
            "collapsing": this.collapsing,
            "columns": this.columns,
            "postFilterOp": this.postFilterOp
        });
    }

    static fromJson(json) {
        return new Filter(
            json.op,
            json.order,
            json.limit,
            json.collapsing,
            json.columns,
            json.postFilterOp
        );
    }
}

export class FilterOp {

    constructor(
        operation,
        left,
        right,
        value
    ) {
        this.operation = operation;
        this.left = left;
        this.right = right;
        this.value = value;
    }

    static field(field) {
        return new FilterOp("field", null, null, field);
    }

    static value(value) {
        return new FilterOp("value", null, null, value);
    }

    static eq(field, value) {
        return new FilterOp("eq", field instanceof FilterOp ? field : FilterOp.field(field), value instanceof FilterOp ? value : FilterOp.value(value), null);
    }

    static neq(field, value) {
        return new FilterOp("neq", field instanceof FilterOp ? field : FilterOp.field(field), value instanceof FilterOp ? value : FilterOp.value(value), null);
    }

    static in(field, values) {
        return new FilterOp("in", field instanceof FilterOp ? field : FilterOp.field(field), values instanceof FilterOp ? values : FilterOp.value(values), null);
    }

    static notin(field, values) {
        return new FilterOp("notin", field instanceof FilterOp ? field : FilterOp.field(field), values instanceof FilterOp ? values : FilterOp.value(values), null);
    }

    static gt(field, value) {
        return new FilterOp("gt", field instanceof FilterOp ? field : FilterOp.field(field), value instanceof FilterOp ? value : FilterOp.value(value), null);
    }

    static gte(field, value) {
        return new FilterOp("gte", field instanceof FilterOp ? field : FilterOp.field(field), value instanceof FilterOp ? value : FilterOp.value(value), null);
    }

    static lt(field, value) {
        return new FilterOp("lt", field instanceof FilterOp ? field : FilterOp.field(field), value instanceof FilterOp ? value : FilterOp.value(value), null);
    }

    static lte(field, value) {
        return new FilterOp("lte", field instanceof FilterOp ? field : FilterOp.field(field), value instanceof FilterOp ? value : FilterOp.value(value), null);
    }

    static and(expr1, expr2) {
        return new FilterOp("and", expr1, expr2, null);
    }

    static or(expr1, expr2) {
        return new FilterOp("or", expr1, expr2, null);
    }

    static contains(field, value) {
        return new FilterOp("contains", field instanceof FilterOp ? field : FilterOp.field(field), value instanceof FilterOp ? value : FilterOp.value(value), null);
    }
}

export class Order {

    static build() {
        var args = Array.prototype.slice.call(arguments);
        const order = new Map();
        for (let i = 0; i < args.length; i += 2) {
            order.set(args[i], args[i + 1]);
        }
        return order;
    }
}