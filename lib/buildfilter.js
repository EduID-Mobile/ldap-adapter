// const debug = require("debug")("ldap-adapter:buildFilter");

function buildFilter(filterObj) {
    if (!filterObj) {
        filterObj = [];
    }

    if (!(filterObj instanceof Array)) {
        filterObj = [filterObj];
    }

    const op = filterObj.shift();

    // and/or handling
    if (op === "&" || op === "|") {
        const qs = filterObj.map((e) => {
            if (e && e.length) {
                return buildFilter(e);
            }
            return "";
        }).filter((e) => e.length);

        if (qs.length > 1) {
            return `(${op}${qs.join("")})`;
        }

        if (qs.length === 1) {
            return qs[0];
        }
        return ""; // operator without filters
    }

    // not operator
    if (op === "!") {
        // not has only one filter
        const e = filterObj.shift();

        if (e && e.length) {
            return `(${op}${buildFilter(e)})`;
        }
        return ""; // operator without filter
    }

    if (op instanceof Array) {
        // always process arrays
        return buildFilter(op);
    }

    // pass literals
    return op ? `(${op})` : "";
}

module.exports = buildFilter;
