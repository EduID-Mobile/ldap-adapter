const debug = require("debug")("ldap-adapter:mapclaims");

function hasSource(def, source) {
    if (typeof def === "object") {
        def = def.attribute;
    }

    if (Array.isArray(def)) {
        return def.find((a) => source[a]);
    }

    return source[def];
}

function valueJson(val) {
    let retval = null;

    debug(`processing value is: ${val}`);
    try {
        if (typeof val === "string") {
            retval = JSON.parse(val);
        }
        else if (Array.isArray(val)) {
            retval =  val.map((v) => JSON.parse(v));
        }
    }
    catch (err) {
        debug("JSON parsing error %o", err);
        retval = null;
    }
    debug("json parsing result: %o", retval);
    return retval;
}

function reverseJson(val) {
    if (!val) {
        return null;
    }
    if (!Array.isArray(val)) {
        return JSON.stringify(val);
    }

    return val.map((obj) => JSON.stringify(obj));
}

function valueReplace(val, swap) {
    if (typeof val === "string") {
        return Object.keys(swap).indexOf(val) < 0 ? val : swap[val];
    }
    return val
        .map((v) => Object.keys(swap).indexOf(v) < 0 ? v : swap[v])
        .filter((v) => v !== null && typeof v !== undefined);
}

function valueLowercase(val) {
    if (Array.isArray(val)) {
        return val.map((v) => v.toLowerCase());
    }
    return val.toLowerCase();
}

function valueExtend(val, suffix) {
    if (typeof suffix === "string"){
        if (Array.isArray(val)) {
            return val.map((v) => typeof v === "string" ? `${v}${suffix}` : v );
        }
        if (typeof val === "string") {
            return `${val}${suffix}`;
        }
    }
    return val;
}

function reverseExtend(value, suffix) {
    if (!value) {
        return null;
    }

    if (!Array.isArray(value)) {
        value = [value];
    }

    return value.map((val) => val.split(suffix).join(""));
}

function valueSplit(arr, sep) {
    debug("called valueSplit");
    if (typeof arr === "string") {
        return arr.split(sep);
    }
    return arr.map((e) => typeof e === "string" ? e.split(sep) : e);
}

function reverseSplit(value, sep) {
    if (typeof value === "string") {
        return value;
    }
    if (Array.isArray(value)) {
        return value.join(sep);
    }
    return null;
}

function valueAssign(val, attrMap) {
    if (Array.isArray(val) && Array.isArray(attrMap)) {
        let retval = {};

        attrMap.reverse();
        val.reverse();

        attrMap.map((m,i) => {
            if (val[i] !== null && typeof val[i] !== "undefined") {
                retval[m] = val[i];
            }
        });
        // fill remaining elements into the last attribute
        if (attrMap.length < val.length) {
            const len = attrMap.length - 1;

            retval[attrMap[len]] = val.slice(len).reverse();
        }

        // reverse back otherwise the code breaks
        attrMap.reverse();
        return retval;
    }
    return val;
}

function reverseAssign(value, attrMap) {
    if (typeof value === "object" && Array.isArray(attrMap)) {
        if (!Array.isArray(value)) {
            value = [value];
        }

        value = value.map((v) => attrMap.map((a) => v[a]));
    }
    return value;
}

function valueLabel(val, label) {
    if (typeof val === "object") {
        return val[label] ? val[label] : null;
    }

    if (typeof val === "string") {
        val = valueSplit(" ");
        return val[1] === label ? val[0] : null;
    }

    val = valueSplit(" ");
    val = val
        .map((split) => {
            if (Array.isArray(split)) {
                return split[1] === label ? split[0] : null;
            }
            if (typeof split === "object") {
                // ensure null value if result is empty
                return split[label] ? split[label] : null;
            }
            return null;
        })
        .filter((rval) => rval !== null);

    if (!val.length) {
        return 0;
    }

    return val.length > 1 ? val : val.pop();
}

function reverseLabel(value, label) {
    if (!Array.isArray(value)) {
        value = [value];
    }

    value = value.map((v) => [v, label].join(" "));

    return value.length > 1 ? value : value.pop();
}

function transposeSource(mapdef, source) {
    let mdef = mapdef.attribute;
    let result = null;

    mdef = Array.isArray(mdef) ? mdef.find((a) => source[a]) : mdef;

    if (mdef) {
        result = source[Array.isArray(mdef) ? mdef.find((a) => source[a]) : mdef];
    }

    debug(`result for ${mdef} is ${result}`);

    if (result && mapdef.replace) {
        result = valueReplace(result, mapdef.replace);
    }

    if (result && mapdef.separator) {
        result = valueSplit(result, mapdef.separator);

        if (result && mapdef.assign) {
            result = valueAssign(result, mapdef.assign);
        }
    }
    else if (result && mapdef.json) {
        debug("json parse");
        result = valueJson(result);
    }

    if (result && mapdef.label) {
        result = valueLabel(result, mapdef.label);
    }

    if (result && mapdef.lowercase) {
        result = valueLowercase(result);
    }

    if (result && mapdef.suffix) {
        result = valueExtend(result, mapdef.suffix);
    }

    if (result && mapdef.array && !Array.isArray(result)) {
        result = [result];
    }

    return result;
}
function hasAlias(claim, mapdef, aliases) {
    if (!Array.isArray(mapdef)) {
        mapdef = [mapdef];
    }

    mapdef.map((def) => {
        if (typeof def === "string") {
            def = {attribute: def};
        }

        if (Array.isArray(def.attribute)) {
            const root = def.attribute[0];

            if (def.attribute.length > 1) {
                aliases[root] = def.attribute;
            }
        }
    });
}

function mapClaim(claim, mapdef, source, forceArray, target) {
    if (!Array.isArray(mapdef)) {
        mapdef = [mapdef];
    }

    // find mapdef in the source
    mapdef = mapdef.find((def) => hasSource(def, source));

    if (mapdef)  {
        // handle the functional definition
        if (typeof mapdef === "string") {
            mapdef = {attribute: mapdef};
        }

        debug("map claim: %O", claim);

        let value = transposeSource(mapdef, source);

        if (typeof value === "undefined" || value === null) {
            return;
        }

        if (forceArray.indexOf(claim) >= 0 && !Array.isArray(value)) {
            value = [value];
        }

        // assign the definition
        const xclaim = claim.split(".");
        const fclaim = xclaim.pop();
        let nclaim;
        let xtarget = target;

        // create nested target objects if necessary
        while (xclaim.length) {
            nclaim = xclaim.shift();
            if (!xtarget[nclaim]) {
                xtarget[nclaim] = {};
            }
            xtarget = xtarget[nclaim];
        }

        xtarget[fclaim] = value;
    }
}

function reverseClaim(claim, mapdef, source, mapTarget) {
    debug("reverse claim");

    if (Array.isArray(mapdef)) {
        mapdef = mapdef[0];
    }
    if (typeof mapdef === "string") {
        mapdef = {attribute: mapdef};
    }
    if (!mapdef) {
        debug("no mapping definition ... stop!");
        return;
    }

    let xsource = source;
    const xclaim = claim.split(".");
    const fclaim = xclaim.pop();
    let nclaim;

    while (xsource && xclaim.length) {
        nclaim = xclaim.shift();
        xsource = xsource[nclaim];
    }

    if (!(xsource && xsource[fclaim])) {
        debug("claim not found");
        return;
    }

    let value = xsource[fclaim];

    debug("get value %O", value);

    if (value && mapdef.suffix) {
        value = reverseExtend(value, mapdef.suffix);
    }

    if (value && mapdef.separator) {
        if (mapdef.assign) {
            value = reverseAssign(value, mapdef.assign);
        }
        if (value) {
            value = reverseSplit(value, mapdef.separator);
        }
    }
    else if (value && mapdef.json) {
        value = reverseJson(value);
    }
    else if (value && mapdef.label) {
        value = reverseLabel(value, mapdef.label);
    }

    if (!value) {
        debug("lost value?");
        return;
    }
    // assign value
    if (Array.isArray(mapdef.attribute)) {
        debug("normalize attribute");
        mapTarget[mapdef.attribute[0]] = value;
    }
    else {
        debug("assign attribute %s", mapdef.attribute);
        mapTarget[mapdef.attribute] = value;
    }
}

function map_claims(mapping, source, forceArray = []) {
    if (!(mapping && source)) {
        return source;
    }
    const mapTarget = {};

    Object.keys(mapping).map((claim) => mapClaim(claim, mapping[claim], source, forceArray, mapTarget));
    return mapTarget;
}

function reverse_claims(mapping, source) {
    if (!(mapping && source)) {
        return source;
    }
    const mapTarget = {};

    Object.keys(source).map((claim) => reverseClaim(claim, mapping[claim], source, mapTarget));
    return mapTarget;
}

function find_aliases(mapping) {
    const aliases = {};

    Object.keys(mapping).map((claim) => hasAlias(claim, mapping[claim], aliases));

    return aliases;
}

module.exports.mapclaims     = map_claims;
module.exports.reverseclaims = reverse_claims;
module.exports.findaliases = find_aliases;
