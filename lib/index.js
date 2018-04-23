const debug = require("debug")("ldap-adapter:core");
const LdapJS     = require("ldapjs");
const buildFilter = require("./buildFilter.js");
const {mapclaims, reverseclaims, findaliases} = require("./mapclaims.js");

const LdapErrors = {
    options: "NoLDAPOptionsProvided",
    url: "NoLDAPServerOption",
    port: "NoLDAPPortOption",
    password: "NoLDAPPassword",
    base: "NoLDAPBaseDN",
    bind: "NoLDAPBindDN",
    connection: "NoConnection",
    notFound: "NotFound",
    unauthorized: "NotAuthorized"
};

function localOptions(clsOpts, usrOpts) {
    let result = Object.assign({}, clsOpts);

    if (usrOpts) {
        result = Object.assign(result, usrOpts);
    }
    return result;
}

class LDAPAdapter {
    constructor(opts, mapping, connection) {
        this.ldapOpts = Object.assign({}, opts);

        if (typeof connection === "object") {
            this.ldapBind = Object.assign({}, connection);
        }

        if (typeof mapping === "object") {
            this.mapping = Object.assign({}, mapping);
        }
    }

    clone(newOpts, mapping) {
        const opts = localOptions(this.ldapOpts, newOpts);

        opts.mapping    = mapping   || this.mapping;

        const newclone = new LDAPAdapter(opts, mapping || this.mapping, this.ldapBind);

        newclone.connection = this.connection;

        return newclone;
    }

    processAliases() {
        if (this.mapping && !this.mappingAliases) {
            this.mappingAliases = findaliases(this.mapping);
        }
    }

    async bind(opts) {
        const ldapOpts = localOptions(this.ldapBind, opts);

        [
            "url",
            "bind",
            "password"
        ].forEach((e) => {
            if (!ldapOpts[e]) {
                throw LdapErrors[e];
            }
        });

        const connection = LdapJS.createClient({
            url: ldapOpts.url
        });

        try {
            const tmpConnection = await new Promise((resolve, reject) => { // eslint-disable-line no-unused-vars
                connection.bind(
                    ldapOpts.bind,
                    ldapOpts.password,
                    (err) => err ? reject(err) : resolve(connection));
            });
        }
        catch (error) {
            debug("%O", error);
            throw LdapErrors.unauthorized;
        }

        this.connection = connection;
    }

    // the raw ldap search call.
    async search(oFilter, baseDN, scope = "sub") {
        const filter = buildFilter(oFilter);

        // debug(baseDN);
        // debug(filter);
        // debug(scope);
        return new Promise((resolve, reject) => {
            this.connection.search(baseDN,
                                   {
                                       filter,
                                       scope
                                   },
                                   (err, res) => {
                                       if (err) {
                                           reject(err);
                                       }
                                       else {
                                           var resset = [];

                                           res.on("searchEntry", entry => resset.push(entry.object));
                                           res.on("end", () => resolve(resset));
                                       }
                                   });
        });
    }

    async rawFind(id, scope = "sub") {
        const lScope = scope || "sub";
        const lClass = this.ldapOpts.class || "*";

        let filter = ["&", `objectClass=${lClass}`];

        if (!id) {
            scope = "base";
        }
        else {
            filter = filter.concat([`${this.ldapOpts.id}=${id}`]);
        }

        if (this.ldapOpts.filter && this.ldapOpts.filter.length) {
            filter = filter.concat(this.ldapOpts.filter);
        }

        const entries = await this.search(filter, this.ldapOpts.base, lScope);

        if (entries.length !== 1) {
            debug(entries.length);
            // entries.map((e) => debug("%O", e));
            return null;
        }

        const result = entries.pop();

        // splitLabeledUri(result);

        return result;
    }

    async find(id, scope = "sub") {
        let result = await this.rawFind(id, scope);

        // debug("%o => %O", id, result);

        if (this.mapping && Object.keys(this.mapping).length) {
            // result = mapClaims(this.mapping, result, []);
            result = mapclaims(this.mapping, result, []);
        }

        if (this.subclaims) {
            // find sub claims
            // map sub claims
        }

        return result;
    }

    async findAndBind(id, password) {
        const lClass = this.ldapOpts.class || "*";

        if (!(this.ldapOpts && this.ldapOpts.bind)) {
            debug("object not allowed to bind");
            throw LdapErrors.bind;
        }

        let filter = ["&", `objectClass=${lClass}`, `${this.ldapOpts.bind}=${id}`];

        if (this.ldapOpts.filter && this.ldapOpts.filter.length) {
            filter = filter.concat(this.ldapOpts.filter);
        }

        const entries = await this.search(filter, this.ldapOpts.base);

        if (!entries.length) {
            debug("bind not found");
            throw LdapErrors.unauthorized;
        }

        if (entries.length > 1) {
            debug("bind not unique");
            throw LdapErrors.unauthorized;
        }

        const bind = entries[0].dn;
        const connection = this.clone({base: bind});

        await connection.bind({ bind, password });

        return connection;
    }

    async upsert(id, payload) {
        this.processAliases(); // figure out ldap aliases and which are in active use for the entry
        // reverse payload to ldap structured
        const rPayload = reverseclaims(this.mapping, payload);
        const entry = await this.rawFind(id);

        try {
            if (!entry) {
                debug("insert new entry %o", id);
                await this.insertEntry(id, rPayload);
            }
            else {
                debug("update entry %o", id);
                await this.updateEntry(entry, rPayload);
            }
        }
        catch (err) {
            debug("upsert failed: %o", err);
        }
    }

    async insertEntry(id, payload) {
        payload[this.ldapOpts.upsert.dn] = id;
        // set dn
        const dn = `${this.ldapOpts.upsert.dn}=${id},${this.ldapOpts.upsert.suffix},${this.ldapOpts.base}`;

        // payload.dn = dn;

        // set object class
        payload.objectClass = this.ldapOpts.upsert.class;

        return new Promise((resolve, reject) => {
            this.connection.add(dn, payload, (err) => err ? reject(err) : resolve());
        });
    }

    async updateEntry(oldPayload, newPayload) {
        //const add = {}, mod = {}, del = {};

        // add -> key exists in newPayload but not in oldPayload
        // mod -> key exists in new and oldPayload
        const dn = oldPayload.dn;

        Object.keys(newPayload).map(async (k) => {
            let change;

            if (["dn", "objectClass", this.ldapOpts.upsert.dn].indexOf(k) < 0) {
                let ok = k;

                // find potential alias
                // MUST NOT create duplicate values that are present on aliases
                // already
                if (this.mappingAliases[k]) {
                    ok = this.mappingAliases[k].find(a => typeof oldPayload[a] !== "undefined");
                }

                // debug("%o -> %o", k, ok);

                if (oldPayload[ok]) {
                // mod -> if single

                    debug("update %o for %o from %o", k, dn, ok);

                    if (!Array.isArray(oldPayload[ok]) && !Array.isArray(newPayload[k])) {
                        // dont optimize, because the next else will be then mistaken
                        if (newPayload[k] !== oldPayload[ok]) {

                            debug("%O", oldPayload[ok]);
                            debug("%O", newPayload[k]);
                            const modification = {};

                            try {
                                modification[k] = newPayload[k];
                                change = new LdapJS.Change({
                                    operation: "replace",
                                    modification
                                });
                                debug("replace %o", k);
                                debug("update %O", modification);

                                await new Promise((resolve, reject) => this.connection.modify(dn, change, (err) => err ? reject(err) : resolve()));
                                debug("value modified");
                            }
                            catch(err) {
                                debug("%O", err);
                            }
                        }
                    }
                    else {
                        if (!Array.isArray(oldPayload[ok])) {
                            oldPayload[ok] = [oldPayload[ok]];
                        }
                        if (!Array.isArray(newPayload[k])) {
                            newPayload[k] = [newPayload[k]];
                        }

                        const aAdd = [], aDel = [];

                        debug("compare %o with %o", newPayload[k], oldPayload[ok]);
                        // add -> if multi and does not exists in old
                        newPayload[k].map((val) => {
                            if (oldPayload[ok].indexOf(val) < 0) {
                                aAdd.push(val);
                            }
                        });

                        // del -> if multi and exists only in old
                        oldPayload[ok].map(val => {
                            if (newPayload[k].indexOf(val) < 0) {
                                aDel.push(val);
                            }
                        });
                        if (aAdd.length) {
                            const modification = {};

                            try {
                                if (k !== ok) {
                                    k = ok;
                                }
                                modification[k] = aAdd;
                                change = new LdapJS.Change({
                                    operation: "add",
                                    modification
                                });

                                debug("update(add) %o", k);
                                debug("update %O", modification);

                                await new Promise((resolve, reject) => this.connection.modify(dn, change, (err) => err ? reject(err) : resolve()));
                            }
                            catch(err) {
                                debug("%O", err);
                            }
                        }
                        if (aDel.length) {
                            const modification = {};

                            try {
                                modification[ok] = aDel;
                                change = new LdapJS.Change({
                                    operation: "delete",
                                    modification
                                });

                                debug("update(del) %o", k);
                                debug("update %O", modification);
                                await new Promise((resolve, reject) => this.connection.modify(dn, change, (err) => err ? reject(err) : resolve()));
                            }
                            catch(err) {
                                debug("%O", err);
                            }
                        }
                    }
                }
                else {
                    const modification = {};

                    try {
                        modification[k] = newPayload[k];
                        change = new LdapJS.Change({
                            operation: "add",
                            modification
                        });

                        debug("update(add2) %o", k);
                        debug("update %O", modification);
                        await new Promise((resolve, reject) => this.connection.modify(dn, change, (err) => err ? reject(err) : resolve()));
                    }
                    catch(err) {
                        debug("modification not performed %O", err);
                    }
                }
            }
        });

        // it is very well possible that the LDAP has keys that are never
        // exposed to the business logic. The logic should not touch those.
    }

    async destroy(id) {
        const entry = await this.rawFind(id);

        if (typeof entry === "object" && entry.dn) {
            try {
                await new Promise((resolve, reject) => this.connection.del(entry.dn, (err) => err ? reject(err) : resolve()));
            }
            catch (err) {
                debug("id cannot be deleted %o", err);
            }
        }
    }

    // consume normally refers to an invalidation of an entry without deleting it
    // However, in LDAP this concept does not exist. Therefore, consume is an
    // alias for delete.
    async consume(id) {
        this.destroy(id);
    }
}

module.exports = LDAPAdapter;
