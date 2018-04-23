const LDAP = require("./lib/index.js");
const Debug = require("debug");

Debug.enable("ldap-adapter:*");
const debug = Debug("ldap-adapter:trial");

const conn = {
    url: "ldap://ocean.home.lo-f.at:389",
    bind: "uid=root,cn=users,dc=home,dc=lo-f,dc=at",
    password: "m4r10n"
};

const opts = {
    class: "inetOrgPerson",
    base: "cn=users,dc=home,dc=lo-f,dc=at",
    scope: "sub",
    id: "uid",
    bind: "uid",
    upsert: {
        dn: "uid",
        suffix: "cn=dynamic",
        class: ["inetOrgPerson", "organizationalPerson", "person", "top"]
    }
};

const mapUser = {
    "sub": [{"attribute": "swissEduID", "lowercase": true}, {"attribute": ["uid", "userid"], "suffix": "@mobinaut.ch", "lowercase": true}],
    "address.street_address": ["street", "streetAddress"],
    "address.locality": ["l", "localityName"],
    "address.region": ["st", "stateOrProvideName"],
    "address.postal_code": ["postalCode"],
    "address.country": ["co", "friendlyCountryName"],
    "email": "mail",
    "email_verified": [],
    "phone_number": ["telephoneNumber"],
    "phone_number_verified": [],
    "name": [{"attribute": "swissEduID", "lowercase": true}, {"attribute": ["cn", "commonname"], "lowercase": true}],
    "given_name": ["gn", "givenName"],
    "family_name": ["sn", "surname"],
    "middle_name": [],
    "nickname": "displayName",
    "preferred_username": [{"attribute": "swissEduID", "lowercase": true},"username"],
    "birthdate": [],
    "gender": [],
    "zoneinfo": [],
    "locale": ["preferredLanguage"],
    "updated_at": [],
    "profile": [{"attribute": "labeledURI", "label": "profile"}],
    "picture": [{"attribute": "labeledURI", "label": "photo"}],
    "website": [{"attribute": "labeledURI", "label": "homepage"}]
};

async function main() {
    const c = new LDAP(opts, null, conn);

    debug("test find() and bind()");

    try {
        await c.bind();
    }
    catch (err) {
        debug("error %O", err);
        throw "exit";
    }

    var result;

    try {
        result = await c.find("phish");
    }
    catch (err) {
        debug("error %O", err);
        throw "exit";
    }
    debug("result %O", result);
    debug("test findAndBind()");

    c.mapping = mapUser;

    try {
        result = await c.findAndBind("phish", "m4r10n");
    }
    catch (err) {
        debug("error %O", err);
        throw "exit";
    }

    try {
        result = await result.find();
    }
    catch (err) {
        debug("error %O", err);
        throw "exit";
    }

    debug("result %O", result);

    const p2 = await c.find("phish2");

    const p3 = await c.find("phish3");

    debug("p2: %O", p2);
    debug("p3: %O", p3);
    // test delete()
    // test consume() (find + delete)

    // debug("result %O", result);
    // console.log("success");
}

main().then(() => process.exit(0)).catch(() => process.exit(1));
