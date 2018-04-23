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
    "sub": [{"attribute": ["uid", "userid"], "suffix": "@mobinaut.ch", "lowercase": true}],
    "address.street_address": {"attribute": ["street", "streetAddress"]},
    "address.locality": {"attribute": ["l", "localityName"]},
    "address.region": {"attribute": ["st", "stateOrProvideName"]},
    "address.postal_code": ["postalCode"],
    "address.country": {"attribute": ["co", "friendlyCountryName"]},
    "email": "mail",
    "email_verified": [],
    "phone_number": ["telephoneNumber"],
    "phone_number_verified": [],
    "name": [{"attribute": ["cn", "commonname"], "lowercase": true}],
    "given_name": {"attribute": ["gn", "givenName"]},
    "family_name": {"attribute": ["sn", "surname"]},
    "middle_name": [],
    "nickname": "displayName",
    "preferred_username": ["username"],
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
        result = await c.find("phish2");
    }
    catch (err) {
        debug("error %O", err);
        throw "exit";
    }
    debug("result %O", result);
    debug("test findAndBind()");

    c.mapping = mapUser;

    try {
        result = await c.findAndBind("phish2", "m4r10n");
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

    debug("test upsert()");
    result.given_name = "christian";
    await c.upsert("phish3", result);

    result.given_name = ["Glahn-O-Mat", "phish2"];
    debug("extended result %O", result);

    await c.upsert("phish2", result);

    // the upsert completes, but the changes are not necessarilz in the directory
    // find phish2 again
    const p3 = await c.find("phish3");
    const p2 = await c.find("phish2");

    debug("p2: %O", p2);
    debug("p3: %O", p3);
    // test delete()
    // test consume() (find + delete)

    // debug("result %O", result);
    // console.log("success");
}

main().then(() => process.exit(0)).catch(() => process.exit(1));
