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

    debug("test find()");

    try {
        await c.bind();
    }
    catch (err) {
        debug("error %O", err);
        throw "exit";
    }

    var result;

    try {
        result = await c.find("phish3");
    }
    catch (err) {
        debug("error %O", err);
        throw "exit";
    }
    debug("result %O", result);
    debug("test delete()");

    // the upsert completes, but the changes are not necessarilz in the directory
    // find phish2 again
    const p3 = await c.destroy("phish3");

}

main().then(() => process.exit(0)).catch(() => process.exit(1));
