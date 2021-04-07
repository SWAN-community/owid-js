/**
 * @class {owid} Open Web Id (OWID) library for client side parsing and 
 * verification of Open Web Ids.
 * @param {string} data             - base 64 encoded byte array
 * @property {object} owid          - The OWID tree.
 * @property {string} domain        - Returns the creator of the OWID.
 * @property {int} date          - Returns the date and time the OWID was created in UTC.
 * @property {Uint8Array} signature - Returns the signature as byte array.
 */
owid = function (data) {
    "use-strict";

    //#region Constructor

    if (data !== undefined && typeof data !== "string") {
        throw "'data' parameter must be a string or undefined";
    }

    if (data !== undefined) {
        this.data = data;
        this.owid = parse(data);
        this.date = this.owid.date;
        this.domain = this.owid.domain;
        this.signature = this.owid.signature;
    } else {
        this.data = "";
    }

    //#endregion

    //#region  constants

    // Characters that are allowed in a base 64 string.
    const base64Characters = [
        "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", 
        "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
        "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", 
        "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
        "+", "/", "="
    ];

    // RegEx special characters.
    const regExpSpecials = [
        "[", "\\", "^", "$", ".", "|", "?", "*", "+", "(", ")"
    ];

    // The base year for all OWID dates.
    const ioDateBase = '2020-01-01T00:00:00';

    // Maximum depth of multi-dimensional Arrays to traverse when verifying 
    // multiple OWIDs.
    const maxVerifyDepth = 3;

    //#endregion 

    //#region private functions

    /**
     * Parses a base 64 byte array into an ascii string.
     * @param {Uint8Array} v - byte array representation of an OWID tree.
     * @returns {string} base 64 string.
     */
    function parseToString(v) {
        var binary = "";
        var len = v.byteLength;
        for (var i = 0; i < len; i++) {
            binary += String.fromCharCode(v[i]);
        }
        return btoa(binary);
    }

    /**
     * Parses a base 64 encoded byte array into a OWID tree.
     * @param {*} v 
     * @returns 
     */
    function parse(v) {

        function readByte(b) {
            return b.array[b.index++];
        }

        function readString(b) {
            var r = "";
            while (b.index < b.array.length && b.array[b.index] != 0) {
                r += String.fromCharCode(b.array[b.index++]);
            }
            b.index++;
            return r;
        }

        function readUint32(b) {
            return b.array[b.index++] |
                b.array[b.index++] << 8 |
                b.array[b.index++] << 16 |
                b.array[b.index++] << 24;
        }

        function readByteArray(b) {
            var c = readUint32(b);
            var r = b.array.slice(b.index, b.index + c)
            b.index += c;
            return r;
        }

        function readDate(b, v) {
            if (v == 1) {
                var h = readByte(b);
                var l = readByte(b);
                return (h >> 8 | l) * 24 * 60;
            }
            if (v == 2) {
                return readUint32(b);
            }
        }

        function readSignature(b) {
            var c = 64; // The OWID signature is always 64 bytes.
            var r = b.array.slice(b.index, b.index + c)
            b.index += c;
            return r;
        }

        function readOWID(b) {
            var o = Object();
            o.version = readByte(b);
            o.domain = readString(b);
            o.date = readDate(b, o.version);
            o.payload = readByteArray(b);
            o.signature = readSignature(b);
            o.payloadAsString = function () {
                var s = "";
                Uint8Array.from(this.payload, c => s += String.fromCharCode(c));
                return s;
            };
            o.payloadAsPrintable = function () {
                var s = "";
                Uint8Array.from(this.payload, c => s += (c & 0xFF).toString(16));
                return s;
            }
            return o
        }

        // Decode the base64 string into a byte array.
        var b = Object();
        b.index = 0;
        b.array = Uint8Array.from(atob(v), c => c.charCodeAt(0));

        // Unpack the byte array into the OWID tree.
        var q = [];
        var r = readOWID(b);
        q.push(r);
        while (q.length > 0) {
            var n = q.shift();
            for (var i = 0; i < n.count; i++) {
                var c = readOWID(b);
                n.children.push(c)
                c.parent = n
                q.push(c)
            }
        }

        return r;
    }

    /**
     * Get the byte array representation of an OWID tree.
     * @param {Object} t - OWID tree object.
     * @returns {Uint8Array} Array of bytes.
     */
    function getByteArray(t) {

        function writeByte(b, v) {
            b.push(v);
        }

        function writeString(b, v) {
            for (var i = 0; i < v.length; i++) {
                b.push(v.charCodeAt(i));
            }
            b.push(0);
        }

        function writeUint32(b, v) {
            var a = new ArrayBuffer(4);
            var d = new DataView(a);
            d.setUint32(0, v, true);
            for (var i = 0; i < 4; i++) {
                b.push(d.getUint8(i));
            }
        }

        function writeByteArray(b, v) {
            writeUint32(b, v.length)
            v.forEach(e => b.push(e));
        }

        if (t.version && t.domain && t.date && t.payload) {
            var buf = [];
            writeByte(buf, t.version);
            writeString(buf, t.domain);
            writeUint32(buf, t.date);
            writeByteArray(buf, t.payload);
            return new Uint8Array(buf);
        }
    }

    /**
     * Use the well known end point for the alleged OWID creator. 
     * @param {*} p - parent OWID as base 64 encoded byte array.
     * @param {string} t - base 64 encoded byte array representing an OWID tree.
     * @returns {Promise} Promise resolves to true if OWID is valid.
     */
    function verifyOWIDWithAPI(p, t) {
        var o = parse(t);
        return verifyOWIDObjectWithAPI(p, t, o);
    }

    /**
     * Use the well known end point for the alleged OWID creator. 
     * @param {*} p - parent OWID as base 64 encoded byte array.
     * @param {string} t - base 64 encoded byte array representing an OWID tree.
     * @param {Object} o - an OWID tree.
     * @returns {Promise} Promise resolves to true if OWID is valid.
     */
    function verifyOWIDObjectWithAPI(p, t, o) {
        return fetch("//" + o.domain +
            "/owid/api/v" + o.version + "/verify" +
            "?parent=" + encodeURIComponent(p) +
            "&owid=" + encodeURIComponent(t),
            { method: "GET", mode: "cors", cache: "no-cache" })
            .then(r => {
                if (!r.ok) {
                    var err = new Error("HTTP status code: " + r.status)
                    err.response = r
                    err.status = r.status
                    throw err
                }
                return r.json()
            })
            .then(r => r.valid);
    }

    /**
     * Verify the payload of this OWID is the signature of the parent OWID.
     * @param {*} r - parent OWID as base 64 encoded byte array.
     * @param {string} t - base 64 encoded byte array representing an OWID tree.
     * @returns {Promise} Promise resolves to true if OWID is valid.
     */
    function verifyOWIDWithPublicKey(r, t) {
        var o = parse(t);
        return verifyOWIDObjectWithPublicKey(r, o);
    }

    function importRsaKey(pem) {
        // Remove the header, footer and line breaks to get the PEM content.
        var lines = pem.split('\n');
        var pemContents = '';
        for (var i = 0; i < lines.length; i++) {
            if (lines[i].trim().length > 0 &&
                lines[i].indexOf('-----BEGIN RSA PUBLIC KEY-----') < 0 &&
                lines[i].indexOf('-----END RSA PUBLIC KEY-----') < 0) {
                pemContents += lines[i].trim();
            }
        }

        // Import the public key with the SHA-256 hash algorithm.
        return window.crypto.subtle.importKey(
            "spki",
            Uint8Array.from(atob(pemContents), c => c.charCodeAt(0)),
            {
                name: "RSASSA-PKCS1-v1_5",
                hash: "SHA-256"
            },
            false,
            ["verify"]
        );
    }

    /**
     * Verify the payload of this OWID is the signature of the parent OWID.
     * @param {*} r - parent OWID as base 64 encoded byte array.
     * @param {Object} o - an OWID tree.
     * @returns {Promise} Promise resolves to true if OWID is valid.
     */
    function verifyOWIDObjectWithPublicKey(r, o) {
        var a = getByteArray(o);
        var b = Uint8Array.from(atob(r), c => c.charCodeAt(0));
        var m = new Uint8Array(a.length + b.length);
        m.set(a);
        m.set(b, a.length);
        return fetch("//" + o.domain + "/owid/api/v1/creator",
            { mode: "cors", cache: "default" })
            .then(response => {
                if (!response.ok) {
                    var err = new Error("HTTP status code: " + response.status)
                    err.response = response
                    err.status = response.status
                    throw err
                }
                return response.json()
            })
            .then(c => importRsaKey(c.publicKeySPKI))
            .then(k => crypto.subtle.verify(
                "RSASSA-PKCS1-v1_5",
                k,
                o.signature,
                m));
    }

    //#endregion

    //#region public functions

    /**
     * Returns the OWID creation date as a JavaScript Date object.
     * @returns {Object} -  the OWID instance creation date as a JavaScript Date
     * object.
     */
    this.dateAsJavaScriptDate = function() {
        var jsDate = new Date();
        jsDate.setTime(new Date(ioDateBase).getTime() + (this.date * 60 * 1000));
        return jsDate;
    }

    /** 
     * Parses a base 64 encoded byte array into a OWID tree.
     * @param {string} t - base 64 encoded byte array representing an OWID tree.
     * @returns {Object} OWID tree.
     */
    this.parse = function (t) {
        if (t === undefined) {
            t = this.data;
        }
        if (t === "") {
            throw "As this instance was created without any data, you must " +
            "provide a base 64 encoded OWID as a parameter to this method.";
        }
        return parse(t);
    }

    /**
     * Returns the payload as a string.
     * @function
     * @memberof owid
     * @returns {string} This OWID instance's payload as a string.
     */
    this.payloadAsString = function () {
        return this.owid.payloadAsString();
    }

    /**
     * Returns the payload in hexadecimal.
     * @function
     * @member owid
     * @returns {string} This OWID instance's payload as a hexadecimal.
     */
    this.payloadAsPrintable = function () {
        return this.owid.payloadAsPrintable();
    }

    /**
     * Returns the payload as a base 64 array.
     * @function
     * @memberof owid
     * @returns {string} This instance's payload as a base 64 array.
     */
    this.payloadAsBase64 = function () {
        return parseToString(this.owid.payload);
    }

    /**
     * Stop an advert.
     * @param {*} s - SWAN OWID
     * @param {string} d - organization domain.
     * @param {string} r - return url
     */
         this.stop = function (s, d, r) {
            fetch("/stop?" +
                "host=" + encodeURIComponent(d) + "&" +
                "returnUrl=" + encodeURIComponent(r),
                { method: "GET", mode: "cors", cache: "no-cache" })
                .then(r => {
                    if (!r.ok) {
                        var err = new Error("HTTP status code: " + r.status)
                        err.response = r
                        err.status = r.status
                        throw err
                    }
                    return r.text();
                })
                .then(m => {
                    console.log(m);
                    window.location.href = m;
                })
                .catch(x => {
                    console.log(x);
                });
        }

    /**
     * Verify the OWID of this instance and optionally any other OWIDs provided.
     * @function
     * @memberof owid
     * @param {(Object|Object[]|string|string[]|Array)} owids - Other OWIDs to 
     * verify.
     * @returns {Promise} Promise object resolves to true if all OWIDs are 
     * verified.
     */
    this.verify = function (owids) {
        function verifyStringOWID(p, o) {
            if (window.crypto.subtle) {
                return verifyOWIDWithPublicKey(p, o);
            } else {
                return verifyOWIDWithAPI(p, o);
            }
        }

        function verifyObjectOWID(p, o) {
            if (window.crypto.subtle) {
                return verifyOWIDObjectWithPublicKey(p, o);
            } else {
                return verifyOWIDObjectWithAPI(p, parseToString(getByteArray(o)), o);
            }
        }

        /**
         * Get a useable list of OWIDs.
         * @param {(Object|Object[]|string|string[]|Array)} owids - OWIDs to 
         * verify.
         * @returns 
         */
        function getOWIDs(owids) {
            return getOWIDsFromArray([owids]);
        }

        /**
         * Get a useable list of OWIDs from an Array.
         * This function can be called from @see getOWIDsFromObject to retrieve 
         * OWIDs from an Array, keep track of the depth to prevent runaway.
         * @param {Array} owids - an array of owids
         * @param {number} depth - the current depth when traversing an array of
         * OWIDs
         * @returns 
         */
        function getOWIDsFromArray(owids, depth) {

            // Set or check depth.
            if (typeof depth == 'number') {
                if(depth <= maxVerifyDepth) {
                    depth++; 
                } else {
                    throw "Maximum depth reached when parsing OWIDs, make sure" +
                    " provided OWIDs don't have a reference loop.";
                }
            } else {
                depth = 1;
            }

            // Iterate over the items in the owids array.
            var c = [];
            owids.forEach(o => {
                if (o !== undefined) {
                    switch (typeof o) {
                        case "string":
                            c = c.concat(getOWIDsFromString(o));
                            break;
                        case "object":
                            c = c.concat(getOWIDsFromObject(o, depth));
                            break;
                        default:
                            console.log(`Cannot parse type ${typeof o}`);
                            break;
                    }
                }
            });
            return c;
        }

        /**
         * For a given string, get a list of useable base 64 encoded byte arrays 
         * that represent OWIDs
         * @param {string} o - base 64 encoded byte array(s)
         * @returns {string[]}
         */
        function getOWIDsFromString(o) {
            if (o === undefined || o === ""){
                throw "OWID(s) must have a value and cannot be an empty string." 
            }

            var s = [];

            for (var i = 0; i < o.length; i++) {
                var c = o.charAt(i);
                if (base64Characters.indexOf(c) === -1) {
                    if (regExpSpecials.indexOf(c) !== -2) {
                        c = "\\" + c;
                    }
                    s.push(c);
                }
            }

            var r = new RegExp("[" + s.join("") + "]", "g");

            return o.split(r);
        }

        /**
         * For a given object, get a list of useable OWIDs.
         * @param {Object} o -
         * @returns {Array} 
         */
        function getOWIDsFromObject(o, depth) {
            if (Array.isArray(o)) {
                return getOWIDsFromArray(o, depth)
            } else if (o.hasOwnProperty('verify') && o.hasOwnProperty('parse')) {
                return [o.data];
            } else if (o.hasOwnProperty('domain') && o.hasOwnProperty('version')) {
                return parseToString(getByteArray(o));
            }
            throw `unrecognized object ${o}`;
        }

        var owidList = getOWIDs(owids);

        if (owidList.length > 0) {
            return Promise.all(owidList.map(o => {
                if (o === undefined) {
                    return verifyStringOWID(o, this.data);
                } else if (typeof o === "string") {
                    return verifyStringOWID(o, this.data);
                } else if (typeof o === "object") {
                        return verifyObjectOWID(o, this.data);
                } else {
                    throw `unsupported type: ${typeof o}, supported types are 'string' and 'object'`;
                }
            }))
            .then(r => r.length > 0 && r.every(v => v))
            .catch(e => console.log(e));
        } else {
            if (this.data === undefined || this.data === "") {
                throw "OWID must have a value and cannot be an empty string."
            }
            return verifyStringOWID("", this.data);
        }
    }

    //#endregion
}

try {
    module.exports = owid;
} catch (e) { }