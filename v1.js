/* ****************************************************************************
 * Copyright 2021 51 Degrees Mobile Experts Limited (51degrees.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 * ***************************************************************************/

/**
 * @class {owid} Open Web Id (OWID) library for client side parsing and
 * verification of Open Web Ids. This library is verify only. Creation and
 * signing of OWIDs is performed by the server side implementations.
 * @param {string} data             - base 64 encoded byte array
 * @property {string} data          - The base 64 string the instance was created from.
 * @property {object} owid          - The OWID tree.
 * @property {string} domain        - Returns the creator of the OWID.
 * @property {int} date             - Returns the date and time the OWID was created as minutes since 2020-01-01 00:00.
 * @property {Uint8Array} signature - Returns the signature as byte array.
 */
var owid = function (data) {
    "use strict";

    //#region Constructor

    if (data !== undefined && typeof data !== "string") {
        throw "'data' parameter must be a string or undefined";
    }

    // An empty string is treated as no data, the same as undefined, so
    // the instance can still be used to verify other OWIDs. Parsing an
    // empty string would be refused as an envelope with no version byte.
    if (data !== undefined && data !== "") {
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

    // Used to importing PEM keys and verification.
    const ECDSA = {
        name: "ECDSA",
        namedCurve: "P-256",
        hash: { name: "SHA-256" }
    }
    
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
     * Decode a base 64 string into a byte array.
     * @param {string} v - an OWID tree encoded in base 64.
     * @returns {Object} - a byte array.
     */
    function parseToByteArray(v) {
        return Uint8Array.from(atob(v), c => c.charCodeAt(0));
    }

    /**
     * Parses a base 64 encoded byte array into a OWID tree.
     * @param {string} v - an OWID tree encoded in base 64.
     * @returns {Object} - OWID tree.
     */
    function parse(v) {
        // The OWID signature is always 64 bytes and is the last thing in a
        // valid OWID.
        var signatureLength = 64;

        // Maximum length of the creator domain in the presentation form
        // that an OWID stores, being the text "example.com" rather than
        // the DNS wire format. RFC 1035 section 2.3.4, "Size limits",
        // restricts the total length of a domain name, meaning its label
        // octets and label length octets, to 255 octets or less. That wire
        // format spends one length octet on every label and one zero octet
        // on the root, whereas the presentation form writes a dot in place
        // of each label length octet and has no text at all for the root
        // octet, so the same published limit is 253 characters here.
        var maximumDomainLength = 253;

        // Refuses a read of n bytes that would run past the end of the
        // buffer. Every count in the byte array is whatever the sender
        // declared, so each read is bounded by the bytes actually present
        // rather than trusting the count.
        function checkPresent(b, n, what) {
            if (b.index + n > b.array.length) {
                throw "OWID " + what + " needs '" + n + "' bytes but " +
                    "only '" + (b.array.length - b.index) + "' are present";
            }
        }

        function readByte(b) {
            checkPresent(b, 1, "byte");
            return b.array[b.index++];
        }

        // Reads the zero terminated creator domain. The scan stops at the
        // end of the buffer, so a domain with no zero terminator before the
        // end is refused rather than the index moving past the end, and it
        // also stops one byte past the published maximum, so a buffer whose
        // domain field never terminates costs the maximum rather than the
        // length of whatever was sent.
        function readString(b) {
            var r = "";
            var end = Math.min(
                b.array.length,
                b.index + maximumDomainLength + 1);
            while (b.index < end && b.array[b.index] != 0) {
                r += String.fromCharCode(b.array[b.index++]);
            }
            if (r.length > maximumDomainLength) {
                throw "OWID domain is not terminated within the '" +
                    maximumDomainLength + "' character maximum";
            }
            checkPresent(b, 1, "string terminator");
            b.index++;
            return r;
        }

        function readUint32(b) {
            checkPresent(b, 4, "32 bit integer");
            // The unsigned shift at the end keeps the result unsigned, as
            // the bitwise operators otherwise make a count with the top
            // bit set negative.
            return (b.array[b.index++] |
                b.array[b.index++] << 8 |
                b.array[b.index++] << 16 |
                b.array[b.index++] << 24) >>> 0;
        }

        // Reads the length-prefixed payload. The count is whatever the
        // sender declared, so it is checked against the bytes actually
        // present before anything is sized by it. A valid OWID is the
        // declared payload followed by the signature and nothing else, so
        // the count must equal the bytes remaining less the signature
        // length, and any other count, short or long, is refused here.
        // Until 28 August 2026 the count went straight to slice, and as
        // the count was read as a signed integer a top bit set moved the
        // index backwards, so a malformed OWID parsed to something rather
        // than being refused.
        function readByteArray(b) {
            var c = readUint32(b);
            var remaining = b.array.length - b.index;
            if (remaining !== c + signatureLength) {
                throw "OWID payload length '" + c + "' does not match the '" +
                    remaining + "' bytes present, of which the final '" +
                    signatureLength + "' must be the signature";
            }
            // Preserve the public parser's long-standing ownership model:
            // callers receive a payload with its own backing buffer.
            var r = b.array.slice(b.index, b.index + c)
            b.index += c;
            return r;
        }

        function readDate(b, v) {
            if (v == 1) {
                var h = readByte(b);
                var l = readByte(b);
                return (h << 8 | l) * 24 * 60;
            }
            if (v == 2 || v == 3) {
                return readUint32(b);
            }
        }

        function readSignature(b) {
            var c = signatureLength;
            // The payload check leaves exactly the signature, and this
            // check keeps that true if the payload read ever changes.
            if (b.array.length - b.index !== c) {
                throw "OWID signature length '" + (b.array.length - b.index) +
                    "' not compatible with '" + c + "' OWID signature length";
            }
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
        b.array = parseToByteArray(v);

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
        var buffer;
        var dataView;
        var position;

        function writeByte(v) {
            buffer[position++] = v;
        }

        function writeString(v) {
            for (var i = 0; i < v.length; i++) {
                writeByte(v.charCodeAt(i));
            }
            writeByte(0);
        }

        function writeUint32(v) {
            dataView.setUint32(position, v, true);
            position += 4;
        }

        function writeByteArray(v) {
            writeUint32(v.length);
            buffer.set(v, position);
            position += v.length;
        }

        if (t.version && t.domain && t.date && t.payload) {
            var length = 1 + t.domain.length + 1 + 4 + 4 + t.payload.length;
            buffer = new Uint8Array(length);
            dataView = new DataView(buffer.buffer);
            position = 0;
            writeByte(t.version);
            writeString(t.domain);
            writeUint32(t.date);
            writeByteArray(t.payload);
            return buffer;
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
        var data = new URLSearchParams();
        data.append("parent", p);
        data.append("owid", t);
        var url = "//" + o.domain + "/owid/api/v" + o.version + "/verify";
        return fetch(url,
            {
                method: "POST",
                mode: "cors",
                cache: "no-cache",
                headers: owid.fetchHeaders,
                body: data
            })
            .then(r => {
                if (r.ok) {
                    return r.json();
                }
                return fetchError("Verify", r);
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

    function importEcdsaKey(pem) {
        // Remove the header, footer and line breaks to get the PEM content.
        var lines = pem.split('\n');
        var pemContents = '';
        for (var i = 0; i < lines.length; i++) {
            if (lines[i].trim().length > 0 &&
                lines[i].indexOf('-----BEGIN PUBLIC KEY-----') < 0 &&
                lines[i].indexOf('-----END PUBLIC KEY-----') < 0) {
                pemContents += lines[i].trim();
            }
        }

        // Guard against an empty or header only PEM, where there is no key
        // data to decode. Without this the atob call below yields an empty
        // array and importKey rejects with an opaque DOMException.
        if (!pemContents) {
            throw "public key PEM contains no key data";
        }

        // Import the public key with the SHA-256 hash algorithm.
        return window.crypto.subtle.importKey(
            "spki",
            Uint8Array.from(atob(pemContents), c => c.charCodeAt(0)),
            ECDSA,
            false,
            ["verify"]
        );
    }

    /**
     * Resolve the Web Crypto SubtleCrypto implementation in a way that works
     * both in the browser and in Node (where it is on globalThis.crypto).
     */
    function getSubtle() {
        var c = (typeof globalThis !== "undefined" && globalThis.crypto)
            ? globalThis.crypto
            : (typeof window !== "undefined" ? window.crypto : undefined);
        if (!c || !c.subtle) {
            throw "Web Crypto (crypto.subtle) is not available in this " +
                "environment";
        }
        return c.subtle;
    }

    /**
     * Import an SPKI public key PEM using the supplied SubtleCrypto. Unlike
     * importEcdsaKey this does not depend on the browser global and is used by
     * the offline verifyWithPublicKey below.
     */
    function importSpkiKey(subtle, pem) {
        var lines = pem.split('\n');
        var contents = '';
        for (var i = 0; i < lines.length; i++) {
            var line = lines[i].trim();
            if (line.length > 0 && line.indexOf('-----') < 0) {
                contents += line;
            }
        }
        if (!contents) {
            throw "public key PEM contains no key data";
        }
        return subtle.importKey(
            "spki",
            Uint8Array.from(atob(contents), c => c.charCodeAt(0)),
            ECDSA,
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
        var url = "//" + o.domain + "/owid/api/v1/creator";
        if (o.date != null) {
            // Request the key that was current when this OWID was signed, so
            // OWIDs created before a key rotation still verify.
            url += "?date=" + o.date;
        }
        return fetch(
            url,
            {
                mode: "cors",
                cache: "default",
                headers: owid.fetchHeaders
            })
            .then(r => {
                if (r.ok) {
                    return r.json()    
                }
                return fetchError("Creator", r);
            })
            .then(c => importEcdsaKey(c.publicKeySPKI))
            .then(k => {
                var a = getByteArray(o);
                var b = Uint8Array.from(atob(r), c => c.charCodeAt(0));
                var m = new Uint8Array(a.length + b.length);
                m.set(a);
                m.set(b, a.length);                
                return crypto.subtle.verify(
                    ECDSA,
                    k,
                    o.signature,
                    m);
            });
    }

    /**
     * Throw error from fetch response.
     * @param {string} n - Name of the fetch call
     * @param {Object} r - Response object
     */
    function fetchError(n, r) {
        return r.text().then(text => {
            throw "'" + n + "' request HTTP status code: " + 
            r.status + 
            ". Response: " + 
            text;
        });
    }

    //#endregion

    //#region public functions

    /**
     * Returns the OWID creation date as a JavaScript Date object.
     * @function
     * @memberof owid
     * @returns {Date} the OWID instance creation date as a JavaScript Date
     * object accurate to the minute.
     */
    this.dateAsJavaScriptDate = function() {
        var jsDate = new Date();
        jsDate.setTime(new Date(ioDateBase).getTime() + (this.date * 60 * 1000));
        return jsDate;
    }

    /**
     * Parses a base 64 encoded byte array into a OWID tree. When no
     * parameter is provided the data the instance was created from is used.
     * @function
     * @memberof owid
     * @param {string} [t] - base 64 encoded byte array representing an OWID
     * tree.
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
     * Returns the payload in hexadecimal. Single digit values are not
     * padded with a leading zero.
     * @function
     * @memberof owid
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
     * Verify this OWID offline against a caller-supplied SPKI public key PEM,
     * optionally together with other OWIDs that were signed with it (pass the
     * same others, in the same order, as when signed). Unlike verify() this
     * does not contact any network end point and works in Node as well as the
     * browser. Returns a Promise that resolves to true if the signature is
     * valid.
     * @function
     * @memberof owid
     * @param {string} publicPem - the creator public key in SPKI PEM form.
     * @param {(Object[]|string[])} [others] - other OWIDs covered by the
     * signature.
     * @returns {Promise} Promise resolving to true if the signature verifies.
     */
    this.verifyWithPublicKey = function (publicPem, others) {
        var self = this;
        // Defer so a synchronous failure in getSubtle or importSpkiKey (e.g.
        // no Web Crypto, or an empty PEM) surfaces as a rejected promise
        // rather than a synchronous throw that escapes the caller's .catch.
        return Promise.resolve().then(function () {
            var subtle = getSubtle();
            others = others || [];
            return importSpkiKey(subtle, publicPem).then(function (key) {
                var parts = [getByteArray(self.owid)];
                others.forEach(function (o) {
                    parts.push(typeof o === "string"
                        ? parseToByteArray(o)
                        : getByteArray(o));
                });
                var total = 0;
                parts.forEach(function (p) { total += p.length; });
                var message = new Uint8Array(total);
                var offset = 0;
                parts.forEach(function (p) { message.set(p, offset); offset += p.length; });
                return subtle.verify(ECDSA, key, self.owid.signature, message);
            });
        });
    }

    /**
     * Stop an advert. Posts the organization domain and the return URL to
     * the /stop end point and then redirects the browser to the URL
     * contained in the response.
     * @function
     * @memberof owid
     * @param {*} s - SWAN OWID, reserved and currently unused.
     * @param {string} d - organization domain to stop.
     * @param {string} r - return url to come back to once stopped.
     */
    this.stop = function (s, d, r) {
        var data = new URLSearchParams();
        data.append("host", d);
        data.append("returnUrl", r);
        fetch("/stop",
            {
                method: "POST",
                mode: "cors", 
                cache: "no-cache",
                body: data
            })
            .then(r => {
                if (r.ok) {
                    return r.text();    
                }
                return fetchError("Stop", r);
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

        /**
         * Get combined base 64 string of other owids to verify with
         * @param {string} others - other OWIDs
         */
        function dataForCypto(others) {
            var a = others.map(o => {
                if (typeof o === "string") {
                    return parseToByteArray(o);
                } else if (typeof o === "object") {
                    return getByteArray(o);
                } else {
                    throw `unsupported type: ${typeof o}, supported types are 'string' and 'object'`;
                }
            });

            var length = 0;
            a.forEach(b => length += b.length);

            var v = new Uint8Array(length);
            var offset = 0;
            a.forEach(b => {
                v.set(b, offset);
                offset += b.length;
            });

            var binary = "";
            for (var i = 0; i < length; i++) {
                binary += String.fromCharCode(v[i]);
            }
            return btoa(binary);
        }

        var owidList = getOWIDs(owids);
        if (owidList.length > 0) {
            if (this.data !== undefined && this.data !== "") {
                var b = dataForCypto(owidList);
                return verifyStringOWID(b, this.data);
            } else {
                return Promise.all(owidList.map(o => {
                    if (typeof o === "string") {
                        return verifyStringOWID("", o);
                    } else if (typeof o === "object") {
                            return verifyObjectOWID("", o);
                    } else {
                        throw `unsupported type: ${typeof o}, supported types are 'string' and 'object'`;
                    }
                }))
                .then(r => r.length > 0 && r.every(v => v));
            }
        } else {
            if (this.data === undefined || this.data === "") {
                throw "OWID must have a value and cannot be an empty string."
            }
            return verifyStringOWID("", this.data);
        }
    }

    //#endregion
}

/**
 * Optional HTTP headers sent with the creator request that fetches the
 * public key. Servers MAY require a credential, for example
 * { "X-Api-Key": "<key>" }. The headers go to every creator domain a
 * verification touches, so only set a credential that all the creators
 * in the tree are meant to see.
 */
owid.fetchHeaders = undefined;

try {
    module.exports = owid;
} catch (e) { }
