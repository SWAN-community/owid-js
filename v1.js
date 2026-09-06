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
 * Open Web Id (OWID) library for client side reading and verification of Open
 * Web Ids. This library is verify only, so creation and signing of OWIDs is
 * performed by the server side implementations.
 *
 * An OWID reaches calling code by exactly one route here, which is a
 * successful read of a complete serialized OWID through owid.parse or
 * owid.parseBytes. There is deliberately no way to build one, because an
 * OWID is only worth anything for being signed, and an unsigned one is
 * indistinguishable from a signed one to the code downstream of it, with the
 * difference surfacing later where nobody is watching.
 *
 * Reading answers rather than throwing. The data comes from outside, so
 * failing to be an OWID is an ordinary outcome rather than an error, and
 * whoever sends the data chooses how often that happens and how large each
 * attempt is.
 */
var owid = (function () {
    "use strict";

    //#region constants

    // The OWID signature is always 64 bytes and is the last thing in a valid
    // OWID.
    const signatureLength = 64;

    // Maximum length of the creator domain in the presentation form that an
    // OWID stores, being the text "example.com" rather than the DNS wire
    // format. RFC 1035 section 2.3.4, "Size limits", restricts the total
    // length of a domain name, meaning its label octets and label length
    // octets, to 255 octets or less. That wire format spends one length octet
    // on every label and one zero octet on the root, whereas the presentation
    // form writes a dot in place of each label length octet and has no text at
    // all for the root octet, so the same published limit is 253 characters
    // here.
    const maximumDomainLength = 253;

    // The versions this implementation knows how to read. Version 1 carries
    // the creation date as two bytes of days, and versions 2 and 3 carry it as
    // four bytes of minutes.
    const supportedVersions = [1, 2, 3];

    // The version byte that stands for an absent node rather than an OWID.
    // It is one byte and carries nothing after it, so there is no identifier
    // to hand back, but it is a meaningful thing to meet part way through a
    // run of envelopes and a caller must be able to tell it apart from data
    // that is simply wrong.
    const absentNodeVersion = 0;

    // The base year for all OWID dates.
    const ioDateBase = '2020-01-01T00:00:00';

    // Maximum depth of multi-dimensional Arrays to traverse when verifying
    // multiple OWIDs.
    const maxVerifyDepth = 3;

    // Characters that are allowed in a base 64 string. Used to find the
    // separators in a string that carries several OWIDs.
    const base64Characters = [
        "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M",
        "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
        "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
        "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
        "+", "/", "="
    ];

    // Used for importing PEM keys and verification.
    const ECDSA = {
        name: "ECDSA",
        namedCurve: "P-256",
        hash: { name: "SHA-256" }
    };

    //#endregion

    //#region statuses

    /**
     * Why a read of external data succeeded or failed.
     *
     * These names are the cross-language vocabulary, so a failure means the
     * same thing whichever language read the bytes. The values are stable
     * strings rather than numbers so that a status can be logged as it is.
     */
    const ParseStatus = Object.freeze({

        // The bytes form a structurally valid OWID. This says nothing about
        // the signature, which is a separate question answered separately.
        PARSED: "Parsed",

        // Nothing was supplied to parse, which covers an absent value, an
        // empty string and a buffer of no bytes on either surface. Having
        // nothing to work on is not the same as data that stopped part way
        // through a field, which is UNEXPECTED_END.
        MISSING_INPUT: "MissingInput",

        // The input was supplied in a form this surface cannot read.
        INVALID_INPUT_TYPE: "InvalidInputType",

        // The string is not valid base 64, so there are no bytes to read.
        INVALID_BASE64: "InvalidBase64",

        // The first byte names a version this implementation does not know.
        // Version zero is not one of those, because it is both known and
        // meaningful, and has ABSENT_NODE of its own below.
        UNSUPPORTED_VERSION: "UnsupportedVersion",

        // The bytes are the absent node marker, version byte zero, which
        // stands for a node that is not there rather than for an identifier.
        //
        // No OWID is handed back, because the marker carries no domain, date,
        // payload or signature and so can never verify, and an OWID with no
        // signature reaching a caller is the one thing having no constructor
        // exists to prevent. What a caller gets instead is the fact that a
        // node was deliberately absent, which is a different thing from the
        // bytes being malformed, and on the framed contract a bytesRead of
        // one, so a run of envelopes can be walked straight past it.
        ABSENT_NODE: "AbsentNode",

        // The data stopped early. That covers stopping in the middle of a
        // field, and on the framed contract it also covers a declared payload
        // that runs past the bytes supplied, because there the bytes after
        // the envelope are not for this parse to judge and all that can be
        // said is that what was declared has not arrived yet. A caller
        // reading from a source still arriving needs to know whether to wait
        // for more bytes or give up, and this is the status that says wait.
        UNEXPECTED_END: "UnexpectedEnd",

        // The creator domain is not terminated, or is longer than the
        // published maximum.
        INVALID_DOMAIN_ENCODING: "InvalidDomainEncoding",

        // The declared payload byte count disagrees with the bytes actually
        // present. Checked before anything is sized by the declaration, so a
        // sender cannot make a reader allocate by claiming a large payload it
        // did not send.
        //
        // Only the whole buffer contract reports this, because only there is
        // every byte present by definition, so a declaration that does not
        // leave exactly the signature disagrees with data that is all there.
        // A frame short of its declared payload is UNEXPECTED_END instead.
        BYTE_COUNT_MISMATCH: "ByteCountMismatch",

        // The envelope is structurally consistent but larger than this
        // runtime can hold. Not a fault in the data, and deliberately distinct
        // from the data being wrong, because the same bytes may be readable
        // elsewhere. Reported when the base 64 decode runs out of room. No
        // real envelope reaches it in V8, because the longest string the
        // engine will build decodes to about 402 MB and the largest typed
        // array is far larger, so the test drives the classification by making
        // the decode fail the way it would rather than by building such a
        // string.
        IMPLEMENTATION_CAPACITY_EXCEEDED: "ImplementationCapacityExceeded",

        // Malformed in a way none of the above describes. A fallback for the
        // genuinely unclassified, not a substitute for naming a failure that
        // is already understood.
        //
        // Nothing produces this, so no test asserts it. The only place that
        // names it is the guard on a whole buffer parse finishing anywhere
        // other than the end of the buffer, and the byte count check above
        // already makes that impossible. A framed parse never reaches the
        // guard at all, because a frame is allowed to leave bytes after it.
        // The guard is kept so that a future change to that arithmetic
        // cannot silently start accepting trailing bytes.
        MALFORMED_ENVELOPE: "MalformedEnvelope"
    });

    /**
     * The outcome of asking whether an OWID's signature is genuine.
     *
     * Only two of these say anything about the signature itself. The rest say
     * the question could not be answered, which is a different thing and must
     * never be reported as a forgery. A key that cannot be fetched, a key that
     * cannot be decoded, or a provider that fails leaves the signature
     * unjudged, and a caller acting on "invalid" would reject good identifiers
     * during an outage.
     *
     * On 30 August 2026 the key endpoints served PEM that a strict parser
     * rejects and every offline verification against them failed, while the
     * keys and the identifiers were both fine. Reported as INVALID_KEY that
     * reads as the operational fault it was, and as SIGNATURE_INVALID it would
     * have read as an attack.
     */
    const SignatureStatus = Object.freeze({

        // The signature is genuine for this data and this key.
        SIGNATURE_VALID: "SignatureValid",

        // The signature is well formed and does not match. The only status
        // that means the identifier should be distrusted.
        SIGNATURE_INVALID: "SignatureInvalid",

        // A signature field of the wrong length reached a verification surface
        // directly.
        //
        // Nothing produces this and no test can, because no surface in this
        // library takes a signature on its own. A signature only ever arrives
        // inside an envelope, where a wrong length is a parse failure,
        // UNEXPECTED_END or BYTE_COUNT_MISMATCH, and the envelope never forms.
        // The member is kept so a caller reading a status from any of the
        // language ports finds the same vocabulary.
        INVALID_SIGNATURE_LENGTH: "InvalidSignatureLength",

        // No key could be obtained, or none covers the identifier's date. The
        // signature was never examined.
        KEY_UNAVAILABLE: "KeyUnavailable",

        // Key material arrived but cannot be decoded, imported or used as the
        // required type. The fault is in the key, not the identifier.
        INVALID_KEY: "InvalidKey",

        // The work required exceeds what this runtime can hold.
        //
        // Nothing produces this and no test can, because an envelope this
        // runtime could not hold could not have been parsed in the first
        // place, so no OWID exists to verify. The member is kept so a caller
        // reading a status from any of the language ports finds the same
        // vocabulary.
        IMPLEMENTATION_CAPACITY_EXCEEDED: "ImplementationCapacityExceeded",

        // The check could not be completed for a reason that is not the
        // identifier's fault, such as a verify end point failing, a malformed
        // key response, or a cryptographic provider failing on valid inputs.
        VERIFICATION_ERROR: "VerificationError"
    });

    //#endregion

    //#region private base 64

    /**
     * Encodes a byte array as a base 64 string.
     * @param {Uint8Array} v - the bytes.
     * @returns {string} base 64 string.
     */
    function encodeBase64(v) {
        var binary = "";
        var len = v.byteLength;
        for (var i = 0; i < len; i++) {
            binary += String.fromCharCode(v[i]);
        }
        return btoa(binary);
    }

    /**
     * Decodes a base 64 string into a byte array, answering with a status
     * rather than throwing. The string comes from outside, so not being base
     * 64 is an ordinary outcome.
     * @param {string} v - the base 64 string.
     * @returns {Object} either { bytes } or { status }.
     */
    function decodeBase64(v) {
        var binary;
        try {
            binary = atob(v);
        } catch (e) {
            // A RangeError means the decoded string would not fit, which is
            // this runtime running out of room rather than the data being
            // wrong. Anything else from atob means the characters are not
            // base 64. The two are kept apart because the same bytes may be
            // readable in a runtime with more room.
            return {
                status: e instanceof RangeError
                    ? ParseStatus.IMPLEMENTATION_CAPACITY_EXCEEDED
                    : ParseStatus.INVALID_BASE64
            };
        }
        try {
            return { bytes: Uint8Array.from(binary, c => c.charCodeAt(0)) };
        } catch (e) {
            return { status: ParseStatus.IMPLEMENTATION_CAPACITY_EXCEEDED };
        }
    }

    //#endregion

    //#region private reading

    /**
     * A read that did not produce an OWID. The details name the numbers that
     * disagreed, never the input itself, because a reader logging a failure
     * must not log whatever an untrusted sender chose to put in it.
     * @param {string} status - the ParseStatus.
     * @param {Object} [details] - numbers describing the disagreement.
     * @returns {Object} the result.
     */
    function parseFailed(status, details) {
        var r = { ok: false, owid: null, status: status };
        if (details !== undefined) {
            Object.keys(details).forEach(function (k) {
                r[k] = details[k];
            });
        }
        return Object.freeze(r);
    }

    /**
     * A parse that produced an OWID.
     * @param {Object} instance - the OWID.
     * @param {Object} [details] - anything the surface reports alongside it.
     * @returns {Object} the result.
     */
    function parseSucceeded(instance, details) {
        var r = { ok: true, owid: instance, status: ParseStatus.PARSED };
        if (details !== undefined) {
            Object.keys(details).forEach(function (k) {
                r[k] = details[k];
            });
        }
        return Object.freeze(r);
    }

    /**
     * Reads an unsigned 32 bit little endian count. The unsigned shift at the
     * end keeps the result unsigned, as the bitwise operators otherwise make a
     * count with the top bit set negative.
     * @param {Uint8Array} bytes - the buffer.
     * @param {number} at - the offset of the first byte.
     * @returns {number} the count.
     */
    function readUint32(bytes, at) {
        return (bytes[at] |
            bytes[at + 1] << 8 |
            bytes[at + 2] << 16 |
            bytes[at + 3] << 24) >>> 0;
    }

    /**
     * Parses one OWID out of a buffer, starting where it is told to.
     *
     * The buffer is walked by index and every read is checked against what is
     * left, so a malformed envelope is a comparison that fails rather than an
     * exception that is built and unwound. That matters because whoever is
     * sending the data chooses how often this fails and how large each attempt
     * is.
     *
     * The two surfaces differ in one place only, which is what each may say
     * about the bytes after the envelope. A whole buffer holds one OWID and
     * nothing else, so the declared payload must leave exactly the signature.
     * A frame is one of a sequence, so the declared payload and the signature
     * must be there and whatever follows them is no business of this parse,
     * because it may be the next envelope.
     *
     * @param {Uint8Array} bytes - the buffer.
     * @param {string} [data] - the base 64 the bytes came from, when the
     * caller already has it.
     * @param {boolean} owned - true when the bytes belong to this library and
     * no caller can change them afterwards.
     * @param {number} from - the offset of the first byte of the envelope.
     * @param {boolean} framed - true when the envelope need not be the whole
     * of what is left.
     * @returns {Object} the result.
     */
    function parseOwid(bytes, data, owned, from, framed) {
        var total = bytes.length;

        /**
         * A failure, carrying the count a framed caller advances by. A parse
         * that failed took nothing, so that count is always zero and the
         * position a caller is holding does not move.
         * @param {string} status - the ParseStatus.
         * @param {Object} [details] - numbers describing the disagreement.
         * @returns {Object} the result.
         */
        function failed(status, details) {
            var d = details === undefined ? {} : details;
            if (framed) {
                d.bytesRead = 0;
            }
            return parseFailed(status, d);
        }

        if (from >= total) {
            return failed(ParseStatus.MISSING_INPUT);
        }

        var at = from;
        var version = bytes[at++];
        if (version === absentNodeVersion) {
            // The absent node marker. No OWID is handed back, because the
            // marker carries no domain, date, payload or signature and so
            // could never verify. What is handed back is the fact that the
            // node was deliberately absent rather than malformed, and, on the
            // framed contract, the one byte it occupied, so a caller walking
            // a run of envelopes can step over it and read the next.
            var absent = {};
            if (framed) {
                absent.bytesRead = 1;
            }
            return parseFailed(ParseStatus.ABSENT_NODE, absent);
        }
        if (supportedVersions.indexOf(version) === -1) {
            // Until 30 August 2026 an unknown version read no date at all and
            // carried on, so an envelope naming a version this library does
            // not know could still be parsed as though it were understood.
            return failed(
                ParseStatus.UNSUPPORTED_VERSION, { version: version });
        }

        // The creator domain, stored as ASCII and terminated by a zero byte.
        // The scan stops at the end of the buffer, so a domain with no
        // terminator before the end is refused rather than the index moving
        // past the end, and it also stops one byte past the published maximum,
        // so a buffer whose domain field never terminates costs the maximum
        // rather than the length of whatever was sent.
        var start = at;
        var limit = Math.min(total, start + maximumDomainLength + 1);
        var domain = null;
        var text = "";
        while (at < limit) {
            if (bytes[at] === 0) {
                domain = text;
                at++;
                break;
            }
            text += String.fromCharCode(bytes[at++]);
        }
        if (domain === null) {
            // Either the buffer ended inside the domain, or the domain ran
            // past the maximum without terminating. The second is a domain
            // that cannot be valid rather than data that merely stopped.
            if (at >= total && (at - start) <= maximumDomainLength) {
                return failed(ParseStatus.UNEXPECTED_END);
            }
            return failed(ParseStatus.INVALID_DOMAIN_ENCODING);
        }

        // The creation date, whose width depends on the version. Version 1
        // counts days and the later versions count minutes, and both are
        // reported here as minutes since the OWID base date.
        var date;
        if (version === 1) {
            if (total - at < 2) {
                return failed(ParseStatus.UNEXPECTED_END);
            }
            date = ((bytes[at] << 8) | bytes[at + 1]) * 24 * 60;
            at += 2;
        } else {
            if (total - at < 4) {
                return failed(ParseStatus.UNEXPECTED_END);
            }
            date = readUint32(bytes, at);
            at += 4;
        }

        if (total - at < 4) {
            return failed(ParseStatus.UNEXPECTED_END);
        }
        var declared = readUint32(bytes, at);
        at += 4;

        // The declaration is a claim by the sender about a payload not yet
        // read, so it is compared with what is actually there before anything
        // is sized by it. All of this is ordinary Number arithmetic, which
        // represents an unsigned 32 bit count, that count plus a signature
        // length, and the difference below, every one of them exactly, so
        // nothing here can wrap.
        var remaining = total - at;
        if (framed) {
            // A frame needs its declared payload and its signature to be
            // there, and says nothing at all about what comes after them,
            // because what comes after them may be the next envelope. This
            // one comparison is the whole difference between the two
            // surfaces.
            //
            // Falling short is an unexpected end rather than a count that
            // disagrees. Here the bytes after the envelope are not for this
            // parse to judge, so nothing can be said about a disagreement
            // with data that is all present, and all that is certain is that
            // what was declared has not arrived. A caller reading from a
            // source still arriving needs to know whether to wait for more
            // bytes or give up, and those are different answers.
            if (remaining < declared + signatureLength) {
                return failed(ParseStatus.UNEXPECTED_END, {
                    declared: declared,
                    remaining: remaining
                });
            }
        } else {
            // A whole buffer holds one OWID and nothing else, so the declared
            // payload must leave exactly the signature. Subtracting first
            // gives a negative count when fewer bytes are left than a
            // signature needs, and a negative count can never equal a
            // declaration. Reporting that as a truncation would name a
            // different fault for the same evidence, because what is certain
            // is that the declared payload cannot leave exactly the signature
            // the version requires.
            var present = remaining - signatureLength;
            if (present !== declared) {
                return failed(ParseStatus.BYTE_COUNT_MISMATCH, {
                    declared: declared,
                    present: present
                });
            }
        }

        var payloadAt = at;
        at += declared;
        var signatureAt = at;
        at += signatureLength;
        if (!framed && at !== total) {
            // Unreachable while the count check above holds, and kept so a
            // future change to that arithmetic cannot silently start accepting
            // trailing bytes.
            return failed(ParseStatus.MALFORMED_ENVELOPE);
        }

        // The envelope is valid, so now, and only now, is it worth a copy. A
        // buffer handed in by a caller is copied so that the caller changing
        // their array afterwards cannot change an OWID whose signature is
        // checked over the bytes as they arrived. The bytes reaching here are
        // always a plain Uint8Array, which parseBytes and parseFrame below
        // guarantee, so slice is a copy and not a view. A frame copies only
        // its own window, so one OWID never holds on to the envelopes either
        // side of it.
        var envelope = (owned && from === 0 && at === total)
            ? bytes
            : bytes.slice(from, at);
        var instance = makeOwid(
            data, envelope, version, domain, date,
            payloadAt - from, signatureAt - from);
        return parseSucceeded(
            instance, framed ? { bytesRead: at - from } : undefined);
    }

    /**
     * Reads a complete OWID from its base 64 form.
     * @param {string} value - the base 64 string.
     * @returns {Object} the result.
     */
    function parseBase64(value) {
        if (value === undefined || value === null || value === "") {
            return parseFailed(ParseStatus.MISSING_INPUT);
        }
        if (typeof value !== "string") {
            return parseFailed(ParseStatus.INVALID_INPUT_TYPE);
        }
        var decoded = decodeBase64(value);
        if (decoded.status !== undefined) {
            return parseFailed(decoded.status);
        }
        return parseOwid(decoded.bytes, value, true, 0, false);
    }

    /**
     * A plain unsigned view over the same memory as the byte array given.
     *
     * Reading through this rather than through the value itself means a
     * signed byte array reads as the unsigned bytes it holds, and a view
     * starting part way into a larger buffer reads from where it starts. The
     * view costs nothing, so nothing is sized by the data before it has been
     * checked.
     * @param {Object} buffer - any view of single bytes.
     * @returns {Uint8Array} the view.
     */
    function asByteView(buffer) {
        return new Uint8Array(
            buffer.buffer, buffer.byteOffset, buffer.byteLength);
    }

    /**
     * True when the value is a view of single bytes, tested by the brand
     * rather than by instanceof, because instanceof asks whether the value
     * came from this realm's Uint8Array. Bytes handed over from a worker, an
     * iframe or the Buffer type in node are a different realm's array and
     * would be refused as the wrong type, which they are not.
     * @param {*} buffer - the value to test.
     * @returns {boolean} whether it is a byte array.
     */
    function isByteArray(buffer) {
        return ArrayBuffer.isView(buffer) && buffer.BYTES_PER_ELEMENT === 1;
    }

    /**
     * Parses a complete OWID from a buffer holding exactly one.
     * @param {Uint8Array} buffer - the envelope.
     * @returns {Object} the result.
     */
    function parseBytes(buffer) {
        if (buffer === undefined || buffer === null) {
            return parseFailed(ParseStatus.MISSING_INPUT);
        }
        if (!isByteArray(buffer)) {
            return parseFailed(ParseStatus.INVALID_INPUT_TYPE);
        }
        return parseOwid(asByteView(buffer), undefined, false, 0, false);
    }

    /**
     * Parses one OWID out of a buffer that may hold several, starting at the
     * offset given.
     * @param {Uint8Array} buffer - the buffer.
     * @param {number} [at] - where the envelope starts, 0 by default.
     * @returns {Object} the result, carrying bytesRead.
     */
    function parseFrame(buffer, at) {
        var from = at === undefined ? 0 : at;
        if (buffer === undefined || buffer === null) {
            return parseFailed(
                ParseStatus.MISSING_INPUT, { bytesRead: 0 });
        }
        if (!isByteArray(buffer)) {
            return parseFailed(
                ParseStatus.INVALID_INPUT_TYPE, { bytesRead: 0 });
        }
        // The offset is this library's own parameter rather than anything the
        // sender chose, so a value that is not a place in a buffer is the
        // caller's mistake. It is still answered rather than thrown, because
        // a surface that never throws is easier to use correctly than one
        // that throws for one argument out of two.
        if (!Number.isInteger(from) || from < 0) {
            return parseFailed(
                ParseStatus.INVALID_INPUT_TYPE, { bytesRead: 0 });
        }
        return parseOwid(asByteView(buffer), undefined, false, from, true);
    }

    //#endregion

    //#region private instances

    // Every OWID this library has read, against the bytes it was read from.
    // Nothing outside can add to it, so membership is how internal code tells
    // a real OWID from an object that merely looks like one, and the bytes
    // are what a signature covering this OWID is checked over when it is
    // named as another OWID somewhere else.
    const instances = new WeakMap();

    /**
     * Builds the OWID that a successful read hands back. The fields are read
     * only and the byte arrays are handed out as copies, because a parsed
     * OWID's signature covers its fields as they arrived, so a caller able to
     * change one would hold something whose signature no longer describes it.
     *
     * This function is private to the module and nothing outside can reach it,
     * so a successful read is the only route by which an OWID arrives in
     * calling code.
     *
     * @param {string} [data] - the base 64 the envelope came from, computed on
     * demand when the envelope came from raw bytes.
     * @param {Uint8Array} envelope - the complete OWID bytes.
     * @param {number} version - the version byte.
     * @param {string} domain - the creator domain.
     * @param {number} date - minutes since the OWID base date.
     * @param {number} payloadAt - offset of the first payload byte.
     * @param {number} signatureAt - offset of the first signature byte.
     * @returns {Object} the OWID.
     */
    function makeOwid(
        data, envelope, version, domain, date, payloadAt, signatureAt) {

        // Views over the one envelope buffer, used by this library only. The
        // public accessors below copy, so nothing a caller holds shares
        // storage with the OWID or with another field of it.
        var payloadView = envelope.subarray(payloadAt, signatureAt);
        var signatureView = envelope.subarray(signatureAt);
        var unsignedView = envelope.subarray(0, signatureAt);

        var instance = {};

        Object.defineProperties(instance, {
            data: {
                enumerable: true,
                get: function () {
                    if (data === undefined) {
                        data = encodeBase64(envelope);
                    }
                    return data;
                }
            },
            version: {
                enumerable: true,
                get: function () { return version; }
            },
            domain: {
                enumerable: true,
                get: function () { return domain; }
            },
            date: {
                enumerable: true,
                get: function () { return date; }
            },
            payload: {
                enumerable: true,
                get: function () { return new Uint8Array(payloadView); }
            },
            signature: {
                enumerable: true,
                get: function () { return new Uint8Array(signatureView); }
            }
        });

        /**
         * Returns the OWID creation date as a JavaScript Date object accurate
         * to the minute.
         * @returns {Date} the creation date.
         */
        instance.dateAsJavaScriptDate = function () {
            var jsDate = new Date();
            jsDate.setTime(new Date(ioDateBase).getTime() + (date * 60 * 1000));
            return jsDate;
        };

        /**
         * Returns the payload as a string, one character per byte.
         * @returns {string} the payload.
         */
        instance.payloadAsString = function () {
            var s = "";
            for (var i = 0; i < payloadView.length; i++) {
                s += String.fromCharCode(payloadView[i]);
            }
            return s;
        };

        /**
         * Returns the payload in hexadecimal. Single digit values are not
         * padded with a leading zero.
         * @returns {string} the payload in hexadecimal.
         */
        instance.payloadAsPrintable = function () {
            // Two characters per byte, so a byte below 0x10 keeps its
            // leading zero and the text can be read back to the same bytes.
            // The other implementations print the same way, so the same
            // payload prints the same everywhere.
            var s = "";
            for (var i = 0; i < payloadView.length; i++) {
                var hex = (payloadView[i] & 0xFF).toString(16);
                s += hex.length === 1 ? "0" + hex : hex;
            }
            return s;
        };

        /**
         * Returns the payload as a base 64 string.
         * @returns {string} the payload as base 64.
         */
        instance.payloadAsBase64 = function () {
            return encodeBase64(payloadView);
        };

        /**
         * Verifies this OWID, optionally together with other OWIDs that the
         * same signature covered. Where the runtime provides Web Crypto the
         * creator's public key is fetched and the signature checked here, and
         * where it does not the creator's verify end point is asked instead.
         * @param {(Object|Object[]|string|string[])} [others] - other OWIDs
         * covered by the signature, in the order they were signed.
         * @returns {Promise} resolves to true when the signature is genuine
         * and false when it is not, and rejects when the question could not be
         * answered.
         */
        instance.verify = function (others) {
            return asBoolean(instance.checkSignature(others));
        };

        /**
         * Verifies this OWID and reports the outcome as a named status, so
         * that "could not check" stays apart from "does not match".
         * @param {(Object|Object[]|string|string[])} [others] - other OWIDs
         * covered by the signature, in the order they were signed.
         * @returns {Promise} resolves to a frozen result carrying ok, status
         * and, where the check could not be completed, a message and a cause.
         */
        instance.checkSignature = function (others) {
            return Promise.resolve().then(function () {
                var extra = othersAsBytes(others);
                return hasSubtle()
                    ? verifyWithCreatorKey(instance, unsignedView, extra)
                    : verifyWithCreatorApi(instance, extra);
            }).catch(asSignatureResult);
        };

        /**
         * Verifies this OWID offline against a caller supplied SPKI public key
         * PEM, contacting no network end point.
         * @param {string} publicPem - the creator public key in SPKI PEM form.
         * @param {(Object|Object[]|string|string[])} [others] - other OWIDs
         * covered by the signature, in the order they were signed.
         * @returns {Promise} resolves to true when the signature is genuine
         * and false when it is not, and rejects when the question could not be
         * answered.
         */
        instance.verifyWithPublicKey = function (publicPem, others) {
            return asBoolean(
                instance.checkSignatureWithPublicKey(publicPem, others));
        };

        /**
         * Verifies this OWID offline against a caller supplied SPKI public key
         * PEM and reports the outcome as a named status.
         * @param {string} publicPem - the creator public key in SPKI PEM form.
         * @param {(Object|Object[]|string|string[])} [others] - other OWIDs
         * covered by the signature, in the order they were signed.
         * @returns {Promise} resolves to a frozen result carrying ok, status
         * and, where the check could not be completed, a message and a cause.
         */
        instance.checkSignatureWithPublicKey = function (publicPem, others) {
            return Promise.resolve().then(function () {
                var extra = othersAsBytes(others);
                var subtle = getSubtle();
                return importSpkiKey(subtle, publicPem).then(function (key) {
                    return checkSignature(
                        subtle, key, signatureView, unsignedView, extra);
                }, function (e) {
                    throw failure(
                        SignatureStatus.INVALID_KEY,
                        "the public key could not be imported",
                        e);
                });
            }).catch(asSignatureResult);
        };

        Object.freeze(instance);
        instances.set(instance, envelope);
        return instance;
    }

    //#endregion

    //#region private verification

    /**
     * A verification that could not be completed, carried through the promise
     * chain so that the status survives to the caller.
     * @param {string} status - the SignatureStatus.
     * @param {string} message - what went wrong, never containing the input.
     * @param {*} [cause] - the original failure, so that a caller of verify
     * sees what it would have seen before.
     * @returns {Object} the carrier.
     */
    function failure(status, message, cause) {
        return {
            isOwidVerificationFailure: true,
            status: status,
            message: message,
            cause: cause
        };
    }

    /**
     * Turns whatever came out of a verification into a result. Anything that
     * is not one of this library's own carriers is a failure of the check
     * rather than a judgement on the signature, so it never becomes
     * SIGNATURE_INVALID.
     * @param {*} e - the value the chain rejected with.
     * @returns {Object} the result.
     */
    function asSignatureResult(e) {
        if (e && e.isOwidVerificationFailure === true) {
            return Object.freeze({
                ok: false,
                status: e.status,
                message: e.message,
                cause: e.cause
            });
        }
        return Object.freeze({
            ok: false,
            status: SignatureStatus.VERIFICATION_ERROR,
            message: "the signature could not be checked",
            cause: e
        });
    }

    /**
     * Reduces a detailed verification to the boolean the plain verify methods
     * promise. Only the two statuses that judge the signature resolve and
     * everything else rejects, because a caller told false would treat an
     * outage as a forgery.
     * @param {Promise} detailed - the detailed verification.
     * @returns {Promise} resolves to true or false, or rejects.
     */
    function asBoolean(detailed) {
        return detailed.then(function (r) {
            if (r.status === SignatureStatus.SIGNATURE_VALID) {
                return true;
            }
            if (r.status === SignatureStatus.SIGNATURE_INVALID) {
                return false;
            }
            throw r.cause !== undefined ? r.cause : r.message;
        });
    }

    /**
     * The Web Crypto SubtleCrypto implementation, in a way that works both in
     * the browser and in Node, where it is on globalThis.crypto.
     * @returns {Object} the implementation, or undefined when there is none.
     */
    function findSubtle() {
        var c = (typeof globalThis !== "undefined" && globalThis.crypto)
            ? globalThis.crypto
            : (typeof window !== "undefined" ? window.crypto : undefined);
        return c ? c.subtle : undefined;
    }

    /**
     * True when this runtime provides Web Crypto, which decides whether a
     * signature is checked here or by the creator's verify end point.
     * @returns {boolean} whether crypto.subtle is available.
     */
    function hasSubtle() {
        return !!findSubtle();
    }

    /**
     * The Web Crypto SubtleCrypto implementation, refusing the verification
     * when the runtime has none.
     * @returns {Object} the implementation.
     */
    function getSubtle() {
        var subtle = findSubtle();
        if (!subtle) {
            throw failure(
                SignatureStatus.VERIFICATION_ERROR,
                "Web Crypto (crypto.subtle) is not available in this " +
                "environment");
        }
        return subtle;
    }

    /**
     * Imports an SPKI public key PEM.
     * @param {Object} subtle - the SubtleCrypto implementation.
     * @param {string} pem - the key in SPKI PEM form.
     * @returns {Promise} resolves to the imported key.
     */
    function importSpkiKey(subtle, pem) {
        if (typeof pem !== "string") {
            throw failure(
                SignatureStatus.INVALID_KEY,
                "public key PEM must be a string",
                "public key PEM contains no key data");
        }
        var lines = pem.split('\n');
        var contents = '';
        for (var i = 0; i < lines.length; i++) {
            var line = lines[i].trim();
            if (line.length > 0 && line.indexOf('-----') < 0) {
                contents += line;
            }
        }
        // Guard against an empty or header only PEM, where there is no key
        // data to decode. Without this the decode below yields an empty array
        // and importKey rejects with an opaque DOMException.
        if (!contents) {
            throw failure(
                SignatureStatus.INVALID_KEY,
                "public key PEM contains no key data",
                "public key PEM contains no key data");
        }
        var decoded = decodeBase64(contents);
        if (decoded.status !== undefined) {
            throw failure(
                SignatureStatus.INVALID_KEY,
                "public key PEM is not valid base 64",
                "public key PEM contains no key data");
        }
        return subtle.importKey(
            "spki", decoded.bytes, ECDSA, false, ["verify"]);
    }

    /**
     * Checks a signature over the OWID's own bytes followed by the bytes of
     * any other OWIDs the same signature covered.
     * @param {Object} subtle - the SubtleCrypto implementation.
     * @param {Object} key - the imported public key.
     * @param {Uint8Array} signature - the signature bytes.
     * @param {Uint8Array} unsigned - this OWID without its signature.
     * @param {Uint8Array[]} extra - the other OWIDs' complete bytes.
     * @returns {Promise} resolves to a result.
     */
    function checkSignature(subtle, key, signature, unsigned, extra) {
        var total = unsigned.length;
        extra.forEach(function (p) { total += p.length; });
        var message = new Uint8Array(total);
        message.set(unsigned);
        var offset = unsigned.length;
        extra.forEach(function (p) {
            message.set(p, offset);
            offset += p.length;
        });
        return subtle.verify(ECDSA, key, signature, message).then(
            function (valid) {
                return Object.freeze({
                    ok: valid === true,
                    status: valid === true
                        ? SignatureStatus.SIGNATURE_VALID
                        : SignatureStatus.SIGNATURE_INVALID
                });
            },
            function (e) {
                throw failure(
                    SignatureStatus.VERIFICATION_ERROR,
                    "the cryptographic provider could not check the signature",
                    e);
            });
    }

    /**
     * Builds the URL of one of the creator's end points for the OWID being
     * verified. The version in the path is the OWID's own version byte,
     * because a creator serves each version of the format at its own path
     * and only the end point that understands the version an OWID was
     * written in can answer for it. Both the key request and the fall back
     * verify request are built here so the two cannot name different
     * versions of the same creator.
     * @param {Object} instance - the OWID being verified.
     * @param {string} method - the end point, "creator" or "verify".
     * @returns {string} the URL, with no query string.
     */
    function creatorApiUrl(instance, method) {
        return "//" + instance.domain +
            "/owid/api/v" + instance.version + "/" + method;
    }

    /**
     * Fetches the creator's public key and checks the signature here. The key
     * is requested for the OWID's own creation date, so OWIDs signed before a
     * key rotation still verify.
     * @param {Object} instance - the OWID being verified.
     * @param {Uint8Array} unsigned - the OWID without its signature.
     * @param {Uint8Array[]} extra - the other OWIDs' complete bytes.
     * @returns {Promise} resolves to a result.
     */
    function verifyWithCreatorKey(instance, unsigned, extra) {
        var subtle = getSubtle();
        var url = creatorApiUrl(instance, "creator");
        if (instance.date != null) {
            url += "?date=" + instance.date;
        }
        // A redirect is never followed. fetch follows one by default, to
        // any other origin, so a creator whose domain answered 302 to
        // some other place would have that other place's key trusted
        // as its own, and a network attacker able to bend the creator's
        // DNS, or a creator that was simply misconfigured, could put a
        // key there and have forgeries verify. It would also carry
        // owid.fetchHeaders, a publisher's credential, to wherever the
        // redirect pointed. With manual the browser hands back an opaque
        // redirect that is not ok, which reads below as the key being
        // unavailable, which it is.
        return fetch(url, {
            mode: "cors",
            cache: "default",
            redirect: "manual",
            headers: owid.fetchHeaders
        }).then(function (r) {
            if (r.ok) {
                return r.json().then(undefined, function (e) {
                    throw failure(
                        SignatureStatus.VERIFICATION_ERROR,
                        "the creator response is not valid JSON",
                        e);
                });
            }
            return r.text().then(function (text) {
                throw failure(
                    SignatureStatus.KEY_UNAVAILABLE,
                    "'Creator' request HTTP status code: " + r.status,
                    "'Creator' request HTTP status code: " + r.status +
                    ". Response: " + text);
            });
        }, function (e) {
            throw failure(
                SignatureStatus.KEY_UNAVAILABLE,
                "the creator key could not be fetched",
                e);
        }).then(function (c) {
            if (!c || typeof c.publicKeySPKI !== "string") {
                throw failure(
                    SignatureStatus.VERIFICATION_ERROR,
                    "the creator response carries no public key",
                    "public key PEM contains no key data");
            }
            return importSpkiKey(subtle, c.publicKeySPKI).then(
                undefined,
                function (e) {
                    throw failure(
                        SignatureStatus.INVALID_KEY,
                        "the public key could not be imported",
                        e);
                });
        }).then(function (key) {
            return checkSignature(
                subtle, key, instance.signature, unsigned, extra);
        });
    }

    /**
     * Asks the creator's verify end point, which is the route taken when the
     * runtime provides no Web Crypto.
     * @param {Object} instance - the OWID being verified.
     * @param {Uint8Array[]} extra - the other OWIDs' complete bytes.
     * @returns {Promise} resolves to a result.
     */
    function verifyWithCreatorApi(instance, extra) {
        var total = 0;
        extra.forEach(function (p) { total += p.length; });
        var joined = new Uint8Array(total);
        var offset = 0;
        extra.forEach(function (p) {
            joined.set(p, offset);
            offset += p.length;
        });
        var body = new URLSearchParams();
        body.append("parent", encodeBase64(joined));
        body.append("owid", instance.data);
        var url = creatorApiUrl(instance, "verify");
        // Not followed either, for the same reasons as the creator
        // request, and because a redirected POST would resend the
        // identifier and the credential to wherever it pointed.
        return fetch(url, {
            method: "POST",
            mode: "cors",
            cache: "no-cache",
            redirect: "manual",
            headers: owid.fetchHeaders,
            body: body
        }).then(function (r) {
            if (r.ok) {
                return r.json().then(undefined, function (e) {
                    throw failure(
                        SignatureStatus.VERIFICATION_ERROR,
                        "the verify response is not valid JSON",
                        e);
                });
            }
            return r.text().then(function (text) {
                throw failure(
                    SignatureStatus.VERIFICATION_ERROR,
                    "'Verify' request HTTP status code: " + r.status,
                    "'Verify' request HTTP status code: " + r.status +
                    ". Response: " + text);
            });
        }, function (e) {
            throw failure(
                SignatureStatus.VERIFICATION_ERROR,
                "the verify end point could not be reached",
                e);
        }).then(function (r) {
            // A response that carries no judgement is a creator answering
            // something other than the question, which leaves the signature
            // unjudged. Reading a missing field as false would report an end
            // point fault as a forgery.
            if (!r || typeof r.valid !== "boolean") {
                throw failure(
                    SignatureStatus.VERIFICATION_ERROR,
                    "the verify response carries no judgement");
            }
            return Object.freeze({
                ok: r.valid,
                status: r.valid
                    ? SignatureStatus.SIGNATURE_VALID
                    : SignatureStatus.SIGNATURE_INVALID
            });
        });
    }

    //#endregion

    //#region private other OWIDs

    /**
     * Turns whatever a caller passed as the other OWIDs covered by a signature
     * into their complete bytes, in the order given. Only base 64 strings and
     * OWIDs this library read are accepted, because an object that merely
     * looks like an OWID has never been read from anything and carries no
     * signature of its own.
     * @param {(Object|Object[]|string|string[])} [others] - the other OWIDs.
     * @returns {Uint8Array[]} their bytes.
     */
    function othersAsBytes(others) {
        if (others === undefined || others === null) {
            return [];
        }
        return collectOthers([others], 1);
    }

    /**
     * Collects the other OWIDs from an array, tracking the depth so that a
     * reference loop cannot run away.
     * @param {Array} others - the other OWIDs.
     * @param {number} depth - the current depth.
     * @returns {Uint8Array[]} their bytes.
     */
    function collectOthers(others, depth) {
        if (depth > maxVerifyDepth) {
            throw failure(
                SignatureStatus.VERIFICATION_ERROR,
                "maximum depth reached when reading the other OWIDs, so " +
                "check that the OWIDs provided have no reference loop");
        }
        var c = [];
        others.forEach(function (o) {
            if (o === undefined || o === null) {
                return;
            }
            if (typeof o === "string") {
                c = c.concat(bytesFromString(o));
            } else if (Array.isArray(o)) {
                c = c.concat(collectOthers(o, depth + 1));
            } else if (instances.has(o)) {
                c.push(bytesOf(o));
            } else {
                throw failure(
                    SignatureStatus.VERIFICATION_ERROR,
                    "an other OWID must be a base 64 string or an OWID from " +
                    "owid.parse, and a '" + typeof o + "' was supplied");
            }
        });
        return c;
    }

    /**
     * Splits a string that may carry several base 64 OWIDs on whatever
     * separators it uses, and decodes each one.
     * @param {string} o - the base 64 string or strings.
     * @returns {Uint8Array[]} their bytes.
     */
    function bytesFromString(o) {
        if (o === "") {
            throw failure(
                SignatureStatus.VERIFICATION_ERROR,
                "OWID(s) must have a value and cannot be an empty string.");
        }
        var separators = [];
        for (var i = 0; i < o.length; i++) {
            var c = o.charAt(i);
            if (base64Characters.indexOf(c) === -1 &&
                separators.indexOf(c) === -1) {
                separators.push(c);
            }
        }
        var parts = separators.length === 0
            ? [o]
            : o.split(new RegExp(
                "[" + escapeForCharacterClass(separators) + "]", "g"));
        var r = [];
        parts.forEach(function (p) {
            if (p === "") {
                return;
            }
            var decoded = decodeBase64(p);
            if (decoded.status !== undefined) {
                throw failure(
                    SignatureStatus.VERIFICATION_ERROR,
                    "an other OWID is not valid base 64");
            }
            r.push(decoded.bytes);
        });
        return r;
    }

    /**
     * Escapes the characters that mean something inside a regular expression
     * character class. Until 30 August 2026 every separator was escaped with a
     * backslash on a condition that could never be false, so the list of
     * characters the escaping was meant to choose between had no effect.
     * @param {string[]} characters - the separator characters.
     * @returns {string} the body of a character class.
     */
    function escapeForCharacterClass(characters) {
        return characters.map(function (c) {
            return "^]\\-".indexOf(c) === -1 ? c : "\\" + c;
        }).join("");
    }

    /**
     * The complete bytes of an OWID this library read.
     * @param {Object} instance - the OWID.
     * @returns {Uint8Array} its bytes.
     */
    function bytesOf(instance) {
        return instances.get(instance);
    }

    //#endregion

    //#region the module

    /**
     * The OWID namespace. Calling it, with or without new, is refused, because
     * an OWID is obtained by reading one. This function exists only to carry
     * the module's operations and to say so to code written against the
     * constructor it replaces.
     */
    function owid() {
        throw "an OWID cannot be constructed. Use owid.parse to read one " +
        "from base 64, or owid.parseBytes to read one from a byte array";
    }

    /**
     * Why a read succeeded or failed. Frozen, and compared by value rather
     * than by the text of any message.
     */
    owid.ParseStatus = ParseStatus;

    /**
     * The outcome of asking whether a signature is genuine. Frozen.
     */
    owid.SignatureStatus = SignatureStatus;

    /**
     * Reads a complete OWID from its base 64 form.
     *
     * The value may be anything at all, because this is external data and
     * failing to be an OWID is an ordinary outcome rather than an error.
     * Nothing is thrown, which is deliberately unlike JSON.parse, and no key
     * is fetched and no signature is checked. A successful parse says the
     * bytes are a structurally valid OWID, which is a different question from
     * whether its signature is genuine.
     *
     * @param {string} value - the OWID as base 64.
     * @returns {Object} a frozen result with ok, owid and status. On success
     * ok is true, owid is the OWID and status is ParseStatus.PARSED. On
     * failure ok is false, owid is null and status names the reason, with the
     * numbers that disagreed alongside it where there are any.
     */
    owid.parse = function (value) {
        return parseBase64(value);
    };

    /**
     * Parses a complete OWID from a buffer holding exactly one. Data after
     * the envelope is refused, because on this surface there is nothing else
     * it could belong to. Where the buffer holds several OWIDs one after
     * another, use parseFrame.
     * @param {Uint8Array} buffer - the OWID bytes.
     * @returns {Object} a frozen result with ok, owid and status.
     */
    owid.parseBytes = function (buffer) {
        return parseBytes(buffer);
    };

    /**
     * Parses one OWID out of a buffer that may hold several, one after
     * another, starting at the offset given.
     *
     * Unlike parseBytes this does not require the envelope to be the last
     * thing in the buffer, because what follows it may be the next envelope
     * rather than rubbish. What it requires is that the declared payload and
     * the signature are both there, and it says nothing at all about the
     * bytes after them. That one comparison is the whole difference between
     * the two surfaces.
     *
     * The result carries bytesRead, being the number of bytes the envelope
     * occupied, so a caller can move on to the next one. A parse that failed
     * took nothing, so bytesRead is zero and the caller's position does not
     * move. Reaching the end of the buffer is MISSING_INPUT, which is what
     * ends a loop:
     *
     *     var at = 0;
     *     for (;;) {
     *         var r = owid.parseFrame(bytes, at);
     *         if (!r.ok) { break; }
     *         use(r.owid);
     *         at += r.bytesRead;
     *     }
     *
     * @param {Uint8Array} buffer - the buffer, which may hold several OWIDs.
     * @param {number} [at] - where the envelope starts, 0 by default.
     * @returns {Object} a frozen result with ok, owid, status and bytesRead.
     */
    owid.parseFrame = function (buffer, at) {
        return parseFrame(buffer, at);
    };

    /**
     * True when the value is an OWID this library read. An object that merely
     * carries the same field names is not one, because its fields have never
     * been read from anything.
     * @param {*} value - the value to test.
     * @returns {boolean} whether it is an OWID.
     */
    owid.isOwid = function (value) {
        return typeof value === "object" && value !== null &&
            instances.has(value);
    };

    /**
     * Verifies each of the OWIDs supplied in its own right, which is what an
     * empty instance used to be created for.
     * @param {(Object|Object[]|string|string[])} owids - the OWIDs, as base 64
     * strings or as OWIDs from parse.
     * @returns {Promise} resolves to true when every one of them is genuine.
     */
    owid.verify = function (owids) {
        return Promise.resolve().then(function () {
            var list = asOwidList(owids, 1);
            if (list.length === 0) {
                throw "OWID(s) must have a value and cannot be an empty " +
                "string.";
            }
            return Promise.all(list.map(function (o) {
                return o.verify();
            })).then(function (r) {
                return r.every(function (v) { return v; });
            });
        }).catch(function (e) {
            // The reading helpers share their refusals with verification, so
            // a refusal arrives as one of the carriers used there. A caller
            // of this method sees a message, as it did before.
            throw (e && e.isOwidVerificationFailure === true) ? e.message : e;
        });
    };

    /**
     * Turns whatever a caller passed into OWIDs, reading any base 64 strings.
     * @param {(Object|Object[]|string|string[])} owids - the OWIDs.
     * @param {number} depth - the current depth.
     * @returns {Object[]} the OWIDs.
     */
    function asOwidList(owids, depth) {
        if (depth > maxVerifyDepth) {
            throw "Maximum depth reached when reading OWIDs, so check that " +
            "the OWIDs provided have no reference loop.";
        }
        if (owids === undefined || owids === null) {
            return [];
        }
        if (Array.isArray(owids)) {
            var c = [];
            owids.forEach(function (o) {
                c = c.concat(asOwidList(o, depth + 1));
            });
            return c;
        }
        if (instances.has(owids)) {
            return [owids];
        }
        if (typeof owids === "string") {
            if (owids === "") {
                throw "OWID(s) must have a value and cannot be an empty " +
                "string.";
            }
            var r = [];
            bytesFromString(owids).forEach(function (b) {
                var read = parseBytes(b);
                if (!read.ok) {
                    throw "an OWID could not be read: " + read.status;
                }
                r.push(read.owid);
            });
            return r;
        }
        throw "an OWID must be a base 64 string or an OWID from " +
        "owid.parse, and a '" + typeof owids + "' was supplied";
    }

    /**
     * Stops an advert. Posts the organization domain and the return URL to the
     * /stop end point and then redirects the browser to the URL contained in
     * the response.
     * @param {string} d - organization domain to stop.
     * @param {string} r - return url to come back to once stopped.
     * @returns {Promise} resolves once the redirect has been started.
     */
    owid.stopAdvert = function (d, r) {
        var data = new URLSearchParams();
        data.append("host", d);
        data.append("returnUrl", r);
        return fetch("/stop", {
            method: "POST",
            mode: "cors",
            cache: "no-cache",
            body: data
        }).then(function (response) {
            if (response.ok) {
                return response.text();
            }
            return response.text().then(function (text) {
                throw "'Stop' request HTTP status code: " + response.status +
                ". Response: " + text;
            });
        }).then(function (m) {
            console.log(m);
            window.location.href = m;
        }).catch(function (x) {
            console.log(x);
        });
    };

    /**
     * Optional HTTP headers sent with the creator request that fetches the
     * public key. Servers MAY require a credential, for example
     * { "X-Api-Key": "<key>" }. The headers go to every creator domain a
     * verification touches, so only set a credential that all the creators in
     * the tree are meant to see.
     */
    owid.fetchHeaders = undefined;

    return owid;

    //#endregion
})();

try {
    module.exports = owid;
} catch (e) { }
