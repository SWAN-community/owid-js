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

// These tests verify a real identifier issued by a live creator against that
// creator's real published signing key schedule, rather than against a key
// pair the test made up for itself. The other suites build their own OWIDs,
// so they prove the library is self consistent but they cannot prove it can
// talk to a creator that actually exists.
//
// The test data in testdata was taken on 4 September 2026 from
// cloud.51degrees.com, and the identifier names 51d.es as its creator. Both
// files are public. An identifier is meant to be handed to anyone who asks,
// and the key schedule is the set of public keys the creator publishes so
// that anyone can check a signature, so neither carries a secret and neither
// can be used to sign anything.
//
// The creator is stood in for here rather than called over the network, so
// the suite stays offline and repeatable, but the stand in behaves the way
// the real service does. It serves each version of the format at its own path
// and returns 404 for the others, and it picks the signing key by the
// creation date the request asks for. Both of those matter. Measured against
// the live service on 4 September 2026, GET /owid/api/v1/creator and
// /owid/api/v2/creator both answered 404 whilst /owid/api/v3/creator answered
// 401, meaning it exists and wants a credential.

const owid = require('./v1');
const nodeCrypto = require('crypto');
const fs = require('fs');
const path = require('path');

Object.defineProperty(global.self, 'crypto', {
    value: {
        subtle: nodeCrypto.webcrypto.subtle
    }
});

// The identifier as it was handed out, together with the facts recorded
// alongside it at the time it was taken.
const fixture = JSON.parse(fs.readFileSync(
    path.join(__dirname, 'testdata', '51did-identifier.json'), 'utf8'));

// The creator's published signing key schedule, oldest first. A key runs from
// its own start until the next key starts.
const schedule = JSON.parse(fs.readFileSync(
    path.join(__dirname, 'testdata', '51did-public-keys.json'), 'utf8'))
    .slice()
    .sort((a, b) => Date.parse(a.startsAt) - Date.parse(b.startsAt));

// The facts the fixture was recorded with. The identifier is a version 3
// OWID created on 4 September 2026 by 51d.es.
const expectedVersion = 3;
const expectedDomain = "51d.es";
const expectedDate = 3510720;

// The moment the stand in treats as now, in minutes since the OWID base
// date, being 14 September 2026, ten days after the identifier was created
// and in the week that followed. Every port's stand in uses this moment. A
// real creator answers an undated request with the key in force at the
// moment of the request, so by then that is no longer the key that signed
// this identifier.
const requestMoment = expectedDate + 10 * 24 * 60;

// The OWID base date as a millisecond timestamp, so a date in minutes can be
// compared with the start of a key's window.
const owidBase = Date.UTC(2020, 0, 1);

/**
 * Returns the key from the published schedule that was in force at the
 * creation date a creator request asks for, which is the way a real creator
 * answers the date parameter.
 * @param {number} dateInMinutes - minutes since the OWID base date.
 * @returns {Object|null} the key, or null when the date falls before the
 * schedule starts.
 */
function keyInForceAt(dateInMinutes) {
    var at = owidBase + dateInMinutes * 60000;
    var found = null;
    schedule.forEach(k => {
        if (Date.parse(k.startsAt) <= at) {
            found = k;
        }
    });
    return found;
}

/**
 * Reads an OWID that the test expects to be valid, asserting the three facts
 * a read always reports before handing back the OWID itself.
 * @param {string} data - the OWID as base 64.
 * @returns {Object} the OWID.
 */
function read(data) {
    var r = owid.parse(data);
    expect(r.ok).toBe(true);
    expect(r.status).toBe(owid.ParseStatus.PARSED);
    expect(r.owid).not.toBeNull();
    return r.owid;
}

/**
 * Stands in for the creator. Only the path naming the version given answers,
 * every other path returns the 404 the live service returns, and the key
 * handed back is the one in force at the date on the request unless the
 * stand in is asked to ignore the date. As the live service does, a request
 * naming no date is answered with the key in force at the moment of the
 * request, a date later than that moment is read as that moment, and a date
 * that is not a number is refused with a 400.
 * @param {Object} [options] - servedVersion is the only version served, and
 * ignoreDate set to true returns the key in force at requestMoment whatever
 * date is asked for, which is what a creator that ignores the date does.
 */
function mockCreator(options) {
    var servedVersion = options && options.servedVersion !== undefined
        ? options.servedVersion
        : expectedVersion;
    var ignoreDate = options && options.ignoreDate === true;
    fetchMock.mockResponse(req => {
        var urlString = req.url;
        if (urlString.startsWith("//")) {
            urlString = "https:" + urlString;
        }
        var url = new URL(urlString);
        if (url.hostname !== expectedDomain ||
            url.pathname !== "/owid/api/v" + servedVersion + "/creator") {
            return Promise.resolve({
                status: 404,
                body: "Status code: 404, method not found"
            });
        }
        var asked = url.searchParams.get("date");
        var at;
        if (ignoreDate || asked === null) {
            at = requestMoment;
        } else if (/^\d+$/.test(asked) === false) {
            return Promise.resolve({
                status: 400,
                body: "date must be the number of minutes since 2020-01-01"
            });
        } else {
            at = Math.min(Number(asked), requestMoment);
        }
        var key = keyInForceAt(at);
        if (key === null) {
            return Promise.resolve({
                status: 404,
                body: "no published key covers that date"
            });
        }
        return Promise.resolve(JSON.stringify({
            publicKeySPKI: key.publicKey
        }));
    });
}

beforeEach(() => {
    fetchMock.resetMocks();
});

test('the published identifier reads as the version 3 OWID it was ' +
    'recorded as', () => {
    var o = read(fixture.identifier);

    expect(o.version).toBe(expectedVersion);
    expect(o.domain).toBe(expectedDomain);
    expect(o.date).toBe(expectedDate);
    expect(o.signature.length).toBe(64);
});

test('the published identifier verifies against the published key schedule',
    () => {
    mockCreator();
    var o = read(fixture.identifier);

    return o.verify().then(valid => {
        expect(valid).toBe(true);
        // One request, to the end point that serves the version this
        // identifier was written in, asking for the key that was in force
        // when it was created.
        expect(fetch.mock.calls.length).toBe(1);
        expect(fetch.mock.calls[0][0]).toBe(
            "//" + o.domain + "/owid/api/v" + o.version +
            "/creator?date=" + o.date);
    });
});

test('the published identifier reports a valid signature', () => {
    mockCreator();
    var o = read(fixture.identifier);

    return o.checkSignature().then(r => {
        expect(r.ok).toBe(true);
        expect(r.status).toBe(owid.SignatureStatus.SIGNATURE_VALID);
    });
});

test('a creator that only serves an older version leaves the signature ' +
    'unjudged', () => {
    // This is the outcome the library produced against the live service for
    // as long as it asked for version 1 whatever version the OWID named.
    // Nothing was forged and nothing was wrong with the identifier, the key
    // simply could never be fetched.
    mockCreator({ servedVersion: 1 });
    var o = read(fixture.identifier);

    return o.checkSignature().then(r => {
        expect(r.ok).toBe(false);
        expect(r.status).toBe(owid.SignatureStatus.KEY_UNAVAILABLE);
    });
});

test('the key is chosen by the creation date, so the key in force in the ' +
    'following week does not verify an older identifier', () => {
    // The key that signed this identifier is not the key in force in the
    // following week, so a creator that ignored the date and handed back the
    // key in force at the moment of the request would report a genuine
    // identifier as a forgery. That is what the date parameter is for.
    var signing = keyInForceAt(expectedDate);
    expect(signing).not.toBeNull();
    expect(signing.startsAt).not.toBe(keyInForceAt(requestMoment).startsAt);

    mockCreator({ ignoreDate: true });
    var o = read(fixture.identifier);

    return o.verify().then(valid => {
        expect(valid).toBe(false);
    });
});

test('the identifier verifies offline against the published key on its own',
    () => {
    // No network at all, which proves the fixture and the published schedule
    // agree independently of how the creator URL is built.
    var o = read(fixture.identifier);

    return o.verifyWithPublicKey(keyInForceAt(o.date).publicKey)
        .then(valid => {
            expect(valid).toBe(true);
            expect(fetch.mock.calls.length).toBe(0);
        });
});
