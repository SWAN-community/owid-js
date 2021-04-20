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

const owid = require('./v1');
const { subtle } = require('crypto').webcrypto;

Object.defineProperty(global.self, 'crypto', {
  value: {
    //subtle: subtle
  }
});

const testCreatorOWID = 
    "AjUxZGIudWsAKyQKAFUBAAABAWhlYWRpbmcAcG9wLXVwLnN3YW4tZGVtby51awAQAAAA27eO" +
    "AAPSTXmKZT79iWgRagI1MWRhLnVrACskCgAQAAAAs1WelonmS0KoK6uiN3rz1rAxJHj2rNKv" +
    "V/9OMOyFlWHY/tbwpdVupNG62p3pCWCuzgV2YMEth3coZhFSZHXJ1mO/U/bkHhGCSG/BStI/" +
    "fJcCNTFkYi51awArJAoAFAAAAO/c7j2xwwF8GN4hOXBIb/auLhy7mftegVZqvbepqw8nVf8B" +
    "yI94w9I/XLNwf5kAFpFeSeo8kwRhXqUyUuWT7FYIi4DnOP9zyTaAY8xgMh77oUjL/QJjbXAu" +
    "c3dhbi1kZW1vLnVrACskCgACAAAAb25Lyrbl9PDGs6VAMqgozsfxCqsVWX6pf2JyFim3zg6l" +
    "LivRDqpCD921elvxdn85/vK0msyTOMjE8buKAza/H2zBAEqEMbMuIoZL8Ji4m4ScYkpQvD3K" +
    "jsLbqI5c7+Ra/Ju43vBMp2st7QLHD4sxwPugeSBEgQRkevAm0H1a3jekMEA";

const testSupplierOWID = 
    "AnBvcC11cC5zd2FuLWRlbW8udWsAKyQKAAIAAAABA6Ljm9cxZfnmwRMjv4MQ0PrAjf8y29Ru" +
    "0sjZG5R+mkjBtQD9J02xZQIk5czsKJzOl6IkOPvbPSGakxyq0HPLX+w";

const testBadOWID = 
    "AmJhZHNzcC5zd2FuLWRlbW8udWsAKyQKAAIAAAABAxu+OOtismihze3LlcNuvT2WXNTGSio" +
    "gw36t85HLwL6YdV4i9kYDCdsP54RS8on/roKKASyh19TpcUQxkIRALFk";

beforeEach(() => {
    // fetchMock.doMock();

    // fetchMock.dontMock();

    fetchMock.mockResponse(req => {
        var urlString = req.url;
        if (urlString.startsWith("//")) {
            urlString = "http:" + urlString;
        }
        var url = new URL(urlString);

        if (url.pathname.endsWith("/verify")) {
            if (url.searchParams.get('owid') == testBadOWID) {
                return Promise.resolve(JSON.stringify({valid: false}));
            } else if (url.searchParams.get('owid') == null || url.searchParams.get('owid') == "") {
                return Promise.resolve({
                    status: 400,
                    body: "Not Found"
                  });
            } else {
                return Promise.resolve(JSON.stringify({valid: true}));
            }
        } else {
          return  Promise.resolve({
            status: 404,
            body: "Not Found"
          });
        }
    });
    
});

test('verify OWID', () => {
    var o = new owid(testCreatorOWID);

    return o.verify().then(result => {
        expect(result).toBe(true);
    });
});

test('verify other OWIDs - string', () => {
    var o = new owid();

    return o.verify(testCreatorOWID).then(result => {
        expect(result).toBe(true);
    });
});

test.each([
    [",", true],
    ["@", true],
    ["#", true],
    ["$", true],
    ["*", true],
    ["^", true],
    ["|", true],
    [".", true],
])('verify other OWIDs - string separator %s', (separator, expected) => {
    var o = new owid();

    var owids = [testCreatorOWID, testCreatorOWID, testCreatorOWID].join(separator);

    return o.verify(owids).then(result => {
        expect(result).toBe(expected);
    });
});

test('verify other OWIDs - object', () => {
    var o = new owid();
    var other = new owid(testCreatorOWID)

    return o.verify(other).then(result => {
        expect(result).toBe(true);
    });
});

test('verify other OWIDs - array string', () => {
    var o = new owid();

    return o.verify([testCreatorOWID]).then(result => {
        expect(result).toBe(true);
    });
});

test('verify other OWIDs - array object', () => {
    var o = new owid();
    var other = new owid(testCreatorOWID)

    return o.verify([other]).then(result => {
        expect(result).toBe(true);
    });
});

test('verify other OWIDs - array mixed', () => {
    var o = new owid();
    var other = new owid(testCreatorOWID);

    return o.verify([other, testCreatorOWID]).then(result => {
        expect(result).toBe(true);
    });
});

test('test owid properties', () => {
    var o = new owid(testCreatorOWID);

    // Returns the payload as a string
    console.log(o.payloadAsString()); 
    expect(o.payloadAsString()).toBeDefined();

    // Returns the payload as a string
    console.log(o.payloadAsPrintable()); 
    expect(o.payloadAsPrintable()).toBeDefined();

    // Returns the payload as a base 64 array
    console.log(o.payloadAsBase64()); 
    expect(o.payloadAsBase64()).toBeDefined();

    // Returns the creator of the OWID
    console.log(o.domain); 
    expect(o.domain).toBeDefined();

    // Returns the date and time the OWID was created in UTC
    console.log(o.date); 
    expect(o.date).toBeDefined();

    // Returns the signature as byte array
    console.log(o.signature); 
    expect(o.signature).toBeDefined();

    // Uses a promise to determine if the OWID is valid.
    return o.verify().then(valid => {
        console.log(valid);
        expect(valid).toBe(true);
    }); 
});

// The verify method takes an array of others OWID instances, strings that can 
// be turned into OWIDs. There are used in the order they were received to form 
// the byte array that is used to verify the OWID. For example;
test('verify supplier\'s OWID', () => {
    var offerId = new owid(testCreatorOWID);
    var supplier = new owid(testSupplierOWID);

    return supplier.verify(offerId).then(valid => {
        expect(valid).toBe(true);
    }); // Verifies the supplier’s OWID that was created with the Offer ID.
});

test('verify bad actor\'s OWID', () => {
    var offerId = new owid(testCreatorOWID);
    var supplier = new owid(testBadOWID);

    return supplier.verify(offerId).then(valid => {
        expect(valid).toBe(false);
    }); // Verifies the supplier’s OWID that was created with the Offer ID.
});

test ('verify empty string throws error', () => {
    var o = new owid("");

    expect(() => o.verify()).toThrow();
    expect(() => o.verify()).toThrow("OWID must have a value and cannot be an empty string.");
});

test ('verify empty string throws error', () => {
    var o = new owid();

    expect(() => o.verify("")).toThrow();
    expect(() => o.verify("")).toThrow("OWID(s) must have a value and cannot be an empty string.");
});

test ('verify empty string throws error', () => {
    var o = new owid(testCreatorOWID);

    expect(() => o.verify("")).toThrow();
    expect(() => o.verify("")).toThrow("OWID(s) must have a value and cannot be an empty string.");
});