const owid = require('./v1');

const { subtle } = require('crypto').webcrypto;

Object.defineProperty(global.self, 'crypto', {
  value: {
    subtle: subtle
  }
});

global.fetch = jest.fn(() =>
  Promise.resolve({
    json: () => Promise.resolve({ valid: true }),
  })
);

const testCreatorOWID = 
    "AjUxZGEudWsA2wIKAFMBAAABAWhlYWRpbmcAbmV3LXBvcmstbGltZXMudWs" +
    "AEAAAACdy1uYpIUDfig5Yf/qrTlACNTFkYS51awDs/AkAEAAAAGbRLWHGH07KoY4" +
    "R9rDekNZxOJK3rhBYW5SbGoxD3oGrrckBvqf2gJ9eAuc4egHGxGPqKrhl8mslf7X" +
    "TlkUhXDkIKj47WYaCIzN83PgrsroOAjUxZGEudWsA2wIKABQAAADv3O49scMBfBj" +
    "eITlwSG/2ri4cu0etpQdFNMgaEf1pVN2hOV6xER9k5TXGpOuBMViaRdUQcnQQK2N" +
    "6JFW2WV6JhT+mgIzVa7unKKpoLh+r/GSjgKkCY21wLnN3YW4tZGVtby51awDbAgo" +
    "AAgAAAG9uYb2MpYHagU7oE+zvLqBhyQTNVmZquLrT+ut2GBjqYWDjC7B8KZXSJy0" +
    "rM4qDs1vI1XXKEIn3SGgZUvpCy8nohADJxLC8vAN3MgbQ8rmI8Y7NF4y8DBcAW0m" +
    "9bO9bhiO+socLw/ylL9dRcvQVojB0UNtmpiRD7LgrahVbyhUE6rk5";
            
const testSupplierOWID = 
    "";

const testBadOWID = 
    "";

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

test('verify bas actor\'s OWID', () => {
    var offerId = new owid(testCreatorOWID);
    var supplier = new owid(testBadOWID);

    return supplier.verify(offerId).then(valid => {
        expect(valid).toBe(false);
    }); // Verifies the supplier’s OWID that was created with the Offer ID.
});