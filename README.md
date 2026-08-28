![Open Web Id](https://github.com/SWAN-community/owid/raw/main/images/owl.128.pxls.100.dpi.png)

# Open Web Id (OWID) JavaScript

## Overview

Open Web Id (OWID) is an open source cryptographically secure shared web
identifier schema. This repository implements OWID in JavaScript.

Read the [OWID](https://github.com/SWAN-community/owid) project to learn more
about the concepts before looking into this implementation.

## Scope of this implementation

This library is verify only and is intended for use in the browser. It parses
OWIDs that were created elsewhere and verifies their signatures. It cannot
create or sign OWIDs. Creation and signing are performed by the server side
implementations.

When the browser provides `crypto.subtle` the library fetches the creator's
public key from their well known end point and verifies the ECDSA signature
locally. When `crypto.subtle` is not available it falls back to the creator's
remote verify end point.

The public key is requested for the OWID's own creation date
(`?date=<minutes>`), so OWIDs signed before a signing-key rotation still
verify. A creator that does not support the `date` parameter ignores it and
returns its current key.

Servers MAY require a credential on the creator end point. Supply the
required headers via `owid.fetchHeaders` before verifying:

```js
owid.fetchHeaders = { "X-Api-Key": "your key" };
```

The headers are sent to every creator domain that a verification touches,
so only set a credential that all the creators in the tree are meant to
see.

## Payload size and application limits

The OWID wire format stores the payload length as an unsigned 32 bit value,
so a payload from zero through 4,294,967,295 bytes is structurally valid. The
format defines no smaller payload limit. The null-terminated domain has no
separate encoded maximum, so the protocol alone is not an application input
limit for the complete envelope.

This library validates that the declared payload length agrees with the bytes
present before it takes a view of the payload. A large declaration without
the corresponding bytes is malformed and is rejected without allocating the
declared size. A matching large payload is not malformed merely because it is
large, and parsing work and memory use scale with the bytes actually present.

The in-memory APIs remain subject to the browser's typed-array, string,
address-space and available-memory limits. Applications accepting untrusted
OWIDs must choose limits suitable for their use case and enforce them before
buffering or Base64-decoding the input. An implementation capacity failure or
an application policy rejection is distinct from an invalid OWID.

For transport input, limit the complete HTTP body or encoded envelope; allow
for the domain and other OWID fields as well as the payload. After parsing,
`instance.owid.payload.length` reports the actual payload size without
another copy and can be used for downstream policy. The parser cannot choose
either limit on behalf of the application.

## Usage

To use OWID-js:

* Add the `owid.js` file to your CDN or web application.
* reference owid.js:
    ```html
    <script src="https://<host>/owid.js" type="text/javascript"></script>
    ```
* call the library:
    ```js
    var o = new owid("[owid base 64 string]");
    o.verify().then(valid  => console.log(valid));
    ```

## Interface

OWID-js library is used to construct owid objects and verify against other
instances of OWID or base 64 encoded strings representing OWID trees.

### Constructor

Create a new instance of OWID without any data. The instance can still be used
to verify other OWIDs.
```js
var o = new owid();
```

Create a new instance of OWID using a base 64 encoded OWID.
```js
var o = new owid("<base 64 encoded OWID>");
```

### Methods

Methods available to call on an instance of OWID.

|Method|Params|Return Type|Description|
|-|-|-|-|
|dateAsJavaScriptDate|n/a|Date|Returns the OWID creation date as a JavaScript Date object.|
|parse|base 64 string (optional)|Object|Parses a base 64 encoded OWID into an OWID tree. Uses the instance's own data when no parameter is provided.|
|payloadAsPrintable|n/a|string|Returns the payload in hexadecimal.|
|payloadAsString|n/a|string|Returns the payload as a string.|
|payloadAsBase64|n/a|string|Returns the payload as a base 64 string.|
|stop|owid, domain, return url|n/a|Posts the domain and return URL to the `/stop` end point and redirects the browser to the URL contained in the response.|
|verify|owid\|owids[]|Promise(bool)|The verify method determines if the OWID instance is valid. It also takes an array of other OWID instances or strings that can be turned into OWIDs to verify the current OWID against.|

### Fields

|Field|Type|Description|
|-|-|-|
|data|string|Returns the base 64 string the instance was created from.|
|date|number|Returns the date and time the OWID was created in UTC as minutes since `2020-01-01 00:00`|
|domain|string|Returns the creator of the OWID.|
|owid|Object|Returns the parsed OWID tree.|
|signature|Uint8Array|Returns the signature as byte array.|

## Examples

Verify an OWID.

```js
var o = new owid("[signed OWID]");
 
console.log(o.payloadAsString()); // Returns the payload as a string.
console.log(o.payloadAsPrintable()); // Returns the payload as a hexadecimal.
console.log(o.payloadAsBase64()); // Returns the payload as a base 64 string.
console.log(o.domain); // Returns the creator of the OWID.
console.log(o.date); // Returns the date and time the OWID was created in UTC as minutes since `2020-01-01 00:00`.
console.log(o.signature); // Returns the signature as byte array.

o.verify()
    .then(valid  => console.log(valid)) // Uses a promise to determine if the OWID is valid.
    .catch(error => console.log(error));
```

Verify one OWID that was signed with another OWID.

```js
var o = new owid("[signed OWID]");

var other = new owid("[other signed OWID]");

o.verify(other)
    .then(valid => console.log(valid))
    .catch(error => console.log(error)); 
```

Verify one OWID with multiple OWID base 64 strings.

```js
var o = new owid("[signed OWID]");

o.verify(["[signed OWID 1]", "[signed OWID 2]", "[signed OWID 3]"])
    .then(valid => console.log(valid))
    .catch(error => console.log(error));
```

Verify one OWID with multiple other OWID instances.

```js
var o = new owid("[signed OWID]");

var other1 = new owid("[signed OWID 1]");
var other2 = new owid("[signed OWID 2]");
var other3 = new owid("[signed OWID 3]");

o.verify([other1, other2, other3])
    .then(valid => console.log(valid))
    .catch(error => console.log(error));
```

## Testing

Tests are performed using Jest. The fetch calls made by the library are
mocked with jest-fetch-mock. The tests in `owid.test.js` cover parsing and
the remote verify end point. The tests in `owid.crypto.test.js` cover local
ECDSA signature verification using the web crypto implementation provided by
Node. The tests in `owid.interop.test.js` verify externally signed fixtures
to prove signature compatibility.

### Pre-requisites

* Node.js version 15 or above. The tests are routinely run with Node.js 24.
* Yarn or npm. The repository includes a `yarn.lock` file, so Yarn is
  preferred.

### Steps

Install yarn if it is not already available.

```bash
npm install --global yarn
```

Install the dependencies.

```bash
yarn install
```

Run the tests.

```bash
yarn test
```

Alternatively use npm.

```bash
npm install
npm test
```

## License

This project is licensed under the Apache License, Version 2.0. See the
[LICENSE](LICENSE) file for details.
