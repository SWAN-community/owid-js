![Open Web Id](https://github.com/SWAN-community/owid/raw/main/images/owl.128.pxls.100.dpi.png)

# Open Web Id (OWID) JavaScript

Open Web Id (OWID) - a open source cryptographically secure shared web identifier 
schema implemented in JavaScript

Read the [OWID](https://github.com/SWAN-community/owid) project to learn more about
the concepts before looking into this implementation.

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

Create a new instance of OWID without any data. The instance can still be used to 
verify other OWIDs.
```js
var o = new owid();
```

Create a new instance of OWID using a encrypted OWID.
```js
var o = new owid("<encrypted data>");
```

### Methods

Methods available to call on an instance of OWID.

|Method|Params|Return Type|Description|
|-|-|-|-|
|dateAsJavaScriptDate|n/a|Date|Returns the OWID creation date as a JavaScript Date object.|
|payloadAsString|n/a|string|Returns the payload as a string.|
|payloadAsBase64|n/a|string|Returns the payload as a base 64 string.|
|verify|owid\|owids[]|Promise(bool)|The verify method determines if the OWID instance is valid. It also takes an array of other OWID instances or strings that can be turned into OWIDs to verify the current OWID against.|

### Fields

|Field|Type|Description|
|-|-|-|
|date|number|Returns the date and time the OWID was created in UTC as minutes since `2020-01-01 00:00`|
|domain|string|Returns the creator of the OWID.|
|signature|Uint8Array|Returns the signature as byte array.|

## Examples

Verify an OWID.

```js
var o = new owid("[encrypted data]");
 
console.log(o.payloadAsString()); // Returns the payload as a string.
console.log(o.payloadAsBase64()); // Returns the payload as a base 64 string.
console.log(o.domain); // Returns the creator of the OWID.
console.log(o.date); // Returns the date and time the OWID was created in UTC as minutes since `2020-01-01 00:00`.
console.log(o.signature); // Returns the signature as byte array.

o.verify().then(valid  => console.log(valid)); // Uses a promise to determine if the OWID is valid.

```

Verify the supplier’s OWID that was created with the Offer ID.

```js
var offerId = new owid("[encrypted Offer OWID]");

var supplier = new owid("[encrypted supplier OWID]");

supplier.verify(offerId).then(valid  => console.log(valid)); 
```

## Tests

Tests are performed using Jest.

### Pre-requisites

* Nodejs version 15.x or above
* Yarn

### Steps

Install yarn,

```bash
npm install --global yarn
```

Install Jest.

```bash
yarn install
```

Run tests.

```bash
yarn test
```