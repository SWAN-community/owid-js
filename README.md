![Open Web Id](https://github.com/SWAN-community/owid/raw/main/images/owl.128.pxls.100.dpi.png)

# Open Web Id (OWID) JavaScript

Open Web Id (OWID) - a open source cryptographically secure shared web identifier 
schema implemented in JavaScript

Read the [OWID](https://github.com/SWAN-community/owid) project to learn more about
the concepts before looking into this reference implementation.

## Usage

To use OWID.js:

* Add the `owid.js` file to your CDN or web application.
* reference owid.js:
    ```
    <script src="https://<host>/owid.js" type="text/javascript"></script>
    ```
* call the library:
    ```
    var valid = new owid("owid base 64 string").verify();
    ```

## Tests

Tests are performed using Jest.

Install yarn,

```
npm install --global yarn
```

Install Jest.

```
yarn install
```

Run tests.

```
yarn test
```