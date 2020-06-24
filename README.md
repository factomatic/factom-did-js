# factom-did

`factom-did` is a JavaScript library for working with DIDs on the Factom blockchain. It is an implementation
of the [Factom DID method
specification](https://github.com/bi-foundation/FIS/blob/feature/DID/FIS/DID.md)

The library enables:

* creation of a new DID
* addition of management key(s) for the DID
* addition of DID key(s) for the DID
* addition of service(s) for the DID
* export of public metadata to be recorded on Factom
* update of an existing DID: adding/revoking management keys, DID keys and services and producing a signed DID
update entry
* upgrade of the method version of an existing DID
* deactivaiton of an existing DID

## Examples
You can find an example of the library workflow in the `examples/` directory.

## Installation
```
npm install factom-did
```

## Build

* Clone the repo

* Install the dependencies:
```
npm install
```

* Execute the tests:
```
npm test
```

* Execute the example:
```
node examples/example.js
```
