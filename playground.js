const {DID} = require('./src/index.js'),
  { KeyType, DIDKeyPurpose } = require('./src/enums');
const entryData = DID
  .builder()
  .managementKey('my-key-1', 0)
  .didKey('my-key-2', [DIDKeyPurpose.AuthenticationKey], KeyType.ECDSA)
  .service('my-service', 'email', 'https://emailme.com')
  .build()
  .exportEntryData();

const content = JSON.parse(entryData['content'].toString());
console.log(content['managementKey']);