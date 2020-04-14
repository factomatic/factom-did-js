const base58 = require('bs58'),
  { DID } = require('./src/index.js'),
  { Ed25519Key } = require('./src/keys/eddsa'),
  { KeyType, DIDKeyPurpose } = require('./src/enums'),
  { ECDSASecp256k1Key } = require('./src/keys/ecdsa'),
  { RSAKey } = require('./src/keys/rsa');

function testDID() {
  const did = DID
  .builder()
  .managementKey('my-key-1', 0)
  .didKey('my-key-2', [DIDKeyPurpose.AuthenticationKey], KeyType.ECDSA)
  .service('my-service', 'email', 'https://emailme.com')
  .build();

  // const content = JSON.parse(entryData['content'].toString());
  // console.log(content['managementKey']);
  
  const updater = DID
    .builder(did.id, [...did.managementKeys], [...did.didKeys], [...did.services])
    .update()
    .rotateManagementKey('my-key-1');
  
  console.log(updater.exportEntryData()['content'].toString());
}

function testEd25519Key() {
  const key = new Ed25519Key();
  const key2 = new Ed25519Key(key.publicKey, key.privateKey);
  const signature = key2.sign(Buffer.from('test'));
  console.log(key2.verify(Buffer.from('test'), signature));
}

function testEd25519Key2() {
  const key = new Ed25519Key();
  const key2 = new Ed25519Key(base58.decode(key.publicKey), base58.decode(key.privateKey));
  const signature = key2.sign('test');
  console.log(key2.verify('test', Buffer.from(signature)));
}

function testSecp256k1Key() {
  const key = new ECDSASecp256k1Key();
  const key2 = new ECDSASecp256k1Key(base58.decode(key.publicKey), base58.decode(key.privateKey));
  const signature = key2.sign('test');
  console.log(key2.verify('test', Buffer.from(signature)));
}

function testRSAKey() {
  const key = new RSAKey();
  const signature = key.sign('test');
  console.log(key.verify('test', signature));
}

testDID();