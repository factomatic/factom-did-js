const {assert, expect } = require('chai').use(require('chai-bytes')),
  { DID } = require('../src/did'),
  { DID_METHOD_SPEC_V020, DID_METHOD_NAME, ENTRY_SCHEMA_V100 } = require('../src/constants'),
  { Network, EntryType, KeyType, DIDKeyPurpose } = require('../src/enums');

const idRegex = new RegExp(`^${DID_METHOD_NAME}:[a-f0-9]{64}$`);

describe('Test DID', function() {
  it('should generate new empty DID', function() {
    const did = DID.builder().build();

    assert.match(did.id, idRegex);
    assert.isArray(did.managementKeys);
    assert.isArray(did.didKeys);
    assert.isArray(did.services);
    assert.isEmpty(did.managementKeys);
    assert.isEmpty(did.didKeys);
    assert.isEmpty(did.services);
    assert.isUndefined(did.network);
    assert.strictEqual(did.specVersion, DID_METHOD_SPEC_V020);
  });

  it('should throw error if DID class is instantiated directly', function() {
    assert.throw(
      () => new DID(),
      'Use `DID.builder()` syntax to create a new DID'
    );
  });

  it('should check frozen properties', function() {
    const did = DID.builder()
      .managementKey('my-key-1', 0)
      .build();

     assert.isFrozen(did.id);
     assert.isFrozen(did.network);
     assert.isFrozen(did.specVersion);
     assert.isFrozen(did.managementKeys);
     assert.isFrozen(did.didKeys);
     assert.isFrozen(did.services);
  });

  it('should build mainnet DID', function() {
    const did = DID.builder()
      .mainnet()
      .build();

    const regex = new RegExp(`^${DID_METHOD_NAME}:${Network.Mainnet}:[a-f0-9]{64}$`);
    assert.match(did.id, regex);
    assert.strictEqual(did.network, Network.Mainnet);
  });

  it('should build testnet DID', function() {
    const did = DID.builder()
      .testnet()
      .build();

    const regex = new RegExp(`^${DID_METHOD_NAME}:${Network.Testnet}:[a-f0-9]{64}$`);
    assert.match(did.id, regex);
    assert.strictEqual(did.network, Network.Testnet);
  });

  it('should export correct extIds', function() {
    const did = DID.builder()
      .managementKey('my-management-key', 0)
      .build();

    const entryData = did.exportEntryData();
    
    const extIds = entryData['extIds'];
    expect(extIds[0]).to.equalBytes(Buffer.from(EntryType.Create));
    expect(extIds[1]).to.equalBytes(Buffer.from(ENTRY_SCHEMA_V100));
    expect(extIds[2]).to.equalBytes(did.nonce);
  });

  it('should export entry data with management key', function() {
    const alias = 'my-management-key';
    const priority = 0;
    const did = DID.builder()
      .managementKey(alias, priority)
      .build();

    const entryData = did.exportEntryData();
    const content = JSON.parse(entryData['content'].toString());
    assert.strictEqual(content['didMethodVersion'], DID_METHOD_SPEC_V020);

    const managementKeys = content['managementKey'];
    assert.strictEqual(managementKeys.length, 1);
    assert.isUndefined(content['didKey']);
    assert.isUndefined(content['services']);

    const firstManagementKey = managementKeys[0];
    assert.strictEqual(firstManagementKey.id, `${did.id}#${alias}`);
    assert.strictEqual(firstManagementKey.priority, priority);
    assert.strictEqual(firstManagementKey.type, KeyType.EdDSA);
    assert.strictEqual(firstManagementKey.controller, did.id);
    assert.strictEqual(firstManagementKey.publicKeyBase58, did.managementKeys[0].publicKey);
    assert.isUndefined(firstManagementKey.priorityRequirement);
  });

  it('should export entry data with did key and service', function() {
    const didKeyAlias = 'my-public-key';
    const didKeyPurpose = [DIDKeyPurpose.PublicKey];
    const didKeyType = KeyType.RSA;
    const didKeyController = `${DID_METHOD_NAME}:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b8005`;
    const didKeyPriorityRequirement = 1;

    const serviceAlias = 'my-photo-service';
    const serviceType = 'PhotoStreamService';
    const serviceEndpoint = 'https://myphoto.com';
    const servicePriorityRequirement = 1;
    const serviceDescription = 'My photo stream service';
    const serviceCost = {'amount': '0.50', 'currency': 'USD'};
    const serviceCustomFields = {
      'description': serviceDescription,
      'cost': serviceCost
    };

    const did = DID.builder()
      .mainnet()
      .managementKey('my-management-key-1', 0)
      .managementKey('my-management-key-2', 2)
      .didKey(didKeyAlias, didKeyPurpose, didKeyType, didKeyController, didKeyPriorityRequirement)
      .service(serviceAlias, serviceType, serviceEndpoint, servicePriorityRequirement, serviceCustomFields)
      .build();

    const entryData = did.exportEntryData();
    const content = JSON.parse(entryData['content'].toString());

    const didKeys = content['didKey'];
    const services = content['services'];
    assert.strictEqual(content['managementKey'].length, 2);
    assert.strictEqual(didKeys.length, 1);
    assert.strictEqual(services.length, 1);

    const firstDIDKey = didKeys[0];
    assert.strictEqual(firstDIDKey.id, `${did.id}#${didKeyAlias}`);
    assert.sameDeepMembers(firstDIDKey.purpose, didKeyPurpose);
    assert.strictEqual(firstDIDKey.type, didKeyType);
    assert.strictEqual(firstDIDKey.controller, didKeyController);
    assert.strictEqual(firstDIDKey.publicKeyPem, did.didKeys[0].publicKey);
    assert.strictEqual(firstDIDKey.priorityRequirement, didKeyPriorityRequirement);

    const firstService = services[0];
    assert.strictEqual(firstService.id, `${did.id}#${serviceAlias}`);
    assert.strictEqual(firstService.type, serviceType);
    assert.strictEqual(firstService.serviceEndpoint, serviceEndpoint);
    assert.strictEqual(firstService.priorityRequirement, servicePriorityRequirement);
    assert.strictEqual(firstService.description, serviceDescription);
    assert.strictEqual(JSON.stringify(firstService.description), JSON.stringify(serviceDescription));
  });

  it('should throw error if entry does not have at least one management key', function() {
    assert.throw(() => {
      DID
        .builder()
        .didKey('my-did-key', [DIDKeyPurpose.AuthenticationKey])
        .service('auth-service', 'AuthenticationService', 'https://authenticateme.com')
        .build()
        .exportEntryData();
    }, 'The DID must have at least one management key.');
  });

  it('should throw error if entry does not have at least one management key with priority 0', function() {
    assert.throw(() => {
      DID
        .builder()
        .managementKey('my-mgmg-key-1', 1)
        .managementKey('my-mgmt-key-2', 2)
        .build()
        .exportEntryData();
    }, 'At least one management key must have priority 0.');
  });

  it('should throw error if entry size is exceeded', function() {
    const builder = DID.builder();
    assert.throw(() => {
      for (let i = 0; i < 35; i++) {
        builder.managementKey(`my-management-key-${i}`, 0);
      }

      builder.build().exportEntryData();
    }, 'You have exceeded the entry size limit! Please remove some of your keys or services.');
  });
});