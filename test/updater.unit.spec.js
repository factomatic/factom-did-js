const {assert, expect } = require('chai').use(require('chai-bytes')),
  { createHash } = require('crypto'),
  { DID } = require('../src/did'),
  { DIDKey } = require('../src/keys/did'),
  { DID_METHOD_NAME, ENTRY_SCHEMA_V100 } = require('../src/constants'),
  { ManagementKey } = require('../src/keys/management'),
  { Network, EntryType, KeyType, DIDKeyPurpose } = require('../src/enums'),
  { Service } = require('../src/service');

const didId = `${DID_METHOD_NAME}:${Network.Mainnet}:db4549470d24534fac28569d0f9c65b5ecef8d6332bc788b4d1b8dc1c2dae13a`;
const controller = `${DID_METHOD_NAME}:${Network.Mainnet}:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b8005`;
const managementKeys = [
  new ManagementKey('my-first-mgmt-key', 0, KeyType.EdDSA, didId),
  new ManagementKey('my-second-mgmt-key', 1, KeyType.ECDSA, didId, 0),
  new ManagementKey('my-third-mgmt-key', 2, KeyType.RSA, controller, 1)
];
const didKeys = [
  new DIDKey('did-key-1', DIDKeyPurpose.AuthenticationKey, KeyType.EdDSA, didId),
  new DIDKey('did-key-2', [DIDKeyPurpose.PublicKey, DIDKeyPurpose.AuthenticationKey], KeyType.ECDSA, didId, 1),
  new DIDKey('did-key-3', [DIDKeyPurpose.PublicKey], KeyType.RSA, controller, 0)
];
const services = [
  new Service('gmail-service', 'EmailService', 'https://gmail.com', 2),
  new Service('banking-credential-service', 'CredentialStoreService', 'https://credentials.com')
];

describe('Test DID Updater', function() {
  it('should throw error if you try to update DID without management keys', function() {
    assert.throw(
      () => DID.builder().update(),
      'Cannot update DID without management keys.'
    );
  });

  describe('Test Management Keys Update', function() {
    beforeEach(() => {
      did = DID.builder(didId, [...managementKeys]);
    });

    it('should add management key', function() {
      const updater = did.update().addManagementKey('my-new-mgmt-key', 2);
      assert.strictEqual(updater.originalManagementKeys.length, 3);
      assert.strictEqual(updater.managementKeys.length, 4);

      const addedKey = updater.managementKeys[3];
      assert.strictEqual(addedKey.alias, 'my-new-mgmt-key');
      assert.strictEqual(addedKey.priority, 2);
    });

    it('should revoke management key', function() {
      const alias = 'my-second-mgmt-key';
      const updater = did.update().revokeManagementKey(alias);

      assert.strictEqual(updater.originalManagementKeys.length, 3);
      assert.strictEqual(updater.managementKeys.length, 2);
      assert.isUndefined(updater.managementKeys.find(k => k.alias === alias));
    });

    it('should rotate management key', function() {
      const alias = 'my-first-mgmt-key';
      const updater = did.update().rotateManagementKey(alias);
      const originalKey = updater.originalManagementKeys.find(k => k.alias == alias);
      const updatedKey = updater.managementKeys.find(k => k.alias == alias);

      assert.notEqual(updatedKey.publicKey, originalKey.publicKey);
      assert.notEqual(updatedKey.privateKey, originalKey.privateKey);
    });

    it('should not rotate nox-existing management key', function() {
      const alias = 'my-mgmt-key';
      const updater = did.update().rotateManagementKey(alias);
      assert.sameDeepMembers(updater.managementKeys, updater.originalManagementKeys);
    });

    it('should throw error if you try to rotate management key with no private key set', function() {
      const alias = 'my-mgmt-key';
      const key = new ManagementKey('test-key', 0, KeyType.EdDSA, didId);
      did = DID.builder(didId, [new ManagementKey(alias, 0, KeyType.EdDSA, didId, 1, key.publicKey)]);

      assert.throw(
        () => did.update().rotateManagementKey(alias),
        'Private key must be set.'
      );
    });
  });

  describe('Test DID Keys Update', function() {
    beforeEach(() => {
      did = DID.builder(didId, [...managementKeys], [...didKeys]);
    });

    it('should add DID key', function() {
      const updater = did.update().addDIDKey('my-new-did-key', DIDKeyPurpose.AuthenticationKey);
      assert.strictEqual(updater.originalDIDKeys.length, 3);
      assert.strictEqual(updater.didKeys.length, 4);

      const addedKey = updater.didKeys[3];
      assert.strictEqual(addedKey.alias, 'my-new-did-key');
      assert.sameDeepMembers(addedKey.purpose, [DIDKeyPurpose.AuthenticationKey]);
    });

    it('should revoke DID key', function() {
      const alias = 'did-key-2';
      const updater = did.update().revokeDIDKey(alias);

      assert.strictEqual(updater.originalDIDKeys.length, 3);
      assert.strictEqual(updater.didKeys.length, 2);
      assert.isUndefined(updater.didKeys.find(k => k.alias === alias));
    });

    it('should rotate DID key', function() {
      const alias = 'did-key-3';
      const updater = did.update().rotateDIDKey(alias);
      const originalKey = updater.originalDIDKeys.find(k => k.alias == alias);
      const updatedKey = updater.didKeys.find(k => k.alias == alias);

      assert.notEqual(updatedKey.publicKey, originalKey.publicKey);
      assert.notEqual(updatedKey.privateKey, originalKey.privateKey);
    });

    it('should not rotate non-existing DID key', function() {
      const alias = 'did-key-33';
      const updater = did.update().rotateDIDKey(alias);
      assert.sameDeepMembers(updater.didKeys, updater.originalDIDKeys);
    });

    it('should revoke DID key with a single matching purpose', function() {
      const alias = 'did-key-1';
      const updater = did.update().revokeDIDKeyPurpose(alias, DIDKeyPurpose.AuthenticationKey);

      assert.strictEqual(Object.keys(updater.didKeyPurposesToRevoke).length, 0);
      assert.strictEqual(updater.originalDIDKeys.length, 3);
      assert.strictEqual(updater.didKeys.length, 2);
      assert.isUndefined(updater.didKeys.find(k => k.alias === alias));
    });

    it('should revoke DID key with multiple purpose', function() {
      const alias = 'did-key-2';
      const testCases = [DIDKeyPurpose.PublicKey, DIDKeyPurpose.AuthenticationKey];
      testCases.forEach(purpose => {
        const updater = did.update().revokeDIDKeyPurpose(alias, purpose);

        assert.strictEqual(Object.keys(updater.didKeyPurposesToRevoke).length, 1);
        assert.strictEqual(updater.didKeyPurposesToRevoke[alias], purpose);

        const originalKey = updater.originalDIDKeys.find(k => k.alias == alias);
        const updatedKey = updater.didKeys.find(k => k.alias == alias);

        assert.strictEqual(originalKey.purpose.length, 2);
        assert.strictEqual(updatedKey.purpose.length, 1);

        const remainingPurpose = purpose === DIDKeyPurpose.PublicKey ? DIDKeyPurpose.AuthenticationKey : DIDKeyPurpose.PublicKey;
        assert.isTrue(updatedKey.purpose.includes(remainingPurpose));
      });
    });

    it('should not revoke key if you try to revoke invalid or non-existent purpose', function() {
      const alias = 'did-key-3';
      const testCases = [DIDKeyPurpose.AuthenticationKey, 'invalid-purpose'];
      testCases.forEach(purpose => {
        const updater = did.update().revokeDIDKeyPurpose(alias, purpose);
        assert.strictEqual(updater.originalDIDKeys.length, 3);
        assert.strictEqual(updater.didKeys.length, 3);
        assert.isDefined(updater.didKeys.find(k => k.alias === alias));
      });
    });

    it('should not revoke non-existing key', function() {
      const alias = 'did-key-5';
      const updater = did.update().revokeDIDKeyPurpose(alias, DIDKeyPurpose.AuthenticationKey);
      assert.strictEqual(updater.originalDIDKeys.length, 3);
      assert.strictEqual(updater.didKeys.length, 3);
      assert.isUndefined(updater.didKeys.find(k => k.alias === alias));
    });
  });

  describe('Test Services Update', function() {
    beforeEach(() => {
      did = DID.builder(didId, [...managementKeys], [...didKeys], [...services]);
    });

    it('should add service', function() {
      const alias = 'my-new-service';
      const type = 'EmailService';
      const endpoint = 'https://abv.bg';
      const priorityRequirement = 1;
      const customFields = {spamCost: {amount: 1.5}};
      const updater = did.update().addService(alias, type, endpoint, priorityRequirement, customFields);

      assert.strictEqual(updater.originalServices.length, 2);
      assert.strictEqual(updater.services.length, 3);

      const addedService = updater.services[2];
      assert.strictEqual(addedService.alias, alias);
      assert.strictEqual(addedService.serviceType, type);
      assert.strictEqual(addedService.endpoint, endpoint);
      assert.strictEqual(addedService.priorityRequirement, priorityRequirement);
      assert.strictEqual(addedService.customFields, customFields);
    });

    it('should revoke service', function() {
      const alias = 'gmail-service';
      const updater = did.update().revokeService(alias);

      assert.strictEqual(updater.originalServices.length, 2);
      assert.strictEqual(updater.services.length, 1);
      assert.isUndefined(updater.services.find(s => s.alias === alias));
    });
  });

  describe('Test Export Update Entry Data', function() {
    beforeEach(() => {
      did = DID.builder(didId, [...managementKeys], [...didKeys], [...services]);
    });

    it('should throw error if no changes are made', function() {
      assert.throw(
        () => did.update().exportEntryData(),
        'The are no changes made to the DID.'
      );
    });

    it('should throw error if no management keys with priority zero are left', function() {
      assert.throw(
        () => did.update().revokeManagementKey('my-first-mgmt-key').exportEntryData(),
        'DIDUpdate entry would leave no management keys of priority zero.'
      );
    });

    it('should export added keys data correctly', function() {
      const firstNewMgmtKeyAlias = 'my-new-mgmt-key-1';
      const firstNewMgmtKeyPriority = 0;
      const secondNewMgmtKeyAlias = 'my-new-mgmt-key-2';
      const secondNewMgmtKeyPriority = 1;
      const secondNewMgmtKeyType = KeyType.RSA;
      const secondNewMgmtKeyController = controller;
      const secondNewMgmtKeyPriorityRequirement = 0;

      const newDIDKeyAlias = 'my-new-did-key';
      const newDIDKeyPurpose = DIDKeyPurpose.PublicKey;
      const newDIDKeyType = KeyType.ECDSA;
      const newDIDPriorityRequirement = 1;

      const newServiceAlias = 'my-signature-service';
      const newServiceType = 'SignatureService';
      const newServiceEndpoint = 'https://signature-service.com';

      const updateEntryData = did
        .update()
        .addManagementKey(firstNewMgmtKeyAlias, firstNewMgmtKeyPriority)
        .addManagementKey(secondNewMgmtKeyAlias, secondNewMgmtKeyPriority, secondNewMgmtKeyType, secondNewMgmtKeyController, secondNewMgmtKeyPriorityRequirement)
        .addDIDKey(newDIDKeyAlias, newDIDKeyPurpose, newDIDKeyType, undefined, newDIDPriorityRequirement)
        .addService(newServiceAlias, newServiceType, newServiceEndpoint)
        .exportEntryData();
      
      const extIds = updateEntryData['extIds'];
      assert.strictEqual(extIds.length, 4);
      expect(extIds[0]).to.equalBytes(Buffer.from(EntryType.Update));
      expect(extIds[1]).to.equalBytes(Buffer.from(ENTRY_SCHEMA_V100));

      const signingKey = did._managementKeys[0];
      const signingKeyId = signingKey.fullId(didId);
      const signedData = "".concat(EntryType.Update, ENTRY_SCHEMA_V100, signingKeyId, updateEntryData['content'].toString());
      const sha256Hash = createHash('sha256');
      sha256Hash.update(Buffer.from(signedData));
      
      expect(extIds[2]).to.equalBytes(Buffer.from(signingKeyId));
      assert.isTrue(signingKey.verify(sha256Hash.digest(), extIds[3]));

      const content = JSON.parse(updateEntryData['content'].toString());
      assert.isUndefined(content['revoke']);

      const added = content['add'];
      const managementKeys = added['managementKey'];
      const didKeys = added['didKey'];
      const services = added['service'];

      assert.strictEqual(managementKeys.length, 2);
      assert.strictEqual(didKeys.length, 1);
      assert.strictEqual(services.length, 1);

      const firstAddedMgmtKey = managementKeys[0];
      assert.strictEqual(firstAddedMgmtKey.id, `${didId}#${firstNewMgmtKeyAlias}`);
      assert.strictEqual(firstAddedMgmtKey.priority, firstNewMgmtKeyPriority);
      assert.strictEqual(firstAddedMgmtKey.type, KeyType.EdDSA);
      assert.strictEqual(firstAddedMgmtKey.controller, didId);
      assert.strictEqual(firstAddedMgmtKey.publicKeyBase58, did._managementKeys[3].publicKey);
      assert.isUndefined(firstAddedMgmtKey.priorityRequirement);

      const secondAddedMgmtKey = managementKeys[1];
      assert.strictEqual(secondAddedMgmtKey.id, `${didId}#${secondNewMgmtKeyAlias}`);
      assert.strictEqual(secondAddedMgmtKey.priority, secondNewMgmtKeyPriority);
      assert.strictEqual(secondAddedMgmtKey.type, secondNewMgmtKeyType);
      assert.strictEqual(secondAddedMgmtKey.controller, secondNewMgmtKeyController);
      assert.strictEqual(secondAddedMgmtKey.publicKeyPem, did._managementKeys[4].publicKey);
      assert.strictEqual(secondAddedMgmtKey.priorityRequirement, secondNewMgmtKeyPriorityRequirement);

      const addedDIDKey = didKeys[0];
      assert.strictEqual(addedDIDKey.id, `${didId}#${newDIDKeyAlias}`);
      assert.sameDeepMembers(addedDIDKey.purpose, [newDIDKeyPurpose]);
      assert.strictEqual(addedDIDKey.type, newDIDKeyType);
      assert.strictEqual(addedDIDKey.controller, didId);
      assert.strictEqual(addedDIDKey.publicKeyBase58, did._didKeys[3].publicKey);
      assert.strictEqual(addedDIDKey.priorityRequirement, newDIDPriorityRequirement);

      const addedService = services[0];
      assert.strictEqual(addedService.id, `${didId}#${newServiceAlias}`);
      assert.strictEqual(addedService.type, newServiceType);
      assert.strictEqual(addedService.serviceEndpoint, newServiceEndpoint);
      assert.isUndefined(addedService.priorityRequirement);
    });

    it('should export revoked keys data correctly', function() {
      const updateEntryData = did
        .update()
        .revokeManagementKey('my-second-mgmt-key')
        .revokeDIDKey('did-key-1')
        .revokeDIDKeyPurpose('did-key-2', DIDKeyPurpose.AuthenticationKey)
        .revokeService('banking-credential-service')
        .exportEntryData();

      const extIds = updateEntryData['extIds'];
      assert.strictEqual(extIds.length, 4);
      expect(extIds[0]).to.equalBytes(Buffer.from(EntryType.Update));
      expect(extIds[1]).to.equalBytes(Buffer.from(ENTRY_SCHEMA_V100));
      expect(extIds[2]).to.equalBytes(Buffer.from(did._managementKeys[0].fullId(didId)));

      const content = JSON.parse(updateEntryData['content'].toString());
      assert.isUndefined(content['add']);
      const revoked = content['revoke'];

      const revokedManagementKeys = revoked['managementKey']
      const revokedDIDKeys = revoked['didKey'];
      const revokedServices = revoked['service'];

      assert.strictEqual(revokedManagementKeys.length, 1);
      assert.strictEqual(revokedDIDKeys.length, 2);
      assert.strictEqual(revokedServices.length, 1);

      const revokedMgmtKey = revokedManagementKeys[0];
      assert.strictEqual(revokedMgmtKey['id'], `${didId}#my-second-mgmt-key`);

      const firstRevokedDIDKey = revokedDIDKeys[0];
      const secondRevokedDIDKey = revokedDIDKeys[1];
      assert.strictEqual(firstRevokedDIDKey['id'], `${didId}#did-key-1`);
      assert.strictEqual(secondRevokedDIDKey['id'], `${didId}#did-key-2`);
      assert.sameDeepMembers(secondRevokedDIDKey['purpose'], [DIDKeyPurpose.AuthenticationKey]);

      const revokedService = revokedServices[0];
      assert.strictEqual(revokedService['id'], `${didId}#banking-credential-service`);
    });

    it('should export update entry data correctly', function() {
      did = DID.builder(
        didId,
        [...managementKeys],
        [...didKeys, new DIDKey('did-key-4', [DIDKeyPurpose.PublicKey, DIDKeyPurpose.AuthenticationKey], KeyType.EdDSA, didId)],
        [...services]
      );

      const signingKey = did._managementKeys[0].fullId(didId);
      const updateEntryData = did
        .update()
        .revokeManagementKey('my-first-mgmt-key')
        .revokeDIDKeyPurpose('did-key-2', DIDKeyPurpose.PublicKey)
        .revokeDIDKeyPurpose('did-key-4', DIDKeyPurpose.AuthenticationKey)
        .revokeService('gmail-service')
        .addManagementKey('new-mgmt-key', 0)
        .addDIDKey('new-did-key', [DIDKeyPurpose.PublicKey, DIDKeyPurpose.AuthenticationKey])
        .exportEntryData();

      const extIds = updateEntryData['extIds'];
      assert.strictEqual(extIds.length, 4);
      expect(extIds[0]).to.equalBytes(Buffer.from(EntryType.Update));
      expect(extIds[1]).to.equalBytes(Buffer.from(ENTRY_SCHEMA_V100));
      expect(extIds[2]).to.equalBytes(Buffer.from(signingKey));

      const content = JSON.parse(updateEntryData['content'].toString());
      const revoked = content['revoke'];
      const added = content['add'];

      const revokedManagementKeys = revoked['managementKey']
      const revokedDIDKeys = revoked['didKey'];
      const revokedServices = revoked['service'];

      assert.strictEqual(revokedManagementKeys.length, 1);
      assert.strictEqual(revokedDIDKeys.length, 2);
      assert.strictEqual(revokedServices.length, 1);

      const revokedMgmtKey = revokedManagementKeys[0];
      assert.strictEqual(revokedMgmtKey['id'], `${didId}#my-first-mgmt-key`);

      const firstRevokedDIDKey = revokedDIDKeys[0];
      const secondRevokedDIDKey = revokedDIDKeys[1];
      assert.strictEqual(firstRevokedDIDKey['id'], `${didId}#did-key-2`);
      assert.sameDeepMembers(firstRevokedDIDKey['purpose'], [DIDKeyPurpose.PublicKey]);
      assert.strictEqual(secondRevokedDIDKey['id'], `${didId}#did-key-4`);
      assert.sameDeepMembers(secondRevokedDIDKey['purpose'], [DIDKeyPurpose.AuthenticationKey]);

      const revokedService = revokedServices[0];
      assert.strictEqual(revokedService['id'], `${didId}#gmail-service`);

      assert.isUndefined(added['service']);
      const addedMgmtKeys = added['managementKey'];
      const addedDIDKey = added['didKey'];

      assert.strictEqual(addedMgmtKeys.length, 1);
      assert.strictEqual(addedDIDKey.length, 1);
    });

    it('should throw error if entry size is exceeded', function() {
      const updater = did
        .update()
        .revokeManagementKey('my-second-mgmt-key')
        .revokeDIDKey('did-key-1')
        .revokeDIDKey('did-key-2')
        .revokeDIDKey('did-key-3')
        .revokeService('gmail-service');

      for (let i = 0; i < 35; i++) {
        updater.addManagementKey(`my-management-key-${i}`, 0);
      }

      assert.throw(() => updater.exportEntryData(),
        'You have exceeded the entry size limit!'
      );
    });
  });
});