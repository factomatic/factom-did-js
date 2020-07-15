import { assert, expect, use } from 'chai';
import chaibytes from 'chai-bytes';
import {
    DID,
    DIDKey,
    ManagementKey,
    Network,
    EntryType,
    KeyType,
    DIDKeyPurpose,
    Service
} from '../src/factom-did';
import { DID_METHOD_SPEC_V020, DID_METHOD_NAME, ENTRY_SCHEMA_V100 } from '../src/constants';

use(chaibytes);

const idRegex = new RegExp(`^${DID_METHOD_NAME}:[a-f0-9]{64}$`);

describe('Test DID', function() {
    it('should throw error if builder is not instance of DIDBuilder class', function() {
        const obj: any = {};
        assert.throw(() => new DID(obj), 'Use `DID.builder()` syntax to create a new DID');
    });

    it('should generate new empty DID', function() {
        const did = DID.builder().build();

        assert.match(did.id, idRegex);
        assert.isArray(did.managementKeys);
        assert.isArray(did.didKeys);
        assert.isArray(did.services);
        assert.isEmpty(did.managementKeys);
        assert.isEmpty(did.didKeys);
        assert.isEmpty(did.services);
        assert.isEmpty(did.network);
        assert.strictEqual(did.specVersion, DID_METHOD_SPEC_V020);
    });

    it('should initialize DIDBuilder correctly', function() {
        const didId = `${DID_METHOD_NAME}:${Network.Testnet}:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b8005`;
        const managementKeys = [
            new ManagementKey('my-first-key', 0, KeyType.EdDSA, didId),
            new ManagementKey('my-second-key', 1, KeyType.ECDSA, didId, 0)
        ];
        const didKeys = [
            new DIDKey('my-did-key', DIDKeyPurpose.AuthenticationKey, KeyType.RSA, didId, 1)
        ];
        const services = [
            new Service('my-photo-service', 'PhotoStreamService', 'https://myphoto.com', 1)
        ];

        const didBuilder = DID.builder(didId, managementKeys, didKeys, services);
        assert.strictEqual(didBuilder.id, didId);
        assert.strictEqual(didBuilder.managementKeys, managementKeys);
        assert.strictEqual(didBuilder.didKeys, didKeys);
        assert.strictEqual(didBuilder.services, services);
        assert.strictEqual(didBuilder.network, Network.Testnet);
        assert.strictEqual(didBuilder.specVersion, DID_METHOD_SPEC_V020);
        assert.strictEqual((didBuilder as any)._usedKeyAliases.size, 3);
        assert.strictEqual((didBuilder as any)._usedServiceAliases.size, 1);
        assert.isTrue((didBuilder as any)._usedKeyAliases.has('my-first-key'));
        assert.isTrue((didBuilder as any)._usedKeyAliases.has('my-second-key'));
        assert.isTrue((didBuilder as any)._usedKeyAliases.has('my-did-key'));
        assert.isTrue((didBuilder as any)._usedServiceAliases.has('my-photo-service'));
    });

    it('should initialize DIDBuilder correctly with different spec version', function() {
        const didId = `${DID_METHOD_NAME}:${Network.Testnet}:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b8005`;
        const managementKeys = [new ManagementKey('my-first-key', 0, KeyType.EdDSA, didId)];
        const specVersion = '0.3.0';

        const didBuilder = DID.builder(didId, managementKeys, undefined, undefined, specVersion);
        assert.strictEqual(didBuilder.specVersion, specVersion);
    });

    it('should generate new didId if the one passed is invalid', function() {
        const didId = `${DID_METHOD_NAME}:${Network.Testnet}:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b800`;
        const didBuilder = DID.builder(didId);
        assert.notEqual(didBuilder.id, didId);
    });

    it('should throw error if duplicate key alias is passed', function() {
        const alias = 'my-first-key';
        const didId = `${DID_METHOD_NAME}:${Network.Testnet}:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b8005`;
        const managementKeys = [new ManagementKey(alias, 0, KeyType.EdDSA, didId)];
        const didKeys = [new DIDKey(alias, DIDKeyPurpose.AuthenticationKey, KeyType.RSA, didId, 1)];

        assert.throw(
            () => DID.builder(didId, managementKeys, didKeys),
            `Duplicate alias "${alias}" detected.`
        );
    });

    it('should throw error if duplicate service alias is passed', function() {
        const alias = 'my-photo-service';
        const didId = `${DID_METHOD_NAME}:${Network.Testnet}:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b8005`;
        const services = [
            new Service(alias, 'PhotoStreamService', 'https://myphoto.com', 1),
            new Service(alias, 'PhotoStreamService', 'https://myphoto.com', 1)
        ];

        assert.throw(
            () => DID.builder(didId, undefined, undefined, services),
            `Duplicate alias "${alias}" detected.`
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
        expect(extIds[2]).to.equalBytes(did.nonce as Buffer);
    });

    it('should export entry data with management keys', function() {
        const firstManagementKeyAlias = 'my-first-management-key';
        const firstManagementKeyPriority = 0;
        const secondManagementKeyAlias = 'my-second-management-key';
        const secondManagementKeyPriority = 1;
        const secondManagementKeyType = KeyType.ECDSA;
        const secondManagementKeyController = `${DID_METHOD_NAME}:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b8005`;
        const secondManagementKeyPriorityRequirement = 2;

        const did = DID.builder()
            .managementKey(firstManagementKeyAlias, firstManagementKeyPriority)
            .managementKey(
                secondManagementKeyAlias,
                secondManagementKeyPriority,
                secondManagementKeyType,
                secondManagementKeyController,
                secondManagementKeyPriorityRequirement
            )
            .build();

        const entryData = did.exportEntryData();
        const content = JSON.parse(entryData['content'].toString());
        assert.strictEqual(content['didMethodVersion'], DID_METHOD_SPEC_V020);

        const managementKeys = content['managementKey'];
        assert.strictEqual(managementKeys.length, 2);
        assert.isUndefined(content['didKey']);
        assert.isUndefined(content['services']);

        const firstManagementKey = managementKeys[0];
        assert.strictEqual(firstManagementKey.id, `${did.id}#${firstManagementKeyAlias}`);
        assert.strictEqual(firstManagementKey.priority, firstManagementKeyPriority);
        assert.strictEqual(firstManagementKey.type, KeyType.EdDSA);
        assert.strictEqual(firstManagementKey.controller, did.id);
        assert.strictEqual(firstManagementKey.publicKeyBase58, did.managementKeys[0].publicKey);
        assert.isUndefined(firstManagementKey.priorityRequirement);

        const secondManagementKey = managementKeys[1];
        assert.strictEqual(secondManagementKey.id, `${did.id}#${secondManagementKeyAlias}`);
        assert.strictEqual(secondManagementKey.priority, secondManagementKeyPriority);
        assert.strictEqual(secondManagementKey.type, secondManagementKeyType);
        assert.strictEqual(secondManagementKey.controller, secondManagementKeyController);
        assert.strictEqual(secondManagementKey.publicKeyBase58, did.managementKeys[1].publicKey);
        assert.strictEqual(
            secondManagementKey.priorityRequirement,
            secondManagementKeyPriorityRequirement
        );
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
        const serviceCost = { amount: '0.50', currency: 'USD' };
        const serviceCustomFields = {
            description: serviceDescription,
            cost: serviceCost
        };

        const did = DID.builder()
            .mainnet()
            .managementKey('my-management-key-1', 0)
            .managementKey('my-management-key-2', 2)
            .didKey(
                didKeyAlias,
                didKeyPurpose,
                didKeyType,
                didKeyController,
                didKeyPriorityRequirement
            )
            .service(
                serviceAlias,
                serviceType,
                serviceEndpoint,
                servicePriorityRequirement,
                serviceCustomFields
            )
            .build();

        const entryData = did.exportEntryData();
        const content = JSON.parse(entryData['content'].toString());

        const didKeys = content['didKey'];
        const services = content['service'];
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
        assert.strictEqual(
            JSON.stringify(firstService.description),
            JSON.stringify(serviceDescription)
        );
    });

    it('should throw error if entry does not have at least one management key', function() {
        assert.throw(() => {
            DID.builder()
                .didKey('my-did-key', [DIDKeyPurpose.AuthenticationKey])
                .service('auth-service', 'AuthenticationService', 'https://authenticateme.com')
                .build()
                .exportEntryData();
        }, 'The DID must have at least one management key.');
    });

    it('should throw error if entry does not have at least one management key with priority 0', function() {
        assert.throw(() => {
            DID.builder()
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
