import { DID, Ed25519Key, KeyType, DIDKeyPurpose } from '../src/factom-did';

/**
 * Builds a new DID containing:
 *   - new management key with priority 0 and default key type and controller
 *   - new authentication key with specified key type
 *   - new service
 */
const buildDID = () => {
    return (
        DID.builder()
            // Can be mainnet/testnet or omitted entirely, in which case no network specifier will be added to the DID
            .testnet()
            .managementKey('my-key-1', 0)
            .didKey('my-key-2', [DIDKeyPurpose.AuthenticationKey], KeyType.ECDSA)
            .service('my-service', 'email', 'https://emailme.com')
            .build()
    );
};

const createDIDManagementEntry = () => {
    const did = buildDID();

    // exports entry's extIds and content
    const entryData = did.exportEntryData();

    const content = JSON.parse(entryData['content'].toString());
    console.log(content);
};

/**
 * Builds a new DID instance and updates the DID.
 */
const createDIDUpdateEntry = () => {
    const did = buildDID();

    const updater = DID.builder(
        did.id,
        [...did.managementKeys],
        [...did.didKeys],
        [...did.services]
    )
        .update()
        .rotateManagementKey('my-key-1')
        .revokeDIDKey('my-key-2')
        .addDIDKey(
            'my-key-3',
            [DIDKeyPurpose.AuthenticationKey, DIDKeyPurpose.PublicKey],
            KeyType.RSA
        );

    const entryData = updater.exportEntryData();
    const content = entryData['content'].toString();
    console.log(content);
};

const createDIDDeactivationEntry = () => {
    const did = buildDID();

    const deactivator = DID.builder(
        did.id,
        [...did.managementKeys],
        [...did.didKeys],
        [...did.services]
    ).deactivate();

    const entryData = deactivator.exportEntryData();
    console.log(entryData);
};

const createDIDMethodVersionUpgradeEntry = () => {
    const did = buildDID();

    const upgrader = DID.builder(
        did.id,
        [...did.managementKeys],
        [...did.didKeys],
        [...did.services]
    ).upgradeSpecVersion('0.3.0');

    const entryData = upgrader.exportEntryData();
    console.log(entryData);

    const content = entryData['content'].toString();
    console.log(content);
};

const signAndVerifyUsingEd25519Key = () => {
    const key = new Ed25519Key();
    const key2 = new Ed25519Key(key.publicKey, key.privateKey);

    const signature = key2.sign('test');
    console.log(key.verify('test', Buffer.from(signature)));
};

createDIDManagementEntry();
