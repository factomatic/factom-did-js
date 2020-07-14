import { calculateChainId, calculateEntrySize } from './blockchain';
import { DIDDocument } from './interfaces/DIDDocument';
import { DIDDeactivator } from './deactivator';
import { DIDVersionUpgrader } from './upgrader';
import { DIDUpdater } from './updater';
import { DIDKey } from './keys/did';
import { EntryData } from './interfaces/EntryData';
import { isValidDIDId } from './validators';
import { ManagementKey } from './keys/management';
import { Network, KeyType, EntryType, DIDKeyPurpose } from './enums';
import { randomBytes } from 'crypto';
import { Service } from './service';
import {
    DID_METHOD_SPEC_V020,
    DID_METHOD_NAME,
    ENTRY_SCHEMA_V100,
    ENTRY_SIZE_LIMIT,
} from './constants';

/**
 * Class that allows exporting of the constructed DID into a format suitable for recording on the Factom blockchain.
 * @param {DIDBuilder} builder
 */
export class DID {
    readonly id: string;
    readonly nonce: Buffer | undefined;
    readonly network: Network;
    readonly specVersion: string | undefined;
    readonly managementKeys: readonly ManagementKey[];
    readonly didKeys: readonly DIDKey[];
    readonly services: readonly Service[];

    constructor(builder: DIDBuilder) {
        if (builder instanceof DIDBuilder) {
            this.id = builder.id;
            this.nonce = builder.nonce;
            this.network = builder.network;
            this.specVersion = builder.specVersion;
            this.managementKeys = Object.freeze(builder.managementKeys);
            this.didKeys = Object.freeze(builder.didKeys);
            this.services = Object.freeze(builder.services);
            Object.freeze(this);
        } else {
            throw new Error('Use `DID.builder()` syntax to create a new DID');
        }
    }

    /**
     * Exports content that can be recorded on-chain to create the DID.
     * @returns {EntryData} An object containing the ExtIDs and the entry content.
     */
    exportEntryData(): EntryData {
        if (this.managementKeys.length < 1) {
            throw new Error('The DID must have at least one management key.');
        }

        if (!this.managementKeys.some((mk) => mk.priority === 0)) {
            throw new Error('At least one management key must have priority 0.');
        }

        const content = Buffer.from(JSON.stringify(this._buildDIDDocument()), 'utf-8');
        const extIds: Buffer[] = [
            Buffer.from(EntryType.Create, 'utf-8'),
            Buffer.from(ENTRY_SCHEMA_V100, 'utf-8'),
            this.nonce as Buffer,
        ];

        const entrySize = calculateEntrySize(extIds, content);
        if (entrySize > ENTRY_SIZE_LIMIT) {
            throw new Error(
                'You have exceeded the entry size limit! Please remove some of your keys or services.'
            );
        }

        return { extIds, content };
    }

    /**
     * Builds a DID Document.
     * @returns {DIDDocument} An object with the DID Document properties.
     */
    private _buildDIDDocument(): DIDDocument {
        const didDocument: DIDDocument = {
            didMethodVersion: this.specVersion as string,
            managementKey: this.managementKeys.map((k) => k.toEntryObj(this.id)),
        };

        if (this.didKeys.length > 0) {
            didDocument.didKey = this.didKeys.map((k) => k.toEntryObj(this.id));
        }

        if (this.services.length > 0) {
            didDocument.service = this.services.map((s) => s.toEntryObj(this.id));
        }

        return didDocument;
    }

    /**
     * DID builder static factory.
     * @param {string} [didId] - The decentralized identifier, a 32 byte hexadecimal string.
     * @param {ManagementKey[]} [managementKeys] - A list of management keys.
     * @param {DIDKey[]} [didKeys] - A list of DID keys.
     * @param {Service[]} [services] - A list of services.
     * @param {string} [specVersion] - DID Method version.
     * @returns {DIDBuilder} A new DIDBuilder.
     */
    static builder(
        didId?: string,
        managementKeys?: ManagementKey[],
        didKeys?: DIDKey[],
        services?: Service[],
        specVersion: string = DID_METHOD_SPEC_V020
    ): DIDBuilder {
        return new DIDBuilder(didId, managementKeys, didKeys, services, specVersion);
    }
}

/**
 * Class that enables the construction of a DID, by facilitating the construction of management keys and DID keys and the
 *  addition of services.
 * @param {string} [didId] - The decentralized identifier, a 32 byte hexadecimal string.
 * @param {ManagementKey[]} [managementKeys] - A list of management keys.
 * @param {DIDKey[]} [didKeys] - A list of DID keys.
 * @param {Service[]} [services] - A list of services.
 * @param {string} [specVersion] - DID Method version.
 */
export class DIDBuilder {
    public managementKeys: ManagementKey[];
    public didKeys: DIDKey[];
    public services: Service[];
    private _id: string;
    private _nonce: Buffer | undefined;
    private _network: Network;
    private _specVersion: string | undefined;
    private _usedKeyAliases: Set<string>;
    private _usedServiceAliases: Set<string>;

    constructor(
        didId?: string,
        managementKeys?: ManagementKey[],
        didKeys?: DIDKey[],
        services?: Service[],
        specVersion?: string
    ) {
        this._id = didId && isValidDIDId(didId) ? didId : this._generateDIDId();
        this.managementKeys = managementKeys ? managementKeys : [];
        this.didKeys = didKeys ? didKeys : [];
        this.services = services ? services : [];
        this._network = this._getNetworkFromId(this._id);
        this._specVersion = specVersion;

        this._usedKeyAliases = new Set();
        this._usedServiceAliases = new Set();

        this.managementKeys.forEach((key) => {
            this._checkAliasIsUnique(this._usedKeyAliases, key.alias);
        });

        this.didKeys.forEach((key) => {
            this._checkAliasIsUnique(this._usedKeyAliases, key.alias);
        });

        this.services.forEach((service) => {
            this._checkAliasIsUnique(this._usedServiceAliases, service.alias);
        });
    }

    get id(): string {
        return this._id;
    }

    get nonce(): Buffer | undefined {
        return this._nonce;
    }

    get network(): Network {
        return this._network;
    }

    get specVersion(): string | undefined {
        return this._specVersion;
    }

    /**
     * @returns {string} The chain ID where this DID is (or will be) stored.
     */
    get chainId(): string {
        return this._id.split(':').slice(-1).pop() as string;
    }

    /**
     * @returns {DIDUpdater} - An object allowing updates to the existing DID.
     */
    update(): DIDUpdater {
        if (this.managementKeys.length === 0) {
            throw new Error('Cannot update DID without management keys.');
        }

        return new DIDUpdater(this);
    }

    /**
     * @returns {DIDDeactivator} - An object allowing deactivation of the existing DID.
     */
    deactivate(): DIDDeactivator {
        if (this.managementKeys.length === 0) {
            throw new Error('Cannot deactivate DID without a management key of priority 0.');
        }

        return new DIDDeactivator(this);
    }

    /**
     * @param {string} newSpecVersion - The new DID Method version
     * @returns {DIDVersionUpgrader} - An object allowing method spec version upgrade of the existing DID.
     */
    upgradeSpecVersion(newSpecVersion: string): DIDVersionUpgrader {
        if (this.managementKeys.length === 0) {
            throw new Error('Cannot upgrade method spec version for DID without management keys.');
        }

        return new DIDVersionUpgrader(this, newSpecVersion);
    }

    /**
     * Sets the DID network to mainnet.
     * @returns {DIDBuilder} - DIDBuilder instance.
     */
    mainnet(): this {
        this._network = Network.Mainnet;
        this._id = `${DID_METHOD_NAME}:${this._network}:${this.chainId}`;

        return this;
    }

    /**
     * Sets the DID network to testnet.
     * @returns {DIDBuilder} - DIDBuilder instance.
     */
    testnet(): this {
        this._network = Network.Testnet;
        this._id = `${DID_METHOD_NAME}:${this._network}:${this.chainId}`;

        return this;
    }

    /**
     * Creates a new management key for the DID.
     * @param {string} alias - A human-readable nickname for the key. It should be unique across the keys defined in the DID document.
     * @param {number} priority - A non-negative integer showing the hierarchical level of the key. Keys with lower priority
     *    override keys with higher priority.
     * @param {KeyType} [keyType] - Identifies the type of signature that the key pair can be used to generate and verify.
     * @param {string} [controller] - An entity that controls the key. It must be a valid DID. If the argument is not passed in,
     *   the default value is used which is the current DID itself.
     * @param {number} [priorityRequirement] - A non-negative integer showing the minimum hierarchical level a key must have in order to remove this key.
     * @returns {DIDBuilder} - DIDBuilder instance.
     */
    managementKey(
        alias: string,
        priority: number,
        keyType: KeyType = KeyType.EdDSA,
        controller?: string,
        priorityRequirement?: number
    ): this {
        if (!controller) {
            controller = this._id;
        }

        const key = new ManagementKey(alias, priority, keyType, controller, priorityRequirement);
        this._checkAliasIsUnique(this._usedKeyAliases, key.alias);
        this.managementKeys.push(key);

        return this;
    }

    /**
     * Creates a new DID key for the DID.
     * @param {string} alias - A human-readable nickname for the key. It should be unique across the keys defined in the DID document.
     * @param {DIDKeyPurpose | DIDKeyPurpose[]} purpose - Shows what purpose(s) the key serves. (PublicKey, AuthenticationKey or both)
     * @param {KeyType} [keyType] - Identifies the type of signature that the key pair can be used to generate and verify.
     * @param {string} [controller] - An entity that controls the key. It must be a valid DID. If the argument is not passed in,
     *   the default value is used which is the current DID itself.
     * @param {number} [priorityRequirement] - A non-negative integer showing the minimum hierarchical level a key must have in order to remove this key.
     * @returns {DIDBuilder} - DIDBuilder instance.
     */
    didKey(
        alias: string,
        purpose: DIDKeyPurpose | DIDKeyPurpose[],
        keyType: KeyType = KeyType.EdDSA,
        controller?: string,
        priorityRequirement?: number
    ): this {
        if (!controller) {
            controller = this._id;
        }

        const key = new DIDKey(alias, purpose, keyType, controller, priorityRequirement);
        this._checkAliasIsUnique(this._usedKeyAliases, key.alias);
        this.didKeys.push(key);

        return this;
    }

    /**
     * Adds a new service to the DID Document.
     * @param {string} alias - A human-readable nickname for the service endpoint.
     *   It should be unique across the services defined in the DID document.
     * @param {string} serviceType - Type of the service endpoint.
     * @param {string} endpoint - A service endpoint may represent any type of service the subject wishes to advertise, including
     *   decentralized identity management services for further discovery, authentication, authorization, or interaction.
     *   The service endpoint must be a valid URL.
     * @param {number} [priorityRequirement] - A non-negative integer showing the minimum hierarchical level a key must have in order to remove this service.
     * @param {Object} [customFields] - An object containing custom fields (e.g "description": "My public social inbox").
     * @returns {DIDBuilder} - DIDBuilder instance.
     */
    service(
        alias: string,
        serviceType: string,
        endpoint: string,
        priorityRequirement?: number,
        customFields?: any
    ): this {
        const service = new Service(
            alias,
            serviceType,
            endpoint,
            priorityRequirement,
            customFields
        );
        this._checkAliasIsUnique(this._usedServiceAliases, service.alias);
        this.services.push(service);

        return this;
    }

    /**
     * Build the DID.
     * @returns {DID} - Built DID.
     */
    build(): DID {
        return new DID(this);
    }

    /**
     * Generates a new DID Id.
     * @returns {string} - A DID Id.
     */
    private _generateDIDId(): string {
        this._nonce = randomBytes(32);
        const chainId = calculateChainId([
            EntryType.Create,
            ENTRY_SCHEMA_V100,
            this._nonce as Buffer,
        ]);
        return `${DID_METHOD_NAME}:${chainId}`;
    }

    private _checkAliasIsUnique(usedAliases: Set<string>, alias: string): void {
        if (usedAliases.has(alias)) {
            throw new Error(`Duplicate alias "${alias}" detected.`);
        }

        usedAliases.add(alias);
    }

    private _getNetworkFromId(didId: string): Network {
        const parts = didId.split(':');
        if (parts.length === 4) {
            return parts[2] as Network;
        }

        return Network.Unspecified;
    }
}
