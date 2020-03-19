const crypto = require('crypto'),
  { calculateChainId, calculateEntrySize } = require('./blockchain'),
  { DID_METHOD_SPEC_V020, DID_METHOD_NAME, ENTRY_SCHEMA_V100, ENTRY_SIZE_LIMIT } = require('./constants'),
  { DIDKey } = require('./keys/did'),
  { ManagementKey } = require('./keys/management'),
  { Network, KeyType, DIDKeyPurpose, EntryType } = require('./enums'),
  { Service } = require('./service');

/**
 * Class that allows exporting of the constructed DID into a format suitable for recording on the Factom blockchain.
 * @param {DIDBuilder} builder
 */
class DID {
  constructor(builder) {
    if (builder instanceof DIDBuilder) {
      this.id = builder._id;
      this.nonce = builder._nonce;
      this.network = builder._network;
      this.specVersion = builder._specVersion;
      this.managementKeys = Object.freeze(builder._managementKeys);
      this.didKeys = Object.freeze(builder._didKeys);
      this.services = Object.freeze(builder._services);
      Object.freeze(this);
    } else {
      throw new Error('Use `DID.builder()` syntax to create a new DID');
    }
  }

  /**
  * Exports content that can be recorded on-chain to create the DID.
  * @returns {Object} An object containing the ExtIDs and the entry content.
  */
  exportEntryData() {
    if (this.managementKeys.length < 1) {
      throw new Error('The DID must have at least one management key.');
    }

    if (!this.managementKeys.find(mk => mk.priority === 0)) {
      throw new Error('At least one management key must have priority 0.');
    }

    const content = Buffer.from(JSON.stringify(this._buildDIDDocument()), 'utf-8');
    const extIds = [
      Buffer.from(EntryType.Create, 'utf-8'),
      Buffer.from(ENTRY_SCHEMA_V100, 'utf-8'),
      this.nonce
    ];

    const entrySize = calculateEntrySize(extIds, content);
    if (entrySize > ENTRY_SIZE_LIMIT) {
      throw new Error('You have exceeded the entry size limit! Please remove some of your keys or services.');
    }

    return { extIds, content };
  }

  /**
  * Builds a DID Document.
  * @returns {Object} An object with the DID Document properties.
  */
  _buildDIDDocument() {
    let didDocument = {
      didMethodVersion: this.specVersion,
      managementKey: this.managementKeys.map(k => k.toEntryObj(this.id))
    };

    if (this.didKeys.length > 0) {
      didDocument.didKey = this.didKeys.map(k => k.toEntryObj(this.id));
    }

    if (this.services.length > 0) {
      didDocument.services = this.services.map(s => s.toEntryObj(this.id));
    }

    return didDocument;
  }

  /**
  * DID builder static factory.
  * @param {string} [specVersion] - Optional DID Method version.
  * @returns {DIDBuilder} A new DIDBuilder.
  */
  static builder(specVersion = DID_METHOD_SPEC_V020) {
    return new DIDBuilder(specVersion);
  }
}

/**
 * Class that enables the construction of a DID, by facilitating the construction of management keys and DID keys and the
    addition of services.
 * @param {string} specVersion - DID Method version.
 */
class DIDBuilder {
  constructor(specVersion) {
    this._id = this._generateDIDId();
    this._managementKeys = [];
    this._didKeys = [];
    this._services = [];
    this._network = undefined;
    this._specVersion = specVersion;

    this.usedKeyAliases = new Set();
    this.usedServiceAliases = new Set();
  }

  /**
  * Sets the DID network to mainnet.
  * @returns {DIDBuilder} - DIDBuilder instance.
  */
  mainnet() {
    this._network = Network.Mainnet;
    const chainId = this._id.split(":").slice(-1).pop();
    this._id = `${DID_METHOD_NAME}:${this._network}:${chainId}`;
    
    return this;
  }

  /**
  * Sets the DID network to testnet.
  * @returns {DIDBuilder} - DIDBuilder instance.
  */
  testnet() {
    this._network = Network.Testnet;
    const chainId = this._id.split(":").slice(-1).pop();
    this._id = `${DID_METHOD_NAME}:${this._network}:${chainId}`;

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
  managementKey(alias, priority, keyType = KeyType.EdDSA, controller, priorityRequirement) {
    if (!controller) {
      controller = this._id;
    }

    const key = new ManagementKey(alias, priority, keyType, controller, priorityRequirement);
    this._checkAliasIsUnique(this.usedKeyAliases, key.alias);
    this._managementKeys.push(key);
  
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
  didKey(alias, purpose, keyType = KeyType.EdDSA, controller, priorityRequirement) {
    if (!controller) {
      controller = this._id;
    }

    const key = new DIDKey(alias, purpose, keyType, controller, priorityRequirement);
    this._checkAliasIsUnique(this.usedKeyAliases, key.alias);
    this._didKeys.push(key);

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
  service(alias, serviceType, endpoint, priorityRequirement, customFields) {
    const service = new Service(alias, serviceType, endpoint, priorityRequirement, customFields);
    this._checkAliasIsUnique(this.usedServiceAliases, service.alias);
    this._services.push(service);
    
    return this;
  }

  /**
  * Build the DID.
  * @returns {DID} - Built DID.
  */
  build() {
    return new DID(this);
  }

  /**
  * Generates a new DID Id.
  * @returns {string} - A DID Id.
  */
  _generateDIDId() {
    this._nonce = crypto.randomBytes(32);
    const chainId = calculateChainId([EntryType.Create, ENTRY_SCHEMA_V100, this._nonce]);
    return `${DID_METHOD_NAME}:${chainId}`;
  }

  _checkAliasIsUnique(usedAliases, alias) {
    if (usedAliases.has(alias)) {
      throw new Error(`Duplicate alias "${alias}" detected.`)
    }

    usedAliases.add(alias);
  }
}

module.exports = {
  DID
};