const { calculateEntrySize } = require('./blockchain'),
  { createHash } = require('crypto'),
  { DIDKey } = require('./keys/did'),
  { DIDKeyPurpose, EntryType, KeyType } = require('./enums'),
  { ENTRY_SCHEMA_V100, ENTRY_SIZE_LIMIT } = require('./constants'),
  { ManagementKey } = require('./keys/management');

/**
 * Facilitates the creation of an update entry for an existing DID.
 * Provides support for adding and revoking management keys, DID keys and services.
 * @param {DIDBuilder} didBuilder
 */
class DIDUpdater {
  constructor(didBuilder) {
    this.didBuilder = didBuilder;
    this.originalManagementKeys = [...this.didBuilder._managementKeys];
    this.originalDIDKeys = [...this.didBuilder._didKeys];
    this.originalServices = [...this.didBuilder._services];
    this.didKeyPurposesToRevoke = {};
  }

  /**
  * @returns {ManagementKey[]} The current state of management keys.
  */
  get managementKeys() {
    return this.didBuilder._managementKeys;
  }

  /**
  * @returns {DIDKey[]} The current state of DID keys.
  */
  get didKeys() {
    /** Apply revocation of DID key purposes */
    let didKeys = [];
    this.didBuilder._didKeys.forEach(key => {
      let revoked = false;
      Object.keys(this.didKeyPurposesToRevoke).forEach(alias => {
        if (alias === key.alias) {
          const revokedPurpose = this.didKeyPurposesToRevoke[alias];
          const remainingPurpose = revokedPurpose === DIDKeyPurpose.PublicKey 
            ? DIDKeyPurpose.AuthenticationKey
            : DIDKeyPurpose.PublicKey;

          didKeys.push(new DIDKey(key.alias, remainingPurpose, key.keyType, key.controller, key.priorityRequirement, key.publicKey, key.privateKey));
          revoked = true;
          return;
        }
      });

      if (!revoked) {
        didKeys.push(key);
      }
    });

    return didKeys;
  }

  /**
  * @returns {Services[]} The current state of services.
  */
  get services() {
    return this.didBuilder._services;
  }

  /**
  * Adds a management key to the DIDBuilder object.
  * @param {string} alias
  * @param {number} priority
  * @param {KeyType} [keyType]
  * @param {string} [controller]
  * @param {number} [priorityRequirement]
  * @returns {DIDUpdater} - DIDUpdater instance.
  */
  addManagementKey(alias, priority, keyType = KeyType.EdDSA, controller, priorityRequirement) {
    this.didBuilder.managementKey(alias, priority, keyType, controller, priorityRequirement);
    return this;
  }

  /**
  * Adds a DID key to the DIDBuilder object.
  * @param {string} alias
  * @param {DIDKeyPurpose | DIDKeyPurpose[]} purpose
  * @param {KeyType} [keyType]
  * @param {string} [controller]
  * @param {number} [priorityRequirement]
  * @returns {DIDUpdater} - DIDUpdater instance.
  */
  addDIDKey(alias, purpose, keyType = KeyType.EdDSA, controller, priorityRequirement) {
    this.didBuilder.didKey(alias, purpose, keyType, controller, priorityRequirement);
    return this;
  }

  /**
  * Adds a new service to the DIDBuilder object.
  * @param {string} alias
  * @param {string} serviceType
  * @param {string} endpoint
  * @param {number} [priorityRequirement]
  * @param {Object} [customFields]
  * @returns {DIDUpdater}
  */
  addService(alias, serviceType, endpoint, priorityRequirement, customFields) {
    this.didBuilder.service(alias, serviceType, endpoint, priorityRequirement, customFields);
    return this;
  }

  /**
  * Revokes a management key from the DIDBuilder object.
  * @param {string} alias - The alias of the key to be revoked
  * @returns {DIDUpdater}
  */
  revokeManagementKey(alias) {
    this.didBuilder._managementKeys = this.didBuilder._managementKeys.filter(k => k.alias !== alias);
    return this;
  }

  /**
  * Revokes a DID key from the DIDBuilder object.
  * @param {string} alias - The alias of the key to be revoked
  * @returns {DIDUpdater}
  */
  revokeDIDKey(alias) {
    this.didBuilder._didKeys = this.didBuilder._didKeys.filter(k => k.alias !== alias);
    return this;
  }

  /**
  * Revokes a single purpose of a DID key from the DIDBuilder object.
  * @param {string} alias - The alias of the key to be revoked
  * @param {DIDKeyPurpose} purpose - The purpose to revoke
  * @returns {DIDUpdater}
  */
  revokeDIDKeyPurpose(alias, purpose) {
    if (![DIDKeyPurpose.AuthenticationKey, DIDKeyPurpose.PublicKey].includes(purpose)) {
      return this;
    }

    const didKey = this.didBuilder._didKeys.find(k => k.alias === alias);
    if (!didKey) {
      return this;
    }

    if (!didKey.purpose.includes(purpose)) {
      return this;
    }

    if (didKey.purpose.length === 1) {
      return this.revokeDIDKey(alias);
    } else {
      this.didKeyPurposesToRevoke[alias] = purpose;
      return this;
    }
  }

  /**
  * Revokes a service from the DIDBuilder object.
  * @param {string} alias - The alias of the service to be revoked
  * @returns {DIDUpdater}
  */
  revokeService(alias) {
    this.didBuilder._services = this.didBuilder._services.filter(k => k.alias !== alias);
    return this;
  }

  /**
  * Rotates a management key.
  * @param {string} alias - The alias of the management key to be rotated
  * @returns {DIDUpdater}
  */
  rotateManagementKey(alias) {
    const managementKey = this.didBuilder._managementKeys.find(k => k.alias === alias);
    if (managementKey) {
      this.didBuilder._managementKeys = this.didBuilder._managementKeys.filter(k => k.alias !== alias);
      const managementKeyClone = Object.assign( {}, managementKey);
      Object.setPrototypeOf(managementKeyClone, ManagementKey.prototype);

      managementKeyClone.rotate();
      this.didBuilder._managementKeys.push(managementKeyClone);
    }

    return this;
  }

  /**
  * Rotates a DID key.
  * @param {string} alias - The alias of the DID key to be rotated
  * @returns {DIDUpdater}
  */
  rotateDIDKey(alias) {
    const didKey = this.didBuilder._didKeys.find(k => k.alias === alias);
    if (didKey) {
      this.didBuilder._didKeys = this.didBuilder._didKeys.filter(k => k.alias !== alias);
      const didKeyClone = Object.assign( {}, didKey);
      Object.setPrototypeOf(didKeyClone, DIDKey.prototype);

      didKeyClone.rotate();
      this.didBuilder._didKeys.push(didKeyClone);
    }

    return this;
  }

  exportEntryData() {
    if (!this.didBuilder._managementKeys.some(k => k.priority === 0)) {
      throw new Error('DIDUpdate entry would leave no management keys of priority zero.');
    }

    const newMgmtKeysResult = this._getNew(this.originalManagementKeys, this.didBuilder._managementKeys);
    const newDIDKeysResult = this._getNew(this.originalDIDKeys, this.didBuilder._didKeys);
    const newServicesResult = this._getNew(this.originalServices, this.didBuilder._services);
    const revokedMgmtKeysResult = this._getRevoked(this.originalManagementKeys, this.didBuilder._managementKeys);
    const revokedDIDKeysResult = this._getRevoked(this.originalDIDKeys, this.didBuilder._didKeys);
    const revokedServicesResult = this._getRevoked(this.originalServices, this.didBuilder._services);

    const addObject = this._constructAddObject(newMgmtKeysResult.new, newDIDKeysResult.new, newServicesResult.new);
    const revokeObject = this._constructRevokeObject(revokedMgmtKeysResult.revoked, revokedDIDKeysResult.revoked, revokedServicesResult.revoked);

    Object.keys(this.didKeyPurposesToRevoke).forEach(alias => {
      try {
        revokeObject['didKey'].push({id: `${this.didBuilder._id}#${alias}`, purpose: [this.didKeyPurposesToRevoke[alias]]});
      } catch {
        revokeObject['didKey'] = [{id: `${this.didBuilder._id}#${alias}`, purpose: [this.didKeyPurposesToRevoke[alias]]}];
      }
    });

    const updateEntryContent = {};
    if (Object.keys(addObject).length > 0) {
      updateEntryContent['add'] = addObject;
    }

    if (Object.keys(revokeObject).length > 0) {
      updateEntryContent['revoke'] = revokeObject;
    }

    if (Object.keys(updateEntryContent).length === 0) {
      throw new Error('The are no changes made to the DID.');
    }

    const updateKeyRequiredPriority = Math.min(
      newMgmtKeysResult.requiredPriorityForUpdate,
      revokedMgmtKeysResult.requiredPriorityForUpdate,
      revokedDIDKeysResult.requiredPriorityForUpdate,
      revokedServicesResult.requiredPriorityForUpdate
    );

    const signingKey = this.originalManagementKeys.sort((a, b) => a.priority - b.priority)[0];
    /**
     * Currently unreachable code!
      if (signingKey.priority > updateKeyRequiredPriority) {
        throw new Error(
          `The update requires a key with priority <= ${updateKeyRequiredPriority}, but the highest priority
          key available is with priority ${signingKey.priority}`
        );
      }
    */

    const signingKeyId = signingKey.fullId(this.didBuilder._id);
    const entryContent = JSON.stringify(updateEntryContent);
    const dataToSign = "".concat(EntryType.Update, ENTRY_SCHEMA_V100, signingKeyId, entryContent);

    const sha256Hash = createHash('sha256');
    sha256Hash.update(Buffer.from(dataToSign));

    const signature = signingKey.sign(sha256Hash.digest());
    const extIds = [
      Buffer.from(EntryType.Update),
      Buffer.from(ENTRY_SCHEMA_V100),
      Buffer.from(signingKeyId),
      Buffer.from(signature)
    ];

    const entrySize = calculateEntrySize(extIds, Buffer.from(entryContent));
    if (entrySize > ENTRY_SIZE_LIMIT) {
      throw new Error('You have exceeded the entry size limit!');
    }

    return {extIds, content: Buffer.from(entryContent)};
  }

  _getNew(original, current) {
    let _new = [];
    let requiredPriorityForUpdate = Number.POSITIVE_INFINITY;
    const originalStrArray = original.map(e => JSON.stringify(e));

    current.forEach(obj => {
      if (!originalStrArray.includes(JSON.stringify(obj))) {
        _new.push(obj.toEntryObj(this.didBuilder._id));

        if (obj.priority && obj.priority < requiredPriorityForUpdate) {
          requiredPriorityForUpdate = obj.priority;
        }
      }
    });

    return {new: _new, requiredPriorityForUpdate};
  }

  _getRevoked(original, current) {
    let revoked = [];
    let requiredPriorityForUpdate = Number.POSITIVE_INFINITY;
    const currentStrArray = current.map(e => JSON.stringify(e));

    original.forEach(obj => {
      if (!currentStrArray.includes(JSON.stringify(obj))) {
        revoked.push({ id: `${this.didBuilder._id}#${obj.alias}` });

        if (obj.priorityRequirement && obj.priorityRequirement < requiredPriorityForUpdate) {
          requiredPriorityForUpdate = obj.priorityRequirement;
        }

        if (obj.priority && !obj.priorityRequirement && obj.priority < requiredPriorityForUpdate) {
          requiredPriorityForUpdate = obj.priority;
        }
      }
    });

    return {revoked, requiredPriorityForUpdate};
  }

  _constructAddObject(newManagementKeys, newDidKeys, newServices) {
    const add = {};

    if (newManagementKeys.length > 0) {
      add['managementKey'] = newManagementKeys;
    }

    if (newDidKeys.length > 0) {
      add['didKey'] = newDidKeys;
    }

    if (newServices.length > 0) {
      add['service'] = newServices;
    }

    return add;
  }

  _constructRevokeObject(revokedManagementKeys, revokedDidKeys, revokedServices) {
    const revoke = {};

    if (revokedManagementKeys.length > 0) {
      revoke['managementKey'] = revokedManagementKeys;
    }

    if (revokedDidKeys.length > 0) {
      revoke['didKey'] = revokedDidKeys;
    }

    if (revokedServices.length > 0) {
      revoke['service'] = revokedServices;
    }

    return revoke;
  }
}

module.exports = {
  DIDUpdater
};