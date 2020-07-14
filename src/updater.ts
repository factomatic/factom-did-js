import { calculateEntrySize } from './blockchain';
import { createHash } from 'crypto';
import { DIDBuilder } from './did';
import { DIDKey } from './keys/did';
import { DIDKeyPurpose, EntryType, KeyType } from './enums';
import { EntryData } from './interfaces/EntryData';
import { ENTRY_SCHEMA_V100, ENTRY_SIZE_LIMIT } from './constants';
import { ManagementKey } from './keys/management';
import { Service } from './service';

/**
 * Facilitates the creation of an update entry for an existing DID.
 * Provides support for adding and revoking management keys, DID keys and services.
 * @param {DIDBuilder} didBuilder
 */
export class DIDUpdater {
    private _didBuilder: DIDBuilder;
    private _originalManagementKeys: ManagementKey[];
    private _originalDIDKeys: DIDKey[];
    private _originalServices: Service[];
    private _didKeyPurposesToRevoke: any;

    constructor(didBuilder: DIDBuilder) {
        this._didBuilder = didBuilder;
        this._originalManagementKeys = [...this._didBuilder.managementKeys];
        this._originalDIDKeys = [...this._didBuilder.didKeys];
        this._originalServices = [...this._didBuilder.services];
        this._didKeyPurposesToRevoke = {};
    }

    /**
     * @returns {ManagementKey[]} The current state of management keys.
     */
    get managementKeys(): ManagementKey[] {
        return this._didBuilder.managementKeys;
    }

    /**
     * @returns {DIDKey[]} The current state of DID keys.
     */
    get didKeys(): DIDKey[] {
        /** Apply revocation of DID key purposes */
        const didKeys: DIDKey[] = [];
        this._didBuilder.didKeys.forEach((key) => {
            let revoked = false;
            Object.keys(this._didKeyPurposesToRevoke).forEach((alias) => {
                if (alias === key.alias) {
                    const revokedPurpose = this._didKeyPurposesToRevoke[alias];
                    const remainingPurpose =
                        revokedPurpose === DIDKeyPurpose.PublicKey
                            ? DIDKeyPurpose.AuthenticationKey
                            : DIDKeyPurpose.PublicKey;

                    didKeys.push(
                        new DIDKey(
                            key.alias,
                            remainingPurpose,
                            key.keyType,
                            key.controller,
                            key.priorityRequirement,
                            key.publicKey,
                            key.privateKey
                        )
                    );
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
    get services(): Service[] {
        return this._didBuilder.services;
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
    addManagementKey(
        alias: string,
        priority: number,
        keyType: KeyType = KeyType.EdDSA,
        controller?: string,
        priorityRequirement?: number
    ): this {
        this._didBuilder.managementKey(alias, priority, keyType, controller, priorityRequirement);
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
    addDIDKey(
        alias: string,
        purpose: DIDKeyPurpose | DIDKeyPurpose[],
        keyType: KeyType = KeyType.EdDSA,
        controller?: string,
        priorityRequirement?: number
    ): this {
        this._didBuilder.didKey(alias, purpose, keyType, controller, priorityRequirement);
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
    addService(
        alias: string,
        serviceType: string,
        endpoint: string,
        priorityRequirement?: number,
        customFields?: any
    ): this {
        this._didBuilder.service(alias, serviceType, endpoint, priorityRequirement, customFields);
        return this;
    }

    /**
     * Revokes a management key from the DIDBuilder object.
     * @param {string} alias - The alias of the key to be revoked
     * @returns {DIDUpdater}
     */
    revokeManagementKey(alias: string): this {
        this._didBuilder.managementKeys = this._didBuilder.managementKeys.filter(
            (k) => k.alias !== alias
        );
        return this;
    }

    /**
     * Revokes a DID key from the DIDBuilder object.
     * @param {string} alias - The alias of the key to be revoked
     * @returns {DIDUpdater}
     */
    revokeDIDKey(alias: string): this {
        this._didBuilder.didKeys = this._didBuilder.didKeys.filter((k) => k.alias !== alias);
        return this;
    }

    /**
     * Revokes a single purpose of a DID key from the DIDBuilder object.
     * @param {string} alias - The alias of the key to be revoked
     * @param {DIDKeyPurpose} purpose - The purpose to revoke
     * @returns {DIDUpdater}
     */
    revokeDIDKeyPurpose(alias: string, purpose: DIDKeyPurpose): this {
        if (![DIDKeyPurpose.AuthenticationKey, DIDKeyPurpose.PublicKey].includes(purpose)) {
            return this;
        }

        const didKey = this._didBuilder.didKeys.find((k) => k.alias === alias);
        if (!didKey) {
            return this;
        }

        if (!didKey.purpose.includes(purpose)) {
            return this;
        }

        if (didKey.purpose.length === 1) {
            return this.revokeDIDKey(alias);
        } else {
            this._didKeyPurposesToRevoke[alias] = purpose;
            return this;
        }
    }

    /**
     * Revokes a service from the DIDBuilder object.
     * @param {string} alias - The alias of the service to be revoked
     * @returns {DIDUpdater}
     */
    revokeService(alias: string): this {
        this._didBuilder.services = this._didBuilder.services.filter((s) => s.alias !== alias);
        return this;
    }

    /**
     * Rotates a management key.
     * @param {string} alias - The alias of the management key to be rotated
     * @returns {DIDUpdater}
     */
    rotateManagementKey(alias: string): this {
        const managementKey = this._didBuilder.managementKeys.find((k) => k.alias === alias);
        if (managementKey) {
            this._didBuilder.managementKeys = this._didBuilder.managementKeys.filter(
                (k) => k.alias !== alias
            );
            const managementKeyClone = Object.assign({}, managementKey);
            Object.setPrototypeOf(managementKeyClone, ManagementKey.prototype);

            managementKeyClone.rotate();
            this._didBuilder.managementKeys.push(managementKeyClone);
        }

        return this;
    }

    /**
     * Rotates a DID key.
     * @param {string} alias - The alias of the DID key to be rotated
     * @returns {DIDUpdater}
     */
    rotateDIDKey(alias: string): this {
        const didKey = this._didBuilder.didKeys.find((k) => k.alias === alias);
        if (didKey) {
            this._didBuilder.didKeys = this._didBuilder.didKeys.filter((k) => k.alias !== alias);
            const didKeyClone = Object.assign({}, didKey);
            Object.setPrototypeOf(didKeyClone, DIDKey.prototype);

            didKeyClone.rotate();
            this._didBuilder.didKeys.push(didKeyClone);
        }

        return this;
    }

    exportEntryData(): EntryData {
        if (!this._didBuilder.managementKeys.some((k) => k.priority === 0)) {
            throw new Error('DIDUpdate entry would leave no management keys of priority zero.');
        }

        const newMgmtKeysResult = this._getNew(
            this._originalManagementKeys,
            this._didBuilder.managementKeys
        );
        const newDIDKeysResult = this._getNew(this._originalDIDKeys, this._didBuilder.didKeys);
        const newServicesResult = this._getNew(this._originalServices, this._didBuilder.services);
        const revokedMgmtKeysResult = this._getRevoked(
            this._originalManagementKeys,
            this._didBuilder.managementKeys
        );
        const revokedDIDKeysResult = this._getRevoked(
            this._originalDIDKeys,
            this._didBuilder.didKeys
        );
        const revokedServicesResult = this._getRevoked(
            this._originalServices,
            this._didBuilder.services
        );

        const addObject = this._constructAddObject(
            newMgmtKeysResult.new as ManagementKey[],
            newDIDKeysResult.new as DIDKey[],
            newServicesResult.new as Service[]
        );
        const revokeObject = this._constructRevokeObject(
            revokedMgmtKeysResult.revoked,
            revokedDIDKeysResult.revoked,
            revokedServicesResult.revoked
        );

        Object.keys(this._didKeyPurposesToRevoke).forEach((alias) => {
            try {
                revokeObject['didKey'].push({
                    id: `${this._didBuilder.id}#${alias}`,
                    purpose: [this._didKeyPurposesToRevoke[alias]],
                });
            } catch (e) {
                revokeObject['didKey'] = [
                    {
                        id: `${this._didBuilder.id}#${alias}`,
                        purpose: [this._didKeyPurposesToRevoke[alias]],
                    },
                ];
            }
        });

        const updateEntryContent: any = {};
        if (Object.keys(addObject).length > 0) {
            updateEntryContent['add'] = addObject;
        }

        if (Object.keys(revokeObject).length > 0) {
            updateEntryContent['revoke'] = revokeObject;
        }

        if (Object.keys(updateEntryContent).length === 0) {
            throw new Error('The are no changes made to the DID.');
        }

        const signingKey = this._originalManagementKeys.sort((a, b) => a.priority - b.priority)[0];

        /**
         *  Currently unreachable code!
         *  const updateKeyRequiredPriority = Math.min(
         *      newMgmtKeysResult.requiredPriorityForUpdate,
         *      revokedMgmtKeysResult.requiredPriorityForUpdate,
         *      revokedDIDKeysResult.requiredPriorityForUpdate,
         *      revokedServicesResult.requiredPriorityForUpdate
         *  );
         *
         *  if (signingKey.priority > updateKeyRequiredPriority) {
         *    throw new Error(
         *      `The update requires a key with priority <= ${updateKeyRequiredPriority}, but the highest priority
         *      key available is with priority ${signingKey.priority}`
         *    );
         *  }
         */

        const signingKeyId = signingKey.fullId(this._didBuilder.id);
        const entryContent = JSON.stringify(updateEntryContent);
        const dataToSign = ''.concat(
            EntryType.Update,
            ENTRY_SCHEMA_V100,
            signingKeyId,
            entryContent
        );

        const sha256Hash = createHash('sha256');
        sha256Hash.update(Buffer.from(dataToSign));

        const signature = signingKey.sign(sha256Hash.digest());
        const extIds = [
            Buffer.from(EntryType.Update),
            Buffer.from(ENTRY_SCHEMA_V100),
            Buffer.from(signingKeyId),
            Buffer.from(signature),
        ];

        const entrySize = calculateEntrySize(extIds, Buffer.from(entryContent));
        if (entrySize > ENTRY_SIZE_LIMIT) {
            throw new Error('You have exceeded the entry size limit!');
        }

        return { extIds, content: Buffer.from(entryContent) };
    }

    private _getNew(original: any[], current: any[]) {
        const _new: any[] = [];
        let requiredPriorityForUpdate = Number.POSITIVE_INFINITY;
        const originalStrArray = original.map((e) => JSON.stringify(e));

        current.forEach((obj) => {
            if (!originalStrArray.includes(JSON.stringify(obj))) {
                _new.push(obj.toEntryObj(this._didBuilder.id));

                if (obj.priority && obj.priority < requiredPriorityForUpdate) {
                    requiredPriorityForUpdate = obj.priority;
                }
            }
        });

        return { new: _new, requiredPriorityForUpdate };
    }

    private _getRevoked(original: any[], current: any[]) {
        const revoked: any[] = [];
        let requiredPriorityForUpdate = Number.POSITIVE_INFINITY;
        const currentStrArray = current.map((e) => JSON.stringify(e));

        original.forEach((obj) => {
            if (!currentStrArray.includes(JSON.stringify(obj))) {
                revoked.push({ id: `${this._didBuilder.id}#${obj.alias}` });

                if (
                    obj.priorityRequirement &&
                    obj.priorityRequirement < requiredPriorityForUpdate
                ) {
                    requiredPriorityForUpdate = obj.priorityRequirement;
                }

                if (
                    obj.priority &&
                    !obj.priorityRequirement &&
                    obj.priority < requiredPriorityForUpdate
                ) {
                    requiredPriorityForUpdate = obj.priority;
                }
            }
        });

        return { revoked, requiredPriorityForUpdate };
    }

    private _constructAddObject(
        newManagementKeys: ManagementKey[],
        newDidKeys: DIDKey[],
        newServices: Service[]
    ) {
        const add: any = {};

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

    private _constructRevokeObject(
        revokedManagementKeys: any[],
        revokedDidKeys: any[],
        revokedServices: any[]
    ) {
        const revoke: any = {};

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
