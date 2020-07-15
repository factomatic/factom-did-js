import { createHash } from 'crypto';
import { EntryData } from './interfaces/EntryData';
import { EntryType } from './enums';
import { ENTRY_SCHEMA_V100 } from './constants';
import { DIDBuilder } from './did';
import { ManagementKey } from './keys/management';

/**
 * Facilitates the creation of a DIDDeactivation entry.
 * @param {DIDBuilder} didBuilder - The DID to deactivate.
 */
export class DIDDeactivator {
    private _didBuilder: DIDBuilder;
    private _signingKey: ManagementKey;

    constructor(didBuilder: DIDBuilder) {
        this._didBuilder = didBuilder;
        this._signingKey = this._didBuilder.managementKeys.sort(
            (a, b) => a.priority - b.priority
        )[0];

        if (this._signingKey.priority !== 0) {
            throw new Error(
                'Deactivation of a DID requires the availability of a management key with priority 0.'
            );
        }
    }

    exportEntryData(): EntryData {
        const signingKeyId = this._signingKey.fullId(this._didBuilder.id);
        const dataToSign = ''.concat(EntryType.Deactivation, ENTRY_SCHEMA_V100, signingKeyId);

        const sha256Hash = createHash('sha256');
        sha256Hash.update(Buffer.from(dataToSign));

        const signature = this._signingKey.sign(sha256Hash.digest());
        const extIds = [
            Buffer.from(EntryType.Deactivation),
            Buffer.from(ENTRY_SCHEMA_V100),
            Buffer.from(signingKeyId),
            Buffer.from(signature)
        ];

        /** The content of the DIDDeactivation entry is empty */
        return { extIds, content: Buffer.from('') };
    }
}
