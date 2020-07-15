import { createHash } from 'crypto';
import { EntryData } from './interfaces/EntryData';
import { EntryType } from './enums';
import { ENTRY_SCHEMA_V100 } from './constants';
import { DIDBuilder } from './did';

/**
 * Facilitates the creation of a DIDMethodVersionUpgrade entry for an existing DID.
 * @param {DIDBuilder} didBuilder
 * @param {string} newSpecVersion - The new version to upgrade to.
 */
export class DIDVersionUpgrader {
    private _didBuilder: DIDBuilder;
    private _newSpecVersion: string;

    constructor(didBuilder: DIDBuilder, newSpecVersion: string) {
        if (
            !newSpecVersion ||
            parseFloat(newSpecVersion) <= parseFloat(didBuilder.specVersion as string)
        ) {
            throw new Error('New version must be an upgrade on old version');
        }

        this._didBuilder = didBuilder;
        this._newSpecVersion = newSpecVersion;
    }

    exportEntryData(): EntryData {
        const signingKey = this._didBuilder.managementKeys.sort(
            (a, b) => a.priority - b.priority
        )[0];
        const signingKeyId = signingKey.fullId(this._didBuilder.id);
        const entryContent = JSON.stringify({ didMethodVersion: this._newSpecVersion });
        const dataToSign = ''.concat(
            EntryType.VersionUpgrade,
            ENTRY_SCHEMA_V100,
            signingKeyId,
            entryContent
        );

        const sha256Hash = createHash('sha256');
        sha256Hash.update(Buffer.from(dataToSign));

        const signature = signingKey.sign(sha256Hash.digest());
        const extIds = [
            Buffer.from(EntryType.VersionUpgrade),
            Buffer.from(ENTRY_SCHEMA_V100),
            Buffer.from(signingKeyId),
            Buffer.from(signature)
        ];

        return { extIds, content: Buffer.from(entryContent) };
    }
}
