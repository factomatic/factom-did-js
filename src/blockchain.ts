import { createHash } from 'crypto';

/**
 * Calculates chain id by hashing each ExtID, joining the hashes into a byte array and hashing the array.
 * @param {Array} extIds - A list of ExtIDs.
 * @returns {string} - Calculated chain id.
 */
export function calculateChainId(extIds: Array<string | Buffer>): string {
    const extIdsHashBytes = extIds.reduce(function (
        total: Uint8Array,
        currentExtId: string | Buffer
    ) {
        const extIdHash = createHash('sha256');
        extIdHash.update(currentExtId);
        return Buffer.concat([total, extIdHash.digest()]);
    },
    Buffer.from([]));

    const fullHash = createHash('sha256');
    fullHash.update(extIdsHashBytes);

    return fullHash.digest('hex');
}

/**
 * Calculates entry size in bytes.
 * @param {Buffer[]} extIds
 * @param {Buffer} content
 * @returns {number} - Entry size.
 */
export function calculateEntrySize(extIds: Buffer[], content: Buffer): number {
    let totalEntrySize = 0;
    const fixedHeaderSize = 35;
    totalEntrySize += fixedHeaderSize + 2 * extIds.length;
    totalEntrySize += content.byteLength;

    extIds.forEach((extId) => {
        totalEntrySize += extId.byteLength;
    });

    return totalEntrySize;
}
