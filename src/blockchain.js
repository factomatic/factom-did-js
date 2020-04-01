const crypto = require('crypto');

/**
 * Calculates chain id by hashing each ExtID, joining the hashes into a byte array and hashing the array.
 * @param {Array} extIds - A list of ExtIDs.
*/
function calculateChainId(extIds) {
  const extIdsHashBytes = extIds.reduce(function (total, currentExtId) {
    const extIdHash = crypto.createHash('sha256');
    extIdHash.update(currentExtId);
    return Buffer.concat([total, extIdHash.digest()]);
  }, Buffer.from([]));

  const fullHash = crypto.createHash('sha256');
  fullHash.update(extIdsHashBytes);

  return fullHash.digest('hex');
}

/**
 * Calculates entry size in bytes.
 * @param {Buffer[]} extIds
 * @param {Buffer} content
*/
function calculateEntrySize(extIds, content) {
  let totalEntrySize = 0;
  const fixedHeaderSize = 35;
  totalEntrySize += fixedHeaderSize + 2 * extIds.length;
  totalEntrySize += content.byteLength;

  extIds.forEach(extId => {
    totalEntrySize += extId.byteLength;
  });

  return totalEntrySize;
}

module.exports = {
  calculateChainId,
  calculateEntrySize
};