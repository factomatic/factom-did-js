const { DID_METHOD_NAME } = require('./constants'),
  { KeyType, Network } = require('./enums');

function validateAlias(alias) {
  const regex = new RegExp('^[a-z0-9-]{1,32}$');
  if (!regex.test(alias)) {
    throw new Error('Alias must not be more than 32 characters long and must contain only lower-case letters, digits and hyphens.');
  }
}

function validateKeyType(keyType) {
  if (![KeyType.EdDSA, KeyType.ECDSA, KeyType.RSA].includes(keyType)) {
    throw new Error('Type must be a valid signature type.');
  }
}

function validateDIDId(didId) {
  const regex = new RegExp(`^${DID_METHOD_NAME}:(${Network.Mainnet}:|${Network.Testnet}:)?[a-f0-9]{64}$`);
  if (!regex.test(didId)) {
    throw new Error('Controller must be a valid DID Id.');
  }
}

function validatePriorityRequirement(priorityRequirement) {
  if (priorityRequirement !== undefined
    && (!Number.isInteger(priorityRequirement) || priorityRequirement < 0)) {
    throw new Error('Priority requirement must be a non-negative integer.');
  }
}

function validateServiceEndpoint(endpoint) {
  const regex = new RegExp(/^(http|https):\/\/(\w+:{0,1}\w*@)?(\S+)(:[0-9]+)?(\/|\/([\w#!:.?+=&%@!\-\/]))?$/);
  if (!regex.test(endpoint)) {
    throw new Error('Endpoint must be a valid URL address starting with http:// or https://.');
  }
}

module.exports = {
  validateAlias,
  validateKeyType,
  validateDIDId,
  validatePriorityRequirement,
  validateServiceEndpoint
};

