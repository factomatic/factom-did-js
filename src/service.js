const { ENTRY_SCHEMA_V100 } = require('./constants'),
  { validateAlias, validateServiceEndpoint, validatePriorityRequirement } = require('./validators');

/**
 * Class representing a service associated with a DID. A service is an end-point, which can be used to communicate with the DID
 * or to carry out different tasks on behalf of the DID (such as signatures, e.g.)
 * @property {string} alias - A human-readable nickname for the service endpoint.
 * @property {string} serviceType - Type of the service endpoint (e.g. email, credential store).
 * @property {string} endpoint - A service endpoint may represent any type of service the subject wishes to advertise,
 *   including decentralized identity management services for further discovery, authentication, authorization, or interaction.
 *   The service endpoint must be a valid URL.
 * @property {number} priorityRequirement - An optional non-negative integer showing the minimum hierarchical level a key must have
 *   in order to remove this service.
 * @property {Object} customFields - An optional object containing custom fields (e.g "description": "My public social inbox").
 */
class Service {
  constructor(alias, serviceType, endpoint, priorityRequirement, customFields) {
    this._validateInputParams(alias, serviceType, endpoint, priorityRequirement, customFields);

    this.alias = alias;
    this.serviceType = serviceType;
    this.endpoint = endpoint;
    this.priorityRequirement = priorityRequirement;
    this.customFields = customFields;
  }

  /**
   * Builds an object suitable for recording on-chain.
   * @param {string} didId - The DID to which this service belongs.
   * @param {string} version - The entry schema version
   * @returns {Object} An object with `id`, `type`, `serviceType` and an optional `priorityRequirement` properties.
  */
  toEntryObj(didId, version=ENTRY_SCHEMA_V100) {
    if (version == ENTRY_SCHEMA_V100) {
      let entryObj = {
        id: this._fullId(didId),
        type: this.serviceType,
        serviceEndpoint: this.endpoint
      };
  
      if (this.priorityRequirement !== undefined) {
        entryObj['priorityRequirement'] = this.priorityRequirement;
      }

      if (this.customFields !== undefined) {
        Object.keys(this.customFields).forEach(customFieldKey => {
          entryObj[customFieldKey] = this.customFields[customFieldKey];
        });
      }
  
      return entryObj;
    }
  
    throw new Error(`Unknown schema version: ${version}`);
  }

  /**
   * Constructs the full ID of the key.
   * @param {string} didId
   * @returns {string}
  */
  _fullId(didId) {
    return `${didId}#${this.alias}`;
  }

  _validateInputParams(alias, serviceType, endpoint, priorityRequirement, customFields) {
    validateAlias(alias);
    validateServiceEndpoint(endpoint);
    validatePriorityRequirement(priorityRequirement);

    if (serviceType === undefined || serviceType.length === 0) {
      throw new Error('Service type is required!');
    }

    if (customFields !== undefined && typeof customFields !== 'object') {
      throw new Error('Custom fields must be an object!');
    }
  }
}

module.exports = {
  Service
};