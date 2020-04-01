const { AbstractDIDKey } = require('./abstract'),
  { ENTRY_SCHEMA_V100 } = require('../constants');

class ManagementKey extends AbstractDIDKey {
  constructor (alias, priority, keyType, controller, priorityRequirement) {
    super(alias, keyType, controller, priorityRequirement);

    if (!Number.isInteger(priority) || priority < 0) {
      throw new Error('Priority must be a non-negative integer.');
    }

    this.priority = priority;
  }

  toEntryObj(didId, version=ENTRY_SCHEMA_V100) {
    let entryObj = super.toEntryObj(didId, version);
    entryObj['priority'] = this.priority;
    return entryObj;
  }
}

module.exports = {
  ManagementKey
};