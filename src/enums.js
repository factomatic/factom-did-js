const Network = {
  Mainnet: 'mainnet',
  Testnet: 'testnet',
  Unspecified: undefined
}

const KeyType = {
  EdDSA: 'Ed25519VerificationKey',
  ECDSA: 'ECDSASecp256k1VerificationKey',
  RSA: 'RSAVerificationKey'
}

const DIDKeyPurpose = {
  PublicKey: 'publicKey',
  AuthenticationKey: 'authenticationKey'
}

const EntryType = {
  Create: 'DIDManagement',
  Update: 'DIDUpdate',
  Deactivation: 'DIDDeactivation',
}

module.exports = {
  Network,
  KeyType,
  DIDKeyPurpose,
  EntryType
}