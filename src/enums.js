const Network = {
  Mainnet: 'mainnet',
  Testnet: 'testnet'
}

const KeyType = {
  EdDSA: "Ed25519VerificationKey",
  ECDSA: "ECDSASecp256k1VerificationKey",
  RSA: "RSAVerificationKey"
}

const DIDKeyPurpose = {
  PublicKey: "publicKey",
  AuthenticationKey: "authenticationKey"
}

const EntryType = {
  Create: "DIDManagement"
}

module.exports = {
  Network,
  KeyType,
  DIDKeyPurpose,
  EntryType
}