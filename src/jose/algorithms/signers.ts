import { Signer } from '../types.js';
import { ed25519 } from './ed25519.js';
import { secp256k1 } from './secp256k1.js';

// the key should be the appropriate `crv` value
export const signers: { [key: string]: Signer } = {
  'Ed25519'   : ed25519,
  'secp256k1' : secp256k1,
};