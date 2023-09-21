import { sign } from "./sign.js"
import { verify, verifyWithPublicKey } from "./verify.js"
import { DidWebResolver } from "./did/did-web-resolver.js"
import { DidKeyResolver } from "./did/did-key-resolver.js"
import { DidResolver } from "./did/did-resolver.js"
import { DIDDocument } from "./did/types.js"
import { isValidDIDDocument } from "./utils/didDoc.js"
import { ALGS } from "./jose/types.js"

export { sign, verify, verifyWithPublicKey, DidResolver, DidWebResolver, DidKeyResolver, DIDDocument, isValidDIDDocument, ALGS}






