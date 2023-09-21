import { DIDDocument } from "../did/types.js";

export function isValidDIDDocument(doc: any): doc is DIDDocument {
    if (!doc || typeof doc !== 'object') return false;
    if (!doc.id || typeof doc.id !== 'string') return false;

    const checkArrayItemsType = (arr: any[], type: string) => arr.every(item => typeof item === type);
    const checkVerificationMethodArray = (arr: any[]) => arr.every(item => typeof item === 'object');

    if (doc['@context'] && typeof doc['@context'] !== 'string' && !checkArrayItemsType(doc['@context'], 'string')) return false;
    if (doc.alsoKnownAs && !checkArrayItemsType(doc.alsoKnownAs, 'string')) return false;
    if (doc.controller && typeof doc.controller !== 'string' && !checkArrayItemsType(doc.controller, 'string')) return false;
    if (doc.verificationMethod && !checkVerificationMethodArray(doc.verificationMethod)) return false;
    if (doc.service && !checkVerificationMethodArray(doc.service)) return false;
    if (doc.authentication && (typeof doc.authentication !== 'string' && !checkArrayItemsType(doc.authentication, 'string') && !checkVerificationMethodArray(doc.authentication))) return false;
    if (doc.assertionMethod && (typeof doc.assertionMethod !== 'string' && !checkArrayItemsType(doc.assertionMethod, 'string') && !checkVerificationMethodArray(doc.assertionMethod))) return false;
    if (doc.keyAgreement && (typeof doc.keyAgreement !== 'string' && !checkArrayItemsType(doc.keyAgreement, 'string') && !checkVerificationMethodArray(doc.keyAgreement))) return false;
    if (doc.capabilityInvocation && (typeof doc.capabilityInvocation !== 'string' && !checkArrayItemsType(doc.capabilityInvocation, 'string') && !checkVerificationMethodArray(doc.capabilityInvocation))) return false;
    if (doc.capabilityDelegation && (typeof doc.capabilityDelegation !== 'string' && !checkArrayItemsType(doc.capabilityDelegation, 'string') && !checkVerificationMethodArray(doc.capabilityDelegation))) return false;

    return true;
}