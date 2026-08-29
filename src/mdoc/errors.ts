// biome-ignore format: no explanation
export class MdlError extends Error {
  constructor(message: string = new.target.name) {
    super(message)
  }
}

export class MdlParseError extends MdlError {}
export class EitherSignatureOrMacMustBeProvidedError extends MdlError {}
export class AtLeastOneCertificateRequiredError extends MdlError {}
export class SignatureAlgorithmDoesNotMatchSigningKeyAlgorithmError extends MdlError {}
export class UnableToExtractX5ChainFromCwtError extends MdlError {}
export class NoPublicKeySetOnStatusListError extends MdlError {}
export class InvalidAlgorithmError extends MdlError {}
export class InvalidMessageAuthenticationCode extends MdlError {}
export class InvalidSignatureError extends MdlError {}
export class JwtNotSupportForStatusListError extends MdlError {}
export class TrustedRevocationCertificatesMustContainAtleastOneCertificateError extends MdlError {}
export class UnableToExtractX5ChainFromIdentifierListError extends MdlError {}
export class InvalidIdentifierListSignatureError extends MdlError {}
export class IdentifierFoundInRevokedListError extends MdlError {}

/**
 * ISO/IEC TS 18013-7:2025 C.5 requires the mdoc to abort when the DC API did not provide an origin,
 * as the session transcript — and thus the anti-relay binding — cannot be computed without it.
 */
export class MissingOriginError extends MdlError {}
export class HpkeNotSupportedError extends MdlError {}

/**
 * The request or response payload handed over the DC API did not have the shape Annex C defines.
 */
export class InvalidDcApiRequestError extends MdlError {}
export class InvalidDcApiResponseError extends MdlError {}
export class InvalidEncryptionInfoError extends MdlError {}
export class InvalidEncryptedResponseError extends MdlError {}
