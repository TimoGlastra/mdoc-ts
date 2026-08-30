import {
  CborStructure,
  ProtectedHeaders,
  RegisteredCwtHeaderClaimKey,
  type SignatureAlgorithm,
  TypedMap,
  typedMap,
  zUint8Array,
} from '@owf/cose'
import z from 'zod'

/**
 * COSE header parameters not yet exposed by `@owf/cose`'s
 * `RegisteredCwtHeaderClaimKey`. Inline pending an upstream addition.
 */
export enum IdentifierListCwtHeaderKey {
  /** `typ`, RFC 9596. A COSE *header* parameter, not a CWT claim. */
  Typ = 16,
}

/** CWT content type strings used by ISO 18013-5 revocation lists. */
export enum MediaTypes {
  IdentifierListCwt = 'application/identifierlist+cwt',
}

// § 12.3.6.4: "The value of the type claim shall be
// 'application/identifierlist+cwt'". `typ` is a COSE header parameter
// (RFC 9596, label 16), not a CWT claim — the same place
// `@owf/token-status-list` writes it on a status list CWT.
const typError = `Typ (protected header 16) shall be '${MediaTypes.IdentifierListCwt}' (ISO 18013-5 § 12.3.6.4)`

const identifierListCwtHeaderSchema = typedMap(
  [
    [RegisteredCwtHeaderClaimKey.Algorithm, z.union([z.string(), z.number()]).exactOptional()],
    // ISO 18013-5 § 12.3.6.3: the signing certificate chain travels in the
    // protected header. Optional here so a chain-less CWT fails with
    // `UnableToExtractX5ChainFromIdentifierListError` rather than a decode error.
    [RegisteredCwtHeaderClaimKey.X5Chain, z.union([zUint8Array, z.array(zUint8Array)]).exactOptional()],
    // Declared optional so that a missing `typ` is reported by the check below
    // rather than by `typedMap`'s generic "expected key '16' to be defined".
    [IdentifierListCwtHeaderKey.Typ, z.literal(MediaTypes.IdentifierListCwt, { error: typError }).exactOptional()],
  ],
  { allowAdditionalKeys: true }
).check((ctx) => {
  if (ctx.value.get(IdentifierListCwtHeaderKey.Typ) === undefined) {
    ctx.issues.push({
      code: 'custom',
      input: ctx.value,
      message: `${typError}, but the protected header has no typ`,
    })
  }
})

export type IdentifierListCwtHeaderEncodedStructure = z.input<typeof identifierListCwtHeaderSchema>
export type IdentifierListCwtHeaderDecodedStructure = z.output<typeof identifierListCwtHeaderSchema>

export type CreateIdentifierListCwtHeaderOptions = {
  algorithm?: SignatureAlgorithm
  x5chain?: Array<Uint8Array>
}

/**
 * Protected header of an `IdentifierListCwt` (ISO/IEC 18013-5 second edition
 * § 12.3.6). Counterpart to `IdentifierListCwtPayload`.
 */
export class IdentifierListCwtHeader extends CborStructure<
  IdentifierListCwtHeaderEncodedStructure,
  IdentifierListCwtHeaderDecodedStructure
> {
  public static override get encodingSchema() {
    return identifierListCwtHeaderSchema
  }

  /** Validate a decoded COSE protected header as an identifier list header. */
  public static fromProtectedHeaders(
    protectedHeaders: ProtectedHeaders | Map<number, unknown> | undefined
  ): IdentifierListCwtHeader {
    const headers = protectedHeaders instanceof ProtectedHeaders ? protectedHeaders.headers.toMap() : protectedHeaders
    return IdentifierListCwtHeader.fromEncodedStructure(
      (headers ?? new Map()) as IdentifierListCwtHeaderEncodedStructure
    )
  }

  public static create(options: CreateIdentifierListCwtHeaderOptions = {}): IdentifierListCwtHeader {
    const map: IdentifierListCwtHeaderDecodedStructure = new TypedMap([
      [IdentifierListCwtHeaderKey.Typ, MediaTypes.IdentifierListCwt],
    ])
    if (options.algorithm !== undefined) {
      map.set(RegisteredCwtHeaderClaimKey.Algorithm, options.algorithm)
    }
    if (options.x5chain !== undefined) {
      map.set(RegisteredCwtHeaderClaimKey.X5Chain, options.x5chain)
    }
    return IdentifierListCwtHeader.fromDecodedStructure(map)
  }

  public get typ(): MediaTypes.IdentifierListCwt {
    // Optional in the map, but the schema's check rejects a header without it.
    return this.structure.get(IdentifierListCwtHeaderKey.Typ) as MediaTypes.IdentifierListCwt
  }

  public get algorithm(): SignatureAlgorithm | undefined {
    return this.structure.get(RegisteredCwtHeaderClaimKey.Algorithm) as SignatureAlgorithm | undefined
  }

  /** Leaf cert + chain from the `x5chain` header, normalized to an array. */
  public get x5chain(): Array<Uint8Array> | undefined {
    const x5c = this.structure.get(RegisteredCwtHeaderClaimKey.X5Chain)
    return x5c instanceof Uint8Array ? [x5c] : x5c
  }
}
