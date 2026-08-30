import { ProtectedHeaders, RegisteredCwtHeaderClaimKey, Sign1, SignatureAlgorithm, UnprotectedHeaders } from '@owf/cose'
import { describe, expect, it } from 'vitest'
import {
  IdentifierList,
  IdentifierListCwt,
  IdentifierListCwtHeader,
  IdentifierListCwtHeaderKey,
  IdentifierListCwtPayload,
  MediaTypes,
} from '../../src'

const identifier = new Uint8Array([1, 2, 3, 4])

const identifierListToken = (typ?: string) => {
  const headers = new Map<number, unknown>([[RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256]])
  if (typ !== undefined) {
    headers.set(IdentifierListCwtHeaderKey.Typ, typ)
  }
  const protectedHeaders = ProtectedHeaders.create({ protectedHeaders: headers })

  const payload = IdentifierListCwtPayload.create({
    identifierList: IdentifierList.create({ identifiers: [identifier] }),
    expirationTime: new Date(Date.now() + 60_000),
  })

  return Sign1.fromDecodedStructure({
    protectedHeaders,
    unprotectedHeaders: UnprotectedHeaders.create({ unprotectedHeaders: new Map() }),
    payload: payload.encode(),
    signature: new Uint8Array(64),
  }).encode()
}

describe('identifier list cwt', () => {
  it('decodes a cwt carrying typ in the protected header', () => {
    const cwt = IdentifierListCwt.fromBytes(identifierListToken(MediaTypes.IdentifierListCwt))

    expect(cwt.typ).toStrictEqual(MediaTypes.IdentifierListCwt)
    expect(cwt.protectedHeaders).toBeInstanceOf(IdentifierListCwtHeader)
    expect(cwt.algorithm).toStrictEqual(SignatureAlgorithm.ES256)
    expect(cwt.includes(identifier)).toStrictEqual(true)
    expect(cwt.includes(new Uint8Array([5, 6]))).toStrictEqual(false)
  })

  it('rejects a cwt that omits typ', () => {
    expect(() => IdentifierListCwt.fromBytes(identifierListToken())).toThrow('but the protected header has no typ')
  })

  it('rejects a cwt whose typ is for another media type', () => {
    expect(() => IdentifierListCwt.fromBytes(identifierListToken('application/statuslist+cwt'))).toThrow(
      "Typ (protected header 16) shall be 'application/identifierlist+cwt'"
    )
  })
})

describe('identifier list cwt header', () => {
  it('creates a header carrying the identifier list media type', () => {
    const header = IdentifierListCwtHeader.create({ algorithm: SignatureAlgorithm.ES256 })

    expect(header.typ).toStrictEqual(MediaTypes.IdentifierListCwt)
    expect(header.algorithm).toStrictEqual(SignatureAlgorithm.ES256)
    expect(header.x5chain).toBeUndefined()
  })

  it('normalizes a single-certificate x5chain to an array', () => {
    const certificate = new Uint8Array([9, 9, 9])
    const headers = new Map<number, unknown>([
      [IdentifierListCwtHeaderKey.Typ, MediaTypes.IdentifierListCwt],
      [RegisteredCwtHeaderClaimKey.X5Chain, certificate],
    ])

    expect(IdentifierListCwtHeader.fromProtectedHeaders(headers).x5chain).toStrictEqual([certificate])
  })

  it('rejects an x5chain that is not made up of byte strings', () => {
    const headers = new Map<number, unknown>([
      [IdentifierListCwtHeaderKey.Typ, MediaTypes.IdentifierListCwt],
      [RegisteredCwtHeaderClaimKey.X5Chain, ['not-a-certificate']],
    ])

    expect(() => IdentifierListCwtHeader.fromProtectedHeaders(headers)).toThrow()
  })
})
