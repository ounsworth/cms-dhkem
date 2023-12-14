---
title: "Use of the DH-Based KEM (DHKEM) in the Cryptographic Message Syntax (CMS)"
abbrev: "CMS DHKEM"
category: std

docname: draft-ounsworth-lamps-cms-dhkem-latest
ipr: trust200902
submissiontype: IETF  # also: "independent", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: Security
workgroup: LAMPS
keyword:
 - Internet-Draft
venue:
  group: "Limited Additional Mechanisms for PKIX and SMIME (lamps)"
  type: "Working Group"
  mail: "spasm@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/spasm/"
  github: "EntrustCorporation/cms-dhkem"
  latest: "https://EntrustCorporation.github.io/cms-dhkem/draft-ietf-ounsworth-cms-dhkem.html"

author:
    -
      ins: M. Ounsworth
      name: Mike Ounsworth
      org: Entrust Limited
      abbrev: Entrust
      street: 2500 Solandt Road – Suite 100
      city: Ottawa, Ontario
      country: Canada
      code: K2K 3G5
      email: mike.ounsworth@entrust.com

    -
      ins: J. Gray
      name: John Gray
      org: Entrust Limited
      abbrev: Entrust
      street: 2500 Solandt Road – Suite 100
      city: Ottawa, Ontario
      country: Canada
      code: K2K 3G5
      email: john.gray@entrust.com

    - name: Russ Housley
      org: Vigil Security, LLC
      abbrev: Vigil Security
      city: Herndon, VA
      country: US
      email: housley@vigilsec.com

normative:
  RFC5083:
  RFC5280:
  RFC5652:
  RFC7748:
  I-D.ietf-lamps-cms-kemri:
  I-D.ietf-lamps-pq-composite-kem:

informative:
  RFC5990:
  RFC9180:


--- abstract

The DHKEM Algorithm is a one-pass (store-and-forward)
mechanism for establishing keying data to a recipient using the
recipient's Diffie-Hellman or elliptic curve Diffie-Hellman public key.
This document uses a straightforward application of {{RFC9180}} to define
a mechanism to wrap Ephemeral-Static (E-S) Diffie-Hellman (DH) and Elliptic Curve
Diffie-Hellman (ECDH) such that it can be used in KEM interfaces
within the Cryptographic Message Syntax (CMS).
This is a sister document to RSA-KEM {{RFC5990}} and simplifies future
cryptographic protocol design by only needing to handle KEMs at the
protocol level.


--- middle

# Introduction

The Cryptographic Message Syntax (CMS) enveloped-data content type
{{RFC5652}} and the CMS authenticated-enveloped-data content type
{{RFC5083}} support both key transport and key agreement algorithms to
establish the key used to encrypt the content.  In recent years,
cryptographers have be specifying asymmetric key establishment algorithms,
including Post-Quantum algorithms as Key Encapsulation Mechanism (KEMs).
This document defines conventions for wrapping Ephemeral-Static (E-S)
Diffie-Hellman (DH) and Elliptic Curve Diffie-Hellman (ECDH) key agreements
to fit the KEM interface for the CMS enveloped-data content type and the CMS
authenticated-enveloped-data content type as defined in
{{I-D.ietf-lamps-cms-kemri}}.
This is a parallel mechanism to {{RFC5990}} which does the same for RSA.
The benefit is to allow forward-compatibility of older DH-based ciphers
into new mechanisms that only support KEMs including the PQ/T Hybrid
mechanisms specified in {{I-D.ietf-lamps-pq-composite-kem}}.

A KEM algorithm is a one-pass (store-and-forward) mechanism for
encapsulating keying material for a recipient using the recipient's
public key.  The recipient's private key is needed to recover the
keying material, which is then treated as a pairwise shared secret
between the sender and recipient.  A KEM algorithm provides three
functions:

* KeyGen() -> (pk, sk):

> Generate a public key (pk) and a corresponding private key (sk). This function is identical to the DH.KeyGen() of the underlying Diffie-Hellman primitive.

* Encapsulate(pk) -> (ct, ss):

> Given the recipient's public key (pk), produce a ciphertext (ct) to be
passed to the recipient and shared secret (ss) for the sender.

* Decapsulate(sk, ct) -> ss:

> Given the private key (sk) and the ciphertext (ct), recover the
shared secret (ss) for the recipient.

To support a particular KEM algorithm, the CMS sender MUST implement KeyGen() and
Encapsulate().

To support a particular KEM algorithm, the CMS recipient MUST implement
KeyGen() and Decapsulate().  The recipient's public key is usually
carried in a certificate {{RFC5280}}.

This draft follows the DH-Based KEM (DHKEM) construction defined in
{{RFC9180}} whereby the `Encapsulate()` operation includes the
generation of an ephemeral key and the usage of that key against the
recipient's static public key.



# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Use of DHKEM  in CMS

This is a straightforward application of the DHKEM construction from
{{RFC9180}} section 4.1 which is to be used unmodified, and is copied below in {{appdx-dhkem}} for convenience.

CMS encrypt operations performed by the sender are to use `Encap(pkR)`.
CMS decrypt operations performed by the received are to use `Decap(enc, skR)`.

The authenticated modes defined in {{RFC9180}}, `AuthEncap(pkR, skS)` and `AuthDecap(enc, skR, pkS)`
do not apply to CMS because CMS uses DH in only the ephemeral-static modes and provides sender authentication through separate digital signatures.


## RecipientInfo Conventions

When the DHKEM Algorithm is employed for a recipient, the
   RecipientInfo alternative for that recipient MUST be
   OtherRecipientInfo using the KEMRecipientInfo structure
   [I-D.ietf-lamps-cms-kemri].  The fields of the KEMRecipientInfo MUST
   have the following values:

      version is the syntax version number; it MUST be 0.

      rid identifies the recipient's certificate or public key.

      kem identifies the KEM algorithm; it MUST contain one of the
      algorithms listed in {{sec-dhkem-algs}}.

      kemct is the ciphertext produced for this recipient; it contains
      the output `enc` from `Encap(pkR)` from {{appdx-dhkem-alg}}, which
      is the serialized ephemeral public key of the sender.

      kdf identifies the key-derivation algorithm.

      kekLength is the size of the key-encryption key in octets.

      ukm is an optional random input to the key-derivation function.

      wrap identifies a key-encryption algorithm used to encrypt the
      content-encryption key.

      encryptedKey is the result of encrypting the keying material with
      the key-encryption key.  When used with the CMS enveloped-data
      content type [RFC5652], the keying material is a content-
      encryption key.  When used with the CMS authenticated-data content
      type [RFC5652], the keying material is a message-authentication
      key.  When used with the CMS authenticated-enveloped-data content
      type [RFC5083], the keying material is a content-authenticated-
      encryption key.

TODO:

## Certificate Conventions

TODO:

## SMIMECapabilities Attribute Conventions

Section 2.5.2 of {{!RFC8551}} defines the SMIMECapabilities signed
attribute (defined as a SEQUENCE of SMIMECapability SEQUENCEs) to
announce a partial list of algorithms that an S/MIME implementation
can support.  When constructing a CMS signed-data content type
{{!RFC5652}}, a compliant implementation MAY include the
SMIMECapabilities signed attribute announcing that it supports the
DHKEM Algorithm.

The SMIMECapability SEQUENCE representing the RSA-KEM Algorithm MUST
include the id-rsa-kem-spki object identifier in the capabilityID
field; see Appendix B for the object identifier value, and see
Appendix C for examples.  When the id-rsa-kem-spki object identifier
appears in the capabilityID field and the parameters are present,
then the parameters field MUST use the GenericHybridParameters type, which is defined in {{I-D.ietf-lamps-cms-kemri}}.

~~~
  GenericHybridParameters ::= SEQUENCE {
    kem  KeyEncapsulationMechanism,
    dem  DataEncapsulationMechanism }
~~~

The definition of KEMAlgorithms from {{I-D.ietf-lamps-cms-kemri}}

~~~
 KEMAlgorithms KEM-ALGORITHM ::= { kema-kem-rsa | kema-rsa-kem, ... }
~~~

is extended to add `kema-dhkem`.

TODO / EDNOTE: I actually don't know how to extend something in ASN.1.

The fields of the GenericHybridParameters type have the following
meanings:

  kem is an AlgorithmIdentifer; the algorithm field MUST be set to
  id-alg-dhkem; the parameters field MUST be DhKemParameters, which
  is a SEQUENCE of an AlgorithmIdentifier that identifies the underlying
  Diffie-Hellman algorithm, an AlgorithmIdentifier that identifies the
  supported key-derivation function and a positive INTEGER that
  identifies the length of the key-encryption key in octets.  If the
  GenericHybridParameters are present, then the provided keyDerivationFunction
  value MUST be used as the key-derivation function in the kdf field of
  KEMRecipientInfo, and the provided key length MUST be used in the
  kekLength of KEMRecipientInfo.

  dem is an AlgorithmIdentifier; the algorithm field MUST be
  present, and it identifies the key-encryption algorithm;
  parameters are optional.  If the GenericHybridParameters are
  present, then the provided dem value MUST be used in the wrap
  field of KEMRecipientInfo.


~~~
DhKemParameters ::= SEQUENCE {
  dhAlg                  DhAlgorithm,
  keyDerivationFunction  KeyDerivationFunction,
  keyLength              KeyLength }

DhAlgorithm ::=
  AlgorithmIdentifier { KEY-AGREE, {DhAlgorithms} }

DhAlgorithms KEY-AGREE ::= { kaa-X25519, kaa-X448, ... }

EDNOTE: I kinda just want to borrow / extend this from RFC8418:

   KeyAgreementAlgs KEY-AGREE ::= { ...,
     kaa-dhSinglePass-stdDH-sha256kdf-scheme   |
     kaa-dhSinglePass-stdDH-sha384kdf-scheme   |
     kaa-dhSinglePass-stdDH-sha512kdf-scheme   |
     kaa-dhSinglePass-stdDH-hkdf-sha256-scheme |
     kaa-dhSinglePass-stdDH-hkdf-sha384-scheme |
     kaa-dhSinglePass-stdDH-hkdf-sha512-scheme }
~~~

TODO: imports:
TODO: KEY-AGREE FROM AlgorithmInformation-2009
       {iso(1) identified-organization(3) dod(6) internet(1) security(5)
       mechanisms(5) pkix(7) id-mod(0)
       id-mod-algorithmInformation-02(58)}

TODO: kaa-X25519, kaa-x448 from 8410

# DHKEM Algorithms {#sec-dhkem-algs}

TODO: a big table ...

This section provides a registry of algorithms to satisfy the specific
DHKEM and KDF algoritms required in {{appdx-dhkem-alg}}.

| DHKEM Algorithm OID | DH Algorithm         | KDF Algorithm | kekLength |
| TBD-DHKEM1          | ECDH-P256            | HKDF-SHA256   | 32        |
| TBD-DHKEM2          | ECDH-brainpoolP256r1 | HKDF-SHA256   | 32        |
| TBD-DHKEM3          | X25519               | HKDF-SHA256   | 32        |
| TBD-DHKEM4          | ECDH-P384            | HKDF-SHA384   | 48        |
| TBD-DHKEM5          | ECDH-brainpoolP384r1 | HKDF-SHA384   | 48        |
| TBD-DHKEM6          | X448                 | HKDF-SHA512   | 64        |
{: #tab-dhkem-algs title="Registered DHKEM Algorithms"}

Full specifications for the referenced algorithms can be found as follows:

* _ECDH_: There does not appear to be a single IETF definition of ECDH, so we refer to the following:
  * _ECDH NIST_: SHALL be Elliptic Curve Cryptography Cofactor Diffie-Hellman (ECC CDH) as defined in section 5.7.1.2 of [SP.800-56Ar3].
  * _ECDH BSI / brainpool_: SHALL be Elliptic Curve Key Agreement algorithm (ECKA) as defined in section 4.3.1 of [BSI-ECC]
* _X25519 / X448_: [RFC7784]
* _HKDF-SHA2_: [RFC5869].

blah blah when used in an AlgorithmIdentifier ... empty params.

blah blah KDF and kekLen MUST be the same as specified in KEMRI ... copy the language from 5990bis.

# ASN.1 Module

In order to carry a DHKEM inside a CMS KEMRecipientInfo {{I-D.ietf-lamps-cms-kemri}},
we define `id-kem-dhkem`, `kema-dhkem`, and `DHKemParameters`.

TODO: sync this up with the extra stuff added in the body.

~~~ ASN.1

<CODE STARTS>

{::include CMS-DHKEM-2023.asn}

<CODE ENDS>

~~~

EDNOTE: The other way to define this would be to call out a toplevel DHKEM for each one: `id-kema-dhkem-dh` `id-kema-dhkem-ecdh`, `id-kema-dhkem-x25519`, `id-kema-dhkem-x448`.

EDNOTE: This approach adds a layer of wrapping for the benefit of agility and future-proofing. I would be happy to write them each out if that's considered better.

# Security Considerations

This document provides an IND-CCA2 secure DHKEM construction.

This document does not add any security considerations above
those already present for the Ephemeral-Static mode of the underlying (EC)DH primitive
and in {{RFC9180}}.


# IANA Considerations

This document registers the OID `id-alg-dhkem`

The IANA is requested to allocate a value
from the "SMI Security for S/MIME Module Identifier" registry for the
included ASN.1 module, and allocate values from "SMI Security for
S/MIME Algorithms" to identify the new algorithm defined within.

##  Object Identifier Allocations

###  Module Registration - SMI Security for S/MIME Module Identifer

-  Decimal: IANA Assigned - Replace TBDMOD
-  Description: CMS-DHKEM-2023 - id-mod-cms-dhkem-2023
-  References: This Document

###  Object Identifier Registrations - SMI Security for S/MIME Attributes

- DHKEM

  - Decimal: IANA Assigned - Replace TBDALG
  - Description: id-alg-dhkem
  - References: This Document



--- back


# DH-Based KEM (DHKEM) Algorithm {#appdx-dhkem}

# Cryptographic dependencies

## Key Derivation Function

A key derivation function (KDF):

* `Extract(salt, ikm) -> prk`: Extract a pseudorandom key of fixed length `keyLength` bytes from input keying material `ikm` and an optional byte string `salt`.
* `Expand(prk, info, L) -> ss`: Expand a pseudorandom key `prk` using optional string info into `L` bytes of output keying material.
* `keyLength`: The output size of the `Extract()` function in bytes.

In the pseudo-code below, these are combined into a single function:

* `ExtractAndExpand(ikm, info) -> ss`.

## (Elliptic Curve) Diffie Hellman

An elliptic curve or finite field Diffie-Hellman group providing the following operations:

* `GenerateKeyPair() -> (pk, sk)`: create a new DH key.
* `DH(skX, pkY) -> ss`: Perform a non-interactive Diffie-Hellman exchange using the private key `skX` and public key `pkY` to produce a Diffie-Hellman shared secret of length `Ndh`. This function can raise a ValidationError as described in {{RFC9180}} Section 7.1.4.

These definitions are taken from {{RFC9180}} and reproduced here for convenience.

## DHKEM {#appdx-dhkem-alg}

### KDF Functions

The KDF functions are defined as follows.

~~~
def LabeledExtract(salt, label, ikm):
  labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
  return Extract(salt, labeled_ikm)

def LabeledExpand(prk, label, info, L):
  labeled_info = concat(I2OSP(L, 2), "HPKE-v1", suite_id,
                        label, info)
  return Expand(prk, labeled_info, L)

def ExtractAndExpand(dh, kem_context):
  eae_prk = LabeledExtract("", "eae_prk", dh)
  shared_secret = LabeledExpand(eae_prk, "shared_secret",
                                kem_context, Nsecret)
  return shared_secret
~~~
{: #code-9180kdfs title="KDF functions from RFC 9180"}

Note that the KDF functions require `Extract()`, which is a direct call
to the underlying KDF, which {{RFC9180}} allows to be HKDF-SHA256,
HKDF-SHA384, or HKDF-SHA512.


### DHKEM Functions

The DHKEM functions are defined as follows:

~~~
def Encap(pkR):
  skE, pkE = GenerateKeyPair()
  dh = DH(skE, pkR)
  enc = SerializePublicKey(pkE)

  pkRm = SerializePublicKey(pkR)
  kem_context = concat(enc, pkRm)

  shared_secret = ExtractAndExpand(dh, kem_context)
  return shared_secret, enc

def Decap(enc, skR):
  pkE = DeserializePublicKey(enc)
  dh = DH(skR, pkE)

  pkRm = SerializePublicKey(pk(skR))
  kem_context = concat(enc, pkRm)

  shared_secret = ExtractAndExpand(dh, kem_context)
  return shared_secret
~~~
{: #code-9180dhkem title="DHKEM functions from RFC 9180"}

Note that the DHKEM functions require `GenerateKeyPair()`, `DH(sk, pk)`,
`SerializePublicKey(pk)`, and `DeserializePublicKey(enc)`, which are
provided by the underlying DH scheme.


# Acknowledgments
{:numbered="false"}

TODO acknowledge.
