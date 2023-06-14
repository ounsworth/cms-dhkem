---
title: "
"
abbrev: "CMS DHKEM"
category: std

docname: draft-ietf-ounsworth-cms-dhkem-latest
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

informative:
  RFC5990:
  RFC9180:
  I-D.ietf-lamps-cms-kemri:


--- abstract

The DHKEM Algorithm is a one-pass (store-and-forward)
   mechanism for establishing keying data to a recipient using the
   recipient's Diffie-Hellman or elliptic curve Diffie-Hellman public key.
This document defines a mechanism
to wrap Ephemeral-Static (E-S) Diffie-Hellman (DH) and Elliptic Curve
Diffie-Hellman (ECDH) to fit the KEM interface.
This is a sister document to RSA-KEM {{RFC5990}} and simplifies future
cryptographic protocol design by only needing to handle KEMs at the protocol level.


--- middle

# Introduction

The Cryptographic Message Syntax (CMS) enveloped-data content type
{{RFC5652}} and the CMS authenticated-enveloped-data content type
{{RFC5083}} support both key transport and key agreement algorithms to
establish the key used to encrypt the content.  In recent years,
cryptographers have be specifying Key Encapsulation Mechanism (KEM)
algorithms, including quantum-secure KEM algorithms.  This document
defines conventions for wrapping Diffie-Hellman Ephemeral-Static (E-S)
Diffie-Hellman (DH) and Elliptic Curve Diffie-Hellman (ECDH) to fit the
KEM interface for the CMS enveloped-data content type and the CMS
authenticated-enveloped-data content type as defined in
{{I-D.ietf-lamps-cms-kemri}}.
This is a parallel mechanism to {{RFC5990}} which does the same for RSA.
The benefit is to allow forward-compatibility of older DH-based ciphers
into new mechanisms that only support KEMs.

A KEM algorithm is a one-pass (store-and-forward) mechanism for
transporting random keying material to a recipient using the recipient's
public key.  The recipient's private key is needed to recover the random
keying material, which is then treated as a pairwise shared secret
between the originator and recipient.  A KEM algorithm provides three
functions:

* KeyGen() -> (pk, sk):

> Generate the public key (pk) and a private key (sk).

* Encapsulate(pk) -> (ct, ss):

> Given the recipient's public key (pk), produce a ciphertext (ct) to be
passed to the recipient and shared secret (ss) for the originator.

* Decapsulate(sk, ct) -> ss:

> Given the private key (sk) and the ciphertext (ct), produce the
shared secret (ss) for the recipient.

To support a particular KEM algorithm, the CMS originator MUST implement
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

# Cryptographic dependencies

## Key Derivation Function

A key derivation function (KDF):

* `Extract(salt, ikm)`: Extract a pseudorandom key of fixed length `keyLength` bytes from input keying material `ikm` and an optional byte string `salt`.
* `Expand(prk, info, L)`: Expand a pseudorandom key `prk` using optional string info into `L` bytes of output keying material.
* `keyLength`: The output size of the `Extract()` function in bytes.

## (Elliptic Curve) Diffie Hellman

An elliptic curve or finite field Diffie-Hellman group providing the following operations:

* `GenerateKeyPair()`: create a new DH key.
* `DH(skX, pkY)`: Perform a non-interactive Diffie-Hellman exchange using the private key `skX` and public key `pkY` to produce a Diffie-Hellman shared secret of length `Ndh`. This function can raise a ValidationError as described in {{RFC9180}} Section 7.1.4.


# DH-Based KEM (DHKEM)

This is a straightforward application of the DHKEM construction from
{{RFC9180}} section 4.1 which is repeated here, unmodified except
for some nomenclature changes to line up with the CMS ASN.1 module below.

~~~
def LabeledExtract(salt, label, ikm):
  labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
  return kdf.Extract(salt, labeled_ikm)

def LabeledExpand(prk, label, info, keyLength):
  labeled_info = concat(I2OSP(keyLength, 2), "HPKE-v1", suite_id,
                        label, info)
  return kdf.Expand(prk, labeled_info, keyLength)

def ExtractAndExpand(dh, kem_context):
  eae_prk = LabeledExtract("", "eae_prk", dh)
  shared_secret = LabeledExpand(eae_prk, "shared_secret",
                                kem_context, keyLength)
  return shared_secret


def Encap(pkR):
  skE, pkE = dh.GenerateKeyPair()
  dhss = dh.DH(skE, pkR)
  enc = SerializePublicKey(pkE)

  pkRm = SerializePublicKey(pkR)
  kem_context = concat(enc, pkRm)

  shared_secret = ExtractAndExpand(dh, kem_context)
  return shared_secret, enc


def Decap(enc, skR):
  pkE = DeserializePublicKey(enc)
  dhss = dh.DH(skR, pkE)

  pkRm = SerializePublicKey(pk(skR))
  kem_context = concat(enc, pkRm)

  shared_secret = ExtractAndExpand(dh, kem_context)
  return shared_secret
~~~

EDNOTE: should we further domain-separate this, for example by adding a context string `kem_context = concat("cms-dhkem", enc, pkRm)` ?


# ASN.1 Module

In order to carry a DHKEM inside a CMS KEMRecipientInfo {{I-D.ietf-lamps-cms-kemri}},
we define `id-kem-dhkem`, `kema-dhkem`, and `DHKemParameters`.

~~~
CMS-DHKEM-2023
    { iso(1) member-body(2) us(840) rsadsi(113549)
      pkcs(1) pkcs-9(9) smime(16) modules(0)
      id-mod-cms-dhkem-2023(99) }

  DEFINITIONS IMPLICIT TAGS ::=
  BEGIN
  -- EXPORTS ALL;

  IMPORTS

  AlgorithmIdentifier{}, KEY-AGREE, KEY-DERIVATION
    FROM AlgorithmInformation-2009
      { iso(1) identified-organization(3) dod(6) internet(1)
        security(5) mechanisms(5) pkix(7) id-mod(0)
        id-mod-algorithmInformation-02(58) }

   KEM-ALGORITHM
     FROM KEMAlgorithmInformation-2023 -- [I-D.ietf-lamps-cms-kemri]
       { iso(1) identified-organization(3) dod(6) internet(1)
         security(5) mechanisms(5) pkix(7) id-mod(0)
         id-mod-kemAlgorithmInformation-2023(99) }

   pk-dh, pk-ec
     FROM PKIXAlgs-2009
       { iso(1) identified-organization(3) dod(6) internet(1)
         security(5) mechanisms(5) pkix(7) id-mod(0)
         id-mod-pkix1-algorithms2008-02(56) }

  pk-X25519, pk-X448
    FROM Safecurves-pkix-18
      { iso(1) identified-organization(3) dod(6) internet(1)
        security(5) mechanisms(5) pkix(7) id-mod(0)
        id-mod-safecurves-pkix(93) } ;


  id-alg-dhkem OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
      rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) alg(3) 99 }

  kema-dhkem KEM-ALGORITHM ::= {
      IDENTIFIER id-alg-dhkem
      PARAMS TYPE DHKemParameters
      PUBLIC-KEYS { pk-dh | pk-ec | pk-X25519 | pk-X448 }
      UKM ARE optional
      SMIME-CAPS { TYPE DHKemParameters IDENTIFIED BY id-kem-dhkem } }

  DHKemParameters ::= SEQUENCE {
      dh         KeyAgreeAlgorithmIdentifier,
      kdf        KeyDerivationFunction,
      keyLength  KeyLength }

  KeyAgreeAlgorithmIdentifier ::= AlgorithmIdentifier{ KEY-AGREE, {...} }

  KeyDerivationFunction ::= AlgorithmIdentifier { KEY-DERIVATION, {...} }

  KeyLength ::= INTEGER (1..MAX)

END

~~~

EDNOTE: The other way to define this would be to call out a toplevel DHKEM for each one: `id-kema-dhkem-dh` `id-kema-dhkem-ecdh`, `id-kema-dhkem-x25519`, `id-kema-dhkem-x448`.
EDNOTE: This approach adds a layer of wrapping for the benefit of agility and future-proofing. I would be happy to write them each out if that's considered better.

# Security Considerations

This document does not add any security considerations above
those already present for the Epheremal-Static mode of the underlying (EC)DH primitive
and in {{RFC9180}}.


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
