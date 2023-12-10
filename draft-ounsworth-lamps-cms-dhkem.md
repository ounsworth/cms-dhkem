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
{{RFC9180}} section 4.1 which is to be used unmodified.

CMS encrypt operations performed by the sender are to use `Encap(pkR)`.
CMS decrypt operations performed by the received are to use `Decap(enc, skR)`.

The authenticated modes defined in {{RFC9180}}, `AuthEncap(pkR, skS)` and `AuthDecap(enc, skR, pkS)`
do not apply to CMS.

# ASN.1 Module

In order to carry a DHKEM inside a CMS KEMRecipientInfo {{I-D.ietf-lamps-cms-kemri}},
we define `id-kem-dhkem`, `kema-dhkem`, and `DHKemParameters`.

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

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
