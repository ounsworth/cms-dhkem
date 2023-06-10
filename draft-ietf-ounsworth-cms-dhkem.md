---
title: "Use of (Elliptic Curve) Diffie-Hellman KEM in the Cryptographic Message Syntax (CMS)"
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

The Cryptographic Message Syntax (CMS) supports key transport and
key agreement algorithms.  In recent years, cryptographers have been
specifying Key Encapsulation Mechanism (KEM) algorithms, including
quantum-secure KEM algorithms.  This document defines a mechanism
to wrap Ephemeral-Static (E-S) Diffie-Hellman (DH) and Elliptic Curve
Diffie-Hellman (ECDH) to fit the KEM interface.


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

# DH-Based KEM (DHKEM)

TODO profile RFC9180 s. 4.1 with CMS-appropriate values of kem_context.
Also double-check what RFC5990 and kemri do, because maybe the 9180 construction is overkill for CMS with all the context strings and ExtractAndExpand steps.

# ASN.1 Module

TODO


# Security Considerations

TODO Security
The hope is that this draft does not add any security considerations above
those already present for the Epheremal-Static mode of the underlying (EC)DH primitive.


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
