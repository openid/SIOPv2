%%%
title = "Self-Issued OpenID Provider v2"
abbrev = "siop-v2"
ipr = "none"
workgroup = "connect"
keyword = ["security", "openid", "ssi"]

[seriesInfo]
name = "Internet-Draft"
value = "openid-connect-self-issued-v2-1_0-05"
status = "standard"

[[author]]
initials="K."
surname="Yasuda"
fullname="Kristina Yasuda"
organization="Microsoft"
    [author.address]
    email = "kristina.yasuda@microsoft.com"

[[author]]
initials="M."
surname="Jones"
fullname="Michael B. Jones"
organization="Microsoft"
    [author.address]
    email = "mbj@microsoft.com"

[[author]]
initials="T."
surname="Looker"
fullname="Tobias Looker"
organization="Mattr"
    [author.address]
    email = "tobias.looker@mattr.global"


%%%

.# Abstract

OpenID Connect defines mechanism by which an End-user can leverage an OpenID Provider (OP) to release identity information (such as authentication and attributes) to a Relying Party (RP) which can act on that information.

This specification extends OpenID Connect with the concept of a Self-Issued OpenID Provider (Self-Issued OP), an OP which is within the End-User’s local control. End-users can leverage Self-Issued OPs to authenticate themselves and present claims directly to the Relying Parties. This allows users to interact with RPs directly, without relying on a third-party provider or requiring the End-User to operate their own hosted infrastructure.

{mainmatter}

# Introduction

This specification extends OpenID Connect with the concept of a _Self-Issued OpenID Provider_ (Self-Issued OP), an OP which is within the End-User’s local control. End-users can leverage Self-Issued OPs to authenticate themselves and present claims directly to Relying Parties. This allows users to interact with RPs directly, without relying on a third-party provider or requiring the End-User to operate their own hosted infrastructure.

An OP releases identity information such as End-user authentication in the form of an ID Token. In the case of a traditional, hosted OP, an RP will typically trust an ID token based on the relationship between the RP and OP. The OP has a reputation-based stake with both RPs and End-Users to provide correct information.

A _Self-Issued ID Token_ is an ID Token issued by a Self-Issued OP. A Self-Issued ID Token differs in that the trust relationship is directly with the End-user.

Because a Self-Issued ID Token does not have the broad reputational trust of a traditional hosted OP, claims about the End-user (e.g. birthdate) are by default self-asserted and non-verifiable. Separate specifications such as [@!OIDC4VP] describe how to present claims from third-party sources which are cryptographically verifiable.

The extensions defined in this specification provide the protocol and policy-level changes needed to support this model of Self-Issued OpenID Providers. Aspects not defined in this specification are expected to continue to follow OpenID Connect Core 1.0.

Note: This specification replaces [Self-Issued OpenID Connect Provider DID Profile v0.1](https://identity.foundation/did-siop/) and was written as a working item of a liaison between Decentralized Identity Foundation and OpenID Foundation.

# Use-cases

## Resilience against Sudden or Planned OP Unavailability

  An OpenID Provider's infrastructure may become unavailable or even destroyed due to natural disasters such as hurricanes, tsunamis and fires, or may be removed from service as a planned business decision. As Self-Issued OPs are local to the End-user environment, there is resilience against such events simultaneously affecting a significant portion of otherwise unimpacted End-Users.

## Authentication at the Edge

  As internet-connected smartphones have risen in availability, traditionally in-person interactions and services have begun to be optimized with digital alternatives. These services often have requirements for digital authentication and for other identity credentials. Self-Issued OPs can provide this authentication directly, without needing to delegate to remote, hosted OPs. This potentially allows for increased efficiency as well as allowing for authentication in environments which may have reduced connectivity.

## Sharing Credentials from Several Issuers in One Transaction

  When End-users apply to open a banking account online, in most countries they are required to submit scanned versions of the required documents. These documents are usually issued by different authorities, and hard to be verified in a digital form. A Self-issued OP directly representing the user may have access to a greater set of such information as credentials, while a traditional OP may not have a business relationship which enables access to such a breadth of information. Self-Issued OPs could aggregate credentials from multiple sources, then release them within a single transaction to a relying party. The relying party can then verify the authenticity of the information to make the necessary business decisions.

## Aggregation of Multiple Personas under One Self-Issued Op

  End-users often use several hosted OpenID Providers for different Relying Parties. While there are many reasons to do this, often this is done to have separately maintained identities, such as keeping a work-related persona separate from a personal persona. An End-user may do this to specifically represent different sets of claims, or because they what to prevent relying parties from correlating their activities by using the same OP. The usage of multiple OPs can create friction later, as the end-user may return later having forgot which OP they used for the relying party.

  A single Self-Issued OP can be chosen by the End-user based on its capability to meet specific needs and privacy concerns. The separately-defined ability to present third-party credentials allows the RP to accept Self-Issued ID Tokens while still evaluating attributes using reputational trust of the credential issuers.

# Scope

As a Self-Issued OP may be running locally as a native application or progressive web application, the RP may not have a network-addressable endpoint to communicate directly with the OP. This specification leverages the implicit flow of OpenID Connect defined in section 3.2 of [@!OpenID] to communicate with such locally-running OPs, and extends OpenID Connect Discovery to represent the differences from traditional OPs.

This document is scoped for a deployment model where the Self-Issued OP is deployed on an End-user's device.

This specification defines:

* Invocation of Self-Issued OP

  This specification defines extensions to the OpenID Connect implicit flow to invoke a Self-Issued OP from a Relying Party. It also proposes user experience behavior when no appropriate Self-Issued Op is available locally.

* Automatic Registration of supported functionality between a RP and Self-Issued OP

  OpenID Connect typically leverages a registration between a Client (acting as a RP) and the OP, which pre-establishes supported functionality before a request has been made. This may be done statically, or may leverage a combination of OpenID Connect Discovery and the OAuth 2.0 Dynamic Client Registration Protocol.

  Relying Parties typically cannot pre-establish registration with a Self-Issued OP, as each End-user might be represented by a different, locally-controlled Self-Issued OP instance. This specification extends the authentication request with a mechanism with additional dynamic registration techniques for feature negotiation.

* Additional claims and processing requirements of Self-Issued ID Tokens

* Including self-asserted (non-verifiable) claims within a Self-Issued ID Token

* Usage of cryptographically verifiable identifiers as a way for RPs to identify the authenticated user

  A _cryptographically verifiable identifier_ is an identifier which is either based upon or can be resolved to cryptographic key material. Self-Issued OPs can prove possession of the underlying key during the OpenID message exchange with the RP. Future exchanges based on the same identifier serve to strongly re-authenticate the End-user.

  This specification defines a subject syntax type which is a thumbprint of the public key material. The public key itself is shared within the ID Token as a _JSON Web Key_ (JWK). The cryptographic algorithm needs to be supported by both the Self-Issued OP and RP.

  This specification also allows for _resolvable identifiers_, which are URIs which can resolve various types of authoritative data underneath an appropriate _resolution method_. Resolvable identifiers may be used as the subject identifiers, or `sub` Claim of the ID Token, when they can be resolved to a set one or more of cryptographic keys that identify the subject. In addition to cryptographic algorithms, both the Self-Issued OP and RP need to support the resolution method. The resolution method is based on the URI itself, such as a "https" resolution method. One example of such a resolvable identifier would be a _Decentralized Identifier_ (DID), where resolution methods would typically also include the _DID Method_, e.g. "did:example".

  For compatibility with the existing JWS/JWE-based cryptography of OpenID Connect, it is assumed such resolved cryptographic identities are representable as a _JSON Web Key Set_ (JWKS). Each key in the set would have a cryptographic algorithm, key identifier, and associated key material.

The following are considered out of scope of this document:

* Presentation of aggregated credentials

  A traditional OP could release additional claims about the user within an ID Token such as a verified email address. The trust in the validity of the claim is based on the trust between the RP and OP.

  A Self-Issued OP can present two types of claims - self-attested claims and claims from a third-party issuer which are cryptographically verifiable.

  This specification relies on other specifications to define the method to present credentials from third-party issuers. One such example is [@!OIDC4VP], which describes the usage of Verifiable Credentials and Verifiable Presentations with OpenID Connect.
  
* Provisioning of aggregated credentials

  The mechanism for a Self-Issued OP to acquire credentials which can be presented is out of scope of this document. Similar to presentation, a traditional OP may also wish to acquire third-party credentials to present to Relying Parties. One mechanism to provision credentials is being defined within the Claims Aggregation specification.

# Terms and definitions

Common terms in this document come from four primary sources: DID-CORE, VC-DATA and OpenID-Core. In the case where a term has a definition that differs, the definition below is authoritative.

- Trust framework
    - a legally enforceable set of specifications, rules, and agreements that govern a multi-party system established for a common purpose, designed for conducting specific types of transactions among a community of participants, and bound by a common set of requirements. [OIX]

- Cryptographically verifiable identifier
    - an identifier which is either based upon or resolves to cryptographic key material.

## Abbreviations

* OP: OpenID Provider
* RP: Relying Party
* Self-Issued OP or SIOP: Self-Issued OpenID Provider

# Protocol Flow

Self-Issued OpenID Provider Request is an OpenID Connect Authentication Request that results in an End-user providing an ID Token to the Relying Party through the Self-Issued OP. The ID Token MAY include attested claims about the End-user.

~~~ ascii-art
+------+                                           +----------------+
|      |                                           |                |
|      |--(1) Self-Issued OpenID Provider Request->|                |
|      |     (Authentication Request)              |                |
|      |                                           |                |
|      |       +----------+                        |                |
|      |       |          |                        |                |
|      |       | End-User |                        |                |
|  RP  |       |          |<--(2) AuthN & AuthZ--->| Self-Issued OP |
|      |       |          |                        |                |
|      |       +----------+                        |                |
|      |                                           |                |
|      |<-(3) Self-Issued OpenID Provider Response-|                |
|      |      (Self-Issued ID Token)               |                |
|      |                                           |                |
+------+                                           +----------------+
~~~
Figure: Self-Issued OP Protocol Flow

# Discovery and Registration

In conventional OpenID Connect flows, Relying Party and OpenID Provider can exchange metadata prior to the transaction, either using [@!OpenID.Discovery] and [@!OpenID.Registration], or out-of-band mechanisms.

However, in Self-Issued OP flows, such mechanisms are typically not available since Self-Issued OPs do not have API endpoints for that purpose. Therefore, alternative mechanisms are adopted, and Self-Issued OPs and Relying Parties are expected to obtain each other's metadata at every single request. Self-Issued OPs utilize registration parameter and/or resolve `client_id` to obtain Relying Party metadata.

## Self-Issued OpenID Provider Invocation

When the End-user first interacts with the RP, there are currently no established, robust means to signal which OpenID Providers to invoke, because applications cannot reliably determine a URI of the Self-Issued OP an End-user may have a relationship with or have installed. The RP is, therefore, responsible for selecting where to direct the request URL.

When the RP sends the request to the Self-Issued OP, there are two scenarios how to reach and invoke an application that can process that request. 

In the first scenario, request is encoded in a QR code, and the End-user scans it with the camera via the application that is intended to handle the request from the RP. In this scenario, the request does not need to be intended for a specfiic `authorization_endpoint` of a Self-Issued OP. Note that this will not work in a same-device Self-Issued OP flow, when the RP and the Self-Issued OP are on the same device.

In the second scenario, request includes `authorization_endpoint` of a Self-Issued OP, and will open a target application. In this scenario, there are two ways of how RP can obtain `authorization_endpoint` of the Self-Issued OP to contruct a targeted request as defined in (#siop-discovery), either using the static set of Self-Issued OP metadata, or by pre-obtaining `authorization_endpoint`. Note that this flow would work both for the same-device Self-Issued OP flow and the cross-device Self-Issued OP flow.

## Self-Issued OpenID Provider Discovery {#siop-discovery}

RP can obtain `authorization_endpoint` of the Self-Issued OP to contruct a request targeted to a particular application either by using the static set of Self-Issued OP metadata as defined in (#siop-discovery), or by pre-obtaining `authorization_endpoint` as defined in (#dynamic-siop-metadata).

Value of the `iss` Claim in the ID Token serves as an indicator which Self-Issued OP Discovery Mechanism is used.

### Static Self-Issued OpenID Provider Discovery Metadata {#static-siop-metadata}

When the RP does not have the means to pre-obtain Self-Issued OP Discovery Metadata, dynamic discovery is not performed. Instead, the following static configuration values are used. 

RP MUST use custom URI scheme `openid://` as the `authorization_endpoint` to construct the request. Self-Issued OPs invoked via `openid://` MUST set issuer identifier, or `iss` Claim in the ID Token to `https://self-issued.me/v2`.

Note that the request using custom URI scheme `openid://` will open only Self-Issued OPs as native apps. For other types of Self-Issued OP deployments, the usage of the Universal Links, or App Links is recommended as explained in (#choice-of-authoriation-endpoint).

```json
{
  "authorization_endpoint": "openid:",
  "issuer": "https://self-issued.me/v2",
  "response_types_supported": [
    "id_token"
  ],
  "scopes_supported": [
    "openid",
    "profile",
    "email",
    "address",
    "phone"
  ],
  "subject_types_supported": [
    "pairwise"
  ],
  "id_token_signing_alg_values_supported": [
    "ES256",
    "ES256K"
  ],
  "request_object_signing_alg_values_supported": [
    "ES256",
    "ES256K"
  ]
}
```

### Dynamic Self-Issued OpenID Provider Discovery Metadata {#dynamic-siop-metadata}

As an alternative mechanism to the (#static-siop-metadata), the RP can pre-obtain Self-Issued OP Discovery Metadata prior to the transaction, either using [@!OpenID.Discovery], or out-of-band mechanisms. 

How the RP obtains Self-Issued OP's issuer identifier is out of scope of this specification. The RPs MAY skip section 2 of [@!OpenID.Discovery].

When [@!OpenID.Discovery] is used, the RP MUST obtain Self-Issued OP metadata from a JSON document that Selc-Issued OP made available at the path formed by concatenating the string `/.well-known/openid-configuration` to the Self-Issed OP's Issuer Identifier.

Note that contrary to [@!OpenID.Discovery], `jwks_uri` parameter MUST NOT be present in Self-Issued OP Metadata. If it is, the RP MUST ignore it, and use `sub` claim in the ID Token to obtain signing keys to validate the signatures from the Self-Issued OpenID Provider.
Note: handling of `jwks_uri` needs to be discussed.

* `authorization_endpoint`
    * REQUIRED. URL of the Self-Issued OP used by the RP to perform Authentication of the End-User. Can be custom URI scheme, or Universal Links/App links. See (#choice-of-authoriation-endpoint).
* `issuer`
    * REQUIRED. URL using the `https` scheme with no query or fragment component that the Self-Issued OP asserts as its Issuer Identifier. MUST be identical to the `iss` Claim value in ID Tokens issued from this Self-Issued OP.
* `response_types_supported`
    * REQUIRED. A JSON array of strings representing supported response types. MUST be `id_token`.
* `scopes_supported`
    * REQUIRED. A JSON array of strings representing supported scopes. MUST support the `openid` scope value.
* `subject_types_supported`
    * REQUIRED. A JSON array of strings representing supported subject types. Valid values include `pairwise` and `public`. 
* `id_token_signing_alg_values_supported`
    * REQUIRED. A JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for the ID Token to encode the Claims in a JWT [JWT]. Valid values include `RS256`, `ES256`, `ES256K`, and `EdDSA`.
* `request_object_signing_alg_values_supported`
    * REQUIRED. A JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for Request Objects, which are described in Section 6.1 of [@!OpenID]. Valid values include `none`, `RS256`, `ES256`, `ES256K`, and `EdDSA`.
* `subject_identifier_types_supported`
    * REQUIRED. A JSON array of strings representing supported subject identifier types. Valid values include `jkt` and `did`.
* `did_methods_supported`
    * OPTIONAL. A JSON array of strings representing supported DID methods, with a `did:` prefix and `:` suffix. For example, support for the DID method  `example` would be represented by `did:example:` as a string value. Specifying `did` as a supported option in `subject_identifier_types_supported` while omitting `did_methods_supported` indicates the Self-Issued OP will attempt to support all DID methods.

Note: need to confirm valid `alg` values that we want to explicitly support for `id_token_signing_alg_values_supported` and  `request_object_signing_alg_values_supported`
Note: Make sure description of `subject_syntax_types_supported` and `did_methods_supported` is consistent with that in the RP Registration section.

Other Discovery parameters defined in section 3 of [@!OpenID.Discovery] MAY be used. 

The RP MUST use the `authorization_endpoint` defined in Self-Issued OP Discovery Metadata to construct the request. Issuer identifier of the Self-Issued OP, or `iss` Claim in the ID Token, MUST be the issuer identifier specified in the Discovery Metadata. 

#### Choice of `authorization_endpoint` {#choice-of-authoriation-endpoint}

As the `authorization_endpoint` of a Self-Issued OP, the use of Universal Links ot App Links is **RECOMMENDED** over the use of custom URI schemes. 

The implementors are highly encouraged to explore other options before using custom URI schemes such as `openid:` due to the known security issues of the custom URI schemes, such as lack of controls to prevent unknown applications from attempting to service authentication requests. See (invocation-using-custom-schema) in Privacy Considerations section for more details.

Note that this section is subject to changes in mobile OS and browser mechanisms.

### Separate identifier per Self-Issued OP (need to decide to keep or not)

When the RP wants to provide End-user choice to select from multiple possible Self-Issued OPs, it MAY present a static list of the supported options. This is similar to the process of supporting multiple different social networks represented as traditional OPs. In this scenario, the Self-Issued OP implementations would have unique identifiers, which could be used to resolve unique metadata, such as custom URI schemes, or universal links and app links.

### Common identifier for one or more Self-Issued OPs (need to decide to keep or not)

The RP can also enable End-User choice while using the same URI if Self-Issued OP implementations belong to a trust framework, and the trust framework may dictacte a common identifier for a set of implementations. This identifier should be communicated to the RP as an `authorization_endpoint` URI which every Self-Issued OP supports and has registered with the underlying browser or operating system. Invocation of this endpoint then delegates the act of selecting any appropriate Self-Issued OP to the underlying browser or operating system.

### Currently known browser behavior (need to decide to keep or not)

The browser or operating system typically has a process by which native applications and websites can register support that one or more apps be called when a HTTPS URI is triggered in lieu of a system browser. This feature goes by several names including "App Links" and "Universal Links", and **MAY** be used to invoke an installed/registered Self-Issued OP. If no appropriate application has been rendered, the request for a Self-Issued OP will go to a browser, which MAY display additional information such as appropriate software options.
If the underlying browser or operating system restricts application support for HTTPS URL handling to an authoritative list, the list would be administered under the trust framework to reflect certified and/or audited implementations.
Note: clarify why authoritative list is relevant
Operating systems also typically have a functionality by which native applications and websites can register a preference that one or more apps be called when a URI underneath a scheme that the platform or browser allows. For custom URI scheme, there is typically no platform or other controls limiting the ability of applications to register such schemes. If no available application supports the custom URI scheme, the platform or browser will typically generate a modal error and present it to the End-User.

## Relying Party Registration

When Self-Issued OP request is signed, the public key to verify the signature **MUST** be obtained by resolving Relying Party's `client_id` as defined in {#rp-resolution}. The rest of the RP Registration metadata **SHOULD** be included in the `registration` parameter inside the Self-Issued OP request, or could be included in the Entity Statement if OpenID Federation 1.0 Automatic Registration method is used.

`registration` parameters **MUST NOT** include `redirect_uris` to prevent attackers from inserting malicious Redirection URI. If `registration` parameter includes `redirect_uris`, Self-Issued OP **MUST** ignore it and only use `redirect_uri` directly supplied in the Self-Issued OP request.

Note that in Self-Issued OP flow no registration response is returned. A successful authentication response implicitly indicates that the registration parameters were accepted.

### Relying Party Registration Parameter {#rp-registration-parameter}

OpenID Connect defines the following negotiation parameters to enable Relying Party to provide information about itself to a Self-Issued OP that would normally be provided to an OP during Dynamic Client Registration:

* `registration` 
  * **OPTIONAL**. This parameter enables RP Registration Metadata to be passed in a single, self-contained parameter. The value is a JSON object containing RP Registration Metadata values. The registration parameter value is represented in an OAuth 2.0 request as a UTF-8 encoded JSON object (which ends up being form-urlencoded when passed as an OAuth parameter). When used in a Request Object value, per Section 6.1, the JSON object is used as the value of the registration member.

* `registration_uri` 
  * **OPTIONAL**. This parameter enables RP Registration Metadata to be passed by reference, rather than by value. The request_uri value is a URL using the https scheme referencing a resource containing RP Negotiation Metadata values. The contents of the resource referenced by the URL MUST be a RP Registration Metadata Object. The scheme used in the `registration_uri` value MUST be https. The request_uri value MUST be reachable by the Self-Issued OP, and SHOULD be reachable by the RP. This parameter is used identically to the request parameter, other than that the Relying Party registration metadata value is retrieved from the resource at the specified URL.

If one of these parameters is used, the other MUST NOT be used in the same request.

RP Negotiation metadata values are defined in Section 4.3 and Section 2.1 of the OpenID Connect Dynamic RP Registration 1.0 [@!OpenID.Registration] specification as well as [@!RFC7591].

Metadata parameters should preferably be sent by reference as a URI using `registration_uri` parameter, but when RP cannot host a webserver, metadata parameters should be sent by value using `registration` parameter.

`registration` and `registration_uri` parameters SHOULD NOT be used when the OP is not a Self-Issued OP.

### Relying Party Metadata Resolution Methods {rp-resolution}

This specification defines two methods of resolving `client_id` of the RP to obtain RP's public key and metadata. These methods are specific to different syntaxes that the `client_id` may utilize. 

Other resolution methods may be defined in the future versions of this specification or by the Trust Frameworks.

#### OpenID Federation 1.0 Automatic Registration

When Relying Party's `client_id` is expressed as an `https` URI, Automatic Registration defined in [OpenID.Federation] MUST be used. 

The Relying Party's Entity Identifier defined in section 1.2 of OpenID.Federation] MUST be `client_id`. When the Self-Issued Request is signed, Self-Issued OP MUST obtain the public key from the `jwks` property in the Relying Party's Entity Statement defined in section 3.1 of [OpenID.Federation]. Metadata other than the public keys MUST also be obtained from the Entity Statement.

Note that to use Automatic Registration, clients would be required to have an individual identifier and an associated public key(s), which is not always the case for the public/native app clients.

#### Decentralized Identifier Resolution

When the Relying Party's `client_id` is expressed as a `did` URI as defined in [@!DID-CORE], a public key used to sign the request MUST be obtained from the `verificationMethod` property of a DID Document. Since DID Document may include multiple public keys, a particular public key used to sign the request in question MUST be identified by the `kid` in the header. To obtain the DID Document, Self-Issued OP MUST use DID Resolution defined by the DID method must be used by the RP.

RP metadata other than the public key MUST be obtained from the `registration` parameter as defined in {#rp-registration-parameter}.

### Relying Party Registration Metadata Values {#rp-metadata}

This extension defines the following RP Registration Metadata values, used by the RP to provide information about itself to the Self-Issued OP:

* `subject_syntax_types_supported`
    * REQUIRED. A JSON array of strings representing supported Subject Syntax Types. Valid values include `jkt` and `did`. For detailed description, see #sub-syntax-type.
* `did_methods_supported`
    * OPTIONAL. A JSON array of strings representing supported DID methods, with a `did:` prefix and `:` suffix. For example, support for the DID method  `example` would be represented by `did:example:` as a string value. Specifying `did` as a supported option in `subject_identifier_types_supported` while omitting `did_methods_supported` indicates the Relying Party will attempt to support all DID methods.

Other registration metadata MAY be used as defined by [@!OpenID.Registration] as well as [@!RFC7591]. Examples are explanatory parameters such as `policy_uri`, `tos_uri`, and `logo_uri`. If the RP uses more than one Redirection URI, the `redirect_uris` parameter would be used to register them. Finally, if the RP is requesting encrypted responses, it would typically use the `jwks_uri`, `id_token_encrypted_response_alg` and `id_token_encrypted_response_enc` parameters.

The following is a non-normative example of the supported RP Registration Metadata Values:

```json
{
  "subject_syntax_types_supported": [
    "did",
    "jkt"
  ],
  "did_methods_supported": [
    "did:key:",
    "did:example:"
  ]
}
```

#### Subject Syntax Types {#sub-syntax-type}

  Subject Syntax Type refers to a type of an identifier used in a `sub` claim in the ID Token issued by a Self-Issued OP. `sub` in Self-Issued OP flow serves as an identifier of the Self-Issued OP's Holder, and is used to obtain cryptographic material to verify the signature on the ID Token.  

 Two types are defined by this specification to be used in RP Registration Metadata `subject_syntax_types_supported`:

* `jkt`
    * JWK Thumbprint subject syntax type. When this type is used, the `sub` claim value MUST be the base64url encoded representation of the thumbprint of the key in the `sub_jwk` claim [@!RFC7638], and `sub_jwk` MUST be included in the Self-Issued OP response.

* `did`
     * Decentralized Identifier subject syntax type. When this type is used,  the `sub` value MUST be a DID defined in [@!DID-CORE], and `sub_jwk` MUST NOT be included in the Self-Issued OP response. The subject syntax type MUST be cryptographicaly verified against the resolved DID Document as defined in Self-Issued OP Validation.

NOTE: Consider adding a subject syntax type for OpenID Connect Federation entity statements.

## Relying Party Registration Metadata Error Response {#rp-reg-error}

This extension defines the following error codes that MUST be returned when the Self-Issued OP does not support some Relying Party Registration metadata values received from the Relying Party in the registration parameter:

* `did_methods_not_supported`
    * The Self-Issued OP does not support any DID methods included in `did_methods_supported` parameter.
* `subject_syntax_types_not_supported`
    * The Self-Issued OP does not support any Subject Syntax Types included in `subject_syntax_types_supported` parameter.
* `credential_formats_not_supported`
    * The Self-Issued OP does not support any credential formats included in `credential_formats_supported` parameter.
* `invalid_registration_uri`
    * The `registration_uri` in the Self-Issued OpenID Provider request returns an error or contains invalid data.
* `invalid_registration_object`
    * The `registration` parameter contains an invalid RP Registration Metadata Object.
* `value_not_supported`
    * The Self-Issued OP does not support one or more of the RP Registration Metadata values defined in {#rp-metadata}. When not supported metadata values include DID methods, Subject Syntax Types, or credential formats, more specific error message as defined above must be used.

The error response must be made in the same manner as defined in Section 3.1.2.6 of [@!OpenID].


# Identifier Portability and Verifiable Presentation Support

# Self-Issued OpenID Provider Request {#siop_authentication_request}

The RP sends the Authentication Request to the Authorization Endpoint with the following parameters:

* `scope`
    * REQUIRED. As specified in Section 3.1.2 of [@!OpenID].
* `response_type`
    * REQUIRED. Constant string value `id_token`.
* `client_id`
    * REQUIRED. Client ID value for the Client, which in this case contains the `redirect_uri` value of the RP.
* `redirect_uri`
    * REQUIRED. MUST equal the `client_id` value. MUST be included for compatibility reasons.
* `id_token_hint`
    * OPTIONAL. As specified in Section 3.1.2 of [@!OpenID]. If the ID Token is encrypted for the Self-Issued OP, the `sub` (subject) of the signed ID Token MUST be sent as the `kid` (Key ID) of the JWE.
* `claims`
    * OPTIONAL. As specified in Section 5.5 of [@!OpenID].
* `registration`
    * OPTIONAL. This parameter is used by the RP to provide information about itself to a Self-Issued OP that would normally be provided to an OP during Dynamic RP Registration, as specified in {#rp-registration-parameter}.
* `registration_uri`
    * OPTIONAL. This parameter is used by the RP to provide information about itself to a Self-Issued OP that would normally be provided to an OP during Dynamic RP Registration, as specified in {#rp-registration-parameter}.
* `request`
    * OPTIONAL. Request Object value, as specified in Section 6.1 of [@!OpenID]. The Request Object MAY be encrypted to the Self-Issued OP by the RP. In this case, the `sub` (subject) of a previously issued ID Token for this RP MUST be sent as the `kid` (Key ID) of the JWE.
* `request_uri`
    * OPTIONAL. URL where Request Object value can be retrieved from, as specified in Section 6.2 of [@!OpenID].

To prevent duplication, registration parameters MUST be passed either in `registration` or `registration_uri` parameters or `request` or `request_uri` parameters. Therefore, when `request` or `request_uri` parameters are NOT present, and RP is NOT using OpenID Federation 1.0 Automatic Registration to pass entire registration metadata, `registration` or `registration_uri` parameters MUST be present in the request. When `request` or `request_uri` parameters are present, `registration` or `registration_uri` parameters MUST be included in either of those parameters.

Since it is an Implicit Flow response, `nonce` Claim MUST be present. 

Other parameters MAY be sent. Note that all Claims are returned in the ID Token.

The entire URL MUST NOT exceed 2048 ASCII characters.

The following is a non-normative example HTTP 302 redirect response by the RP, which triggers the User Agent to make an Authentication Request to the Self-Issued OP (with line wraps within values for display purposes only):

```
  HTTP/1.1 302 Found
  Location: openid://?
    response_type=id_token
    &client_id=https%3A%2F%2Fclient.example.org%2Fcb
    &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
    &scope=openid%20profile
    &state=af0ifjsldkj
    &nonce=n-0S6_WzA2Mj
    &registration=%7B%22logo_uri%22%3A%22https%3A%2F%2F
      client.example.org%2Flogo.png%22%7D
```

# Self-Issued OpenID Provider Response {#siop-authentication-response}

A Self-Issued OpenID Provider Response is returned when Self-Issued OP supports all Relying Party Registration metadata values received from the Relying Party in the `registration` parameter. If one or more of the Relying Party Registration Metadata Values is not supported, Self-Issued OP MUST return an error according to (#rp-reg-error).

The response contains an ID Token and, if applicable, further response parameters as defined in extensions. As an example, the response MAY also include a VP token as defined in [OIDC4VP].

This extension defines the following claims to be included in the ID token for use in Self-Issued OpenID Provider Responses:

* `sub`
    * REQUIRED. Subject identifier value. When Subject Syntax Type is `jkt`, the value is the base64url encoded representation of the thumbprint of the key in the `sub_jwk` Claim. When Subject Syntax Type is `did`, the value is a Decentralized Identifier. The thumbprint value of Subject Syntax Type `jkt` is computed as the SHA-256 hash of the octets of the UTF-8 representation of a JWK constructed containing only the REQUIRED members to represent the key, with the member names sorted into lexicographic order, and with no white space or line breaks. For instance, when the `kty` value is `RSA`, the member names `e`, `kty`, and `n` are the ones present in the constructed JWK used in the thumbprint computation and appear in that order; when the `kty` value is `EC`, the member names `crv`, `kty`, `x`, and `y` are present in that order. Note that this thumbprint calculation is the same as that defined in the JWK Thumbprint [@!RFC7638] specification.
* `sub_jwk`
    * REQUIRED. A JSON object for a secure binding between the subject of the verifiable credential and the subject identifier (and related keys) of the holder who creates the presentation. When Subject Syntax Type is `jkt`, the key is a bare key in JWK [JWK] format (not an X.509 certificate value). When Subject Syntax Type is `did`, `sub_jwk` MUST contain a `kid` member that is a DID URL referring to the verification method in the Self-Issued OP's DID Document that can be used to verify the JWS of the ID Token directly or indirectly. Use of the `sub_jwk` Claim is NOT RECOMMENDED when the OP is not Self-Issued.

Whether the Self-Issued OP is a mobile client or a web client, the response is the same as the normal Implicit Flow response with the following refinements. Since it is an Implicit Flow response, the response parameters will be returned in the URL fragment component, unless a different Response Mode was specified.

1. The `iss` (issuer) Claim Value is `https://self-issued.me/v2`.
2. The `sub` (subject) Claim value is either the base64url encoded representation of the thumbprint of the key in the `sub_jwk` Claim or a Decentralized Identifier.
3. When `sub` Claim value is the base64url encoded representation of the thumbprint, a `sub_jwk` Claim is present, with its value being the public key used to check the signature of the ID Token.
4. No Access Token is returned for accessing a UserInfo Endpoint, so all Claims returned MUST be in the ID Token.

## Verifiable Presentation Support

Self-Issued OP and the RP that wish to support request and presentation of Verifiable Presentations MUST be compliant with OpenID Connect for Verifiable Presentations [@!OIDC4VP] and W3C Verifiable Credentials Specification [@!VC-DATA].

Verifiable Presentation is a tamper-evident presentation encoded in such a way that authorship of the data can be trusted after a process of cryptographic verification. Certain types of verifiable presentations might contain selectively disclosed data that is synthesized from, but does not contain, the original verifiable credentials (for example, zero-knowledge proofs). [@!VC-DATA]


# Self-Issued ID Token Validation {#siop-id_token-validation}
See [@!OIDC4VP] on how to support multiple credential formats such as JWT and Linked Data Proofs.

To validate the ID Token received, the RP MUST do the following:

1. The Relying Party (RP) MUST validate that the value of the `iss` (issuer) Claim equals to the `authorization_endpoint` in the Self-Issued OP metadata. When static Self-Issued OP Discovery metadata has been used, `iss` MUST be `https://self-issued.me/v2`. When dynamic Self-Issued OP Discovery metadata has been performed, `iss` MUST exactly match the `issuer` identifier pre-obtained by the RP.
1. The RP MUST validate that the `aud` (audience) Claim contains the value of the `redirect_uri` that the RP sent in the Authentication Request as an audience.
1. The RP MUST validate the signature of the ID Token. When Subject Syntax Type is `jkt`, validation is done according to JWS [JWS] using the algorithm specified in the `alg` header parameter of the JOSE Header, using the key in the `sub_jwk` Claim. The key MUST be a bare key in JWK format (not an X.509 certificate value). The RP MUST validate that the algorithm is one of the allowed algorithms (as in `id_token_signing_alg_values_supported`). When Subject Syntax Type is `did`, validation is performed against the key obtained from a DID Document. DID Document MUST be obtained by resolving a Decentralized Identifier included in the `sub` claim using DID Resolution as defined by a DID Method specification of the DID Method used. Since `verificationMethod` property in the DID Document may contian multiple public key sets, public key identified by a key identifier `kid` in a Header of a signed ID Token MUST be used to validate that ID Token.
2. The RP MUST validate the `sub` value. When Subject Syntax Type is `jkt`, the RP MUST validate that the `sub` claim value equals the base64url encoded representation of the thumbprint of the key in the `sub_jwk` Claim, as specified in (#siop-authentication-response). When Subject Syntax Type is `did`, the RP MUST validate that the `sub` claim value equals the `id` property in the DID Document. 
3. The current time MUST be before the time represented by the `exp` Claim (possibly allowing for some small leeway to account for clock skew).
 The `iat` Claim can be used to reject tokens that were issued too far away from the current time, limiting the amount of time that nonces need to be stored to prevent attacks. The acceptable range is RP-specific.
2. The RP MUST validate that a `nonce` Claim is present and is the same value as the one that was sent in the Authentication Request. The Client SHOULD check the `nonce` value for replay attacks. The precise method for detecting replay attacks is RP specific.

The following is a non-normative example of a base64url decoded Self-Issued ID Token body (with line wraps within values for display purposes only):

```json
{
  "iss": "https://self-issued.me/v2",
  "sub": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
  "aud": "https://client.example.org/cb",
  "nonce": "n-0S6_WzA2Mj",
  "exp": 1311281970,
  "iat": 1311280970,
  "sub_jwk": {
    "kty": "RSA",
    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt
    VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W
    -5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQ
    MicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdk
    t-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-cs
    FCur-kEgU8awapJzKnqDKgw",
    "e": "AQAB"
  }
}
```

# Cross Device SIOP

This section describes how SIOP is used in cross-device scenarios. In contrast to on-device scenarios, neither RP nor SIOP can communicate to each other via HTTP redirects through a user agent. The flow is therefore modified as follows:

1. The RP prepares a SIOP request and renders it as a QR code.
2. The user scans the QR code with her smartphone's camera app.
3. The standard mechanisms for invoking the SIOP are used on the smartphone (based on the `openid` custom scheme).
4. The SIOP processes the authentication request.
5. Upon completion of the authentication request, the SIOP directly sends a HTTP POST request with the authentication response to an endpoint exposed by the RP.

Note: The request in Step 5 is not a form post request where the SIOP would respond to a user agent with a form, which automatically triggers a POST request to the RP. The SIOP sends this request directly to the RP's endpoint.

## Authentication Request

The cross-device authentication request differs from the on-device variant as defined in (#siop_authentication_request) as follows:

* This specification introduces a new response mode `post` in accordance with [OIDM]. This response mode is used to request the SIOP to deliver the result of the authentication process to a certain endpoint. The additional parameter `response_mode` is used to carry this value.
* This endpoint the SIOP shall deliver the authentication result to is conveyed in the standard parameter `redirect_uri`.
* The RP MUST ensure the `nonce` value used for a particular transaction is available at this endpoint for security checks.

Here is an example of an authentication request URL:

```
    openid://?
    response_type=id_token
    &response_mode=post
    &client_id=https%3A%2F%2Fclient.example.org%2Fcb
    &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
    &scope=openid%20profile
    &state=af0ifjsldkj
    &nonce=n-0S6_WzA2Mj
    &registration=%7B%22subject_syntax_types_supported%22:%5B%22jkt%22%5D,
    %22id_token_signing_alg_values_supported%22:%5B%22RS256%22%5D%7D
```

Note: Such an authentication request might result in a large QR code, especially when including a `claims` parameter and extensive registration data. A RP MAY consider to use a `request_uri` in such a case.

## Authentication Response

The SIOP sends the authentication response to the endpoint passed in the `redirect_uri` authentication request parameter using a HTTP POST request using "application/x-www-form-urlencoded" encoding. The authentication response contains the parameters as defined in (#siop-authentication-response).

The following shows a non-normative example of an authentication response:

```http
  POST /cb HTTP/1.1
  Host: client.example.com
  Content-Type: application/x-www-form-urlencoded

  &id_token=eyJ0 ... NiJ9.eyJ1c ... I6IjIifX0.DeWt4Qu ... ZXso
```

## ID Token Validation

The RP MUST perform all the check as defined in (#siop-id_token-validation).

Additionally, the RP MUST check whether the `nonce` claim value provided in the ID Token is known to the RP and was not used before in an authentication response.

# References

The following is a non-normative example of an ID token containing a verifiable presentation (with line wraps within values for display purposes only):
```json
{
  "iss": "https://self-issued.me/v2",
  "sub": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
  "aud": "https://client.example.org/cb",
  "nonce": "n-0S6_WzA2Mj",
  "exp": 1311281970,
  "iat": 1311280970,
  "sub_jwk": {
    "kty": "RSA",
    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt
    VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W
    -5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQ
    MicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdk
    t-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-cs
    FCur-kEgU8awapJzKnqDKgw",
    "e": "AQAB"
  },
  "verifiable_presentations": [
    {
      "format": "vp_jwt",
      "presentation": "ewogICAgImlzcyI6Imh0dHBzOi8vYm9vay5pdHNvdXJ3ZWIub...IH0="
    }
  ]
}
```

Note: Further processing steps are required if the authentication response contains verifiable presentations - see [@!OIDC4VP].

## Security Considerations

### Invocation using Custom Schema {#invocation-using-custom-schema}

Usage of custom schemas as a way to invoke a Self-Issued OP may lead to phishing attacks and undefined behavior.

Custom schema is a mechanism offered by Mobile Operating System providers. If an application developer registers custom schema with the application, that application will be invoked when a request containing custom schema is received by the device.

Any malicious app can register the custom schema already used by another app, imitate the user interface and impersonate a good app.

When more than one Self-issued OP with the same custom schema has been installed on one device, the behavior of Self-Issued OP is undefined.

## Privacy Considerations

### Selective disclosure and un-linkable presentations
Usage of decentralized identifiers does not automatically prevent possible RP correlation. If a status check of the presentation is done, IdP / SIOP correlation can occur.

Consider supporting selective disclosure and un-linkable presentations using zero-knowledge proofs or single-use credentials instead of traditional correlatable signatures.

# References

## Non-Normative References

* [draft-jones-self_issued_identifier] https://bitbucket.org/openid/connect/src/master/SIOP/draft-jones-self_issued_identifier.md
* [siop-requirements] https://bitbucket.org/openid/connect/src/master/SIOP/siop-requirements.md
* [OIX] https://openidentityexchange.org/networks/87/item.html?id=365

# Relationships to other documents

The scope of this draft was an extention to OpenID Connect Chapter 7 Self-Issued OpenID Provider. However, some sections of it could become applicable more generally to the entire OpenID Connect specification.

{backmatter}

<reference anchor="VC-DATA" target="https://www.w3.org/TR/vc-data-model/">
        <front>
        <title>Decentralized Identifiers (DIDs) v1.0</title>
        <author fullname="Manu Sporny">
            <organization>Digital Bazaar</organization>
        </author>
        <author fullname="Grant Noble">
            <organization>ConsenSys</organization>
        </author>
        <author fullname="Dave Longley">
            <organization>Digital Bazaar</organization>
        </author>
        <author fullname="Daniel C. Burnett">
            <organization>ConsenSys</organization>
        </author>
        <author fullname="Brent Zundel">
            <organization>Evernym</organization>
        </author>
        <date day="19" month="Nov" year="2019"/>
        </front>
</reference>

<reference anchor="OpenID" target="http://openid.net/specs/openid-connect-core-1_0.html">
  <front>
    <title>OpenID Connect Core 1.0 incorporating errata set 1</title>
    <author initials="N." surname="Sakimura" fullname="Nat Sakimura">
      <organization>NRI</organization>
    </author>
    <author initials="J." surname="Bradley" fullname="John Bradley">
      <organization>Ping Identity</organization>
    </author>
    <author initials="M." surname="Jones" fullname="Mike Jones">
      <organization>Microsoft</organization>
    </author>
    <author initials="B." surname="de Medeiros" fullname="Breno de Medeiros">
      <organization>Google</organization>
    </author>
    <author initials="C." surname="Mortimore" fullname="Chuck Mortimore">
      <organization>Salesforce</organization>
    </author>
   <date day="8" month="Nov" year="2014"/>
  </front>
</reference>

<reference anchor="OpenID.Registration" target="https://openid.net/specs/openid-connect-registration-1_0.html">
  <front>
    <title>OpenID Connect Dynamic Client Registration 1.0 incorporating errata set 1</title>
	  <author fullname="Nat Sakimura">
      <organization>NRI</organization>
    </author>
    <author fullname="John Bradley">
      <organization>Ping Identity</organization>
    </author>
    <author fullname="Mike Jones">
      <organization>Microsoft</organization>
    </author>
    <date day="8" month="Nov" year="2014"/>
  </front>
 </reference>

<reference anchor="OpenID.Discovery" target="https://openid.net/specs/openid-connect-discovery-1_0.html">
  <front>
    <title>OpenID Connect Core 1.0 incorporating errata set 1</title>
    <author initials="N." surname="Sakimura" fullname="Nat Sakimura">
      <organization>NRI</organization>
    </author>
    <author initials="J." surname="Bradley" fullname="John Bradley">
      <organization>Ping Identity</organization>
    </author>
    <author initials="M." surname="Jones" fullname="Mike Jones">
      <organization>Microsoft</organization>
    </author>
    <author initials="E." surname="Jay" fullname="Edmund Jay">
      <organization>Illumila</organization>
    </author>
   <date day="8" month="Nov" year="2014"/>
  </front>
</reference>

<reference anchor="OIDC4VP" target="https://openid.net/specs/openid-connect-4-verifiable-presentations-1_0.html">
  <front>
    <title>OpenID Connect Core 1.0 incorporating errata set 1</title>
    <author initials="O." surname="Terbu" fullname="Oliver Terbu">
      <organization>ConsenSys Mesh</organization>
    </author>
    <author initials="T." surname="Lodderstedt" fullname="Torsten Lodderstedt">
      <organization>yes.com</organization>
    </author>
    <author initials="K." surname="Yasuda" fullname="Kristina Yasuda">
      <organization>Microsoft</organization>
    </author>
    <author initials="A." surname="Lemmon" fullname="Adam Lemmon">
      <organization>Convergence.tech</organization>
    </author>
    <author initials="T." surname="Looker" fullname="Tobias Looker">
      <organization>Mattr</organization>
    </author>
    <date day="20" month="May" year="2021"/>
  </front>
</reference>

<reference anchor="DID-CORE" target="https://www.w3.org/TR/2021/PR-did-core-20210803/">
        <front>
        <title>Decentralized Identifiers (DIDs) v1.0</title>
        <author fullname="Manu Sporny">
            <organization>Digital Bazaar</organization>
        </author>
        <author fullname="Amy Guy">
            <organization>Digital Bazaar</organization>
        </author>
        <author fullname="Markus Sabadello">
            <organization>Danube Tech</organization>
        </author>
        <author fullname="Drummond Reed">
            <organization>Evernym</organization>
        </author>
        <date day="3" month="Aug" year="2021"/>
        </front>
</reference>

<reference anchor="OIDM" target="https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html">
        <front>
        <title>OAuth 2.0 Multiple Response Type Encoding Practices</title>
        <author initials="B." surname="de Medeiros" fullname="Breno de Medeiros">
            <organization>Google</organization>
        </author>
        <author initials="M." surname="Scurtescu" fullname="M. Scurtescu">
            <organization>Google</organization>
        </author>        
        <author initials="P." surname="Tarjan" fullname="Facebook">
            <organization>Evernym</organization>
        </author>
        <author initials="M." surname="Jones" fullname="Mike Jones">
            <organization>Microsoft</organization>
        </author>
        <date day="25" month="Feb" year="2014"/>
        </front>
</reference>

<reference anchor="RFC7638" target="https://tools.ietf.org/html/rfc7638">
        <front>
        <title>JSON Web Key (JWK) Thumbprint</title>
        <author initials="M." surname="Jones" fullname="Mike Jones">
            <organization>Microsoft</organization>
        </author>
        <author initials="N." surname="Sakimura" fullname="Nat Sakimura">
            <organization>NRI</organization>
        </author>
        <date day="1" month="Sept" year="2015"/>
        </front>
</reference>

# IANA Considerations

TBD

# Notices 

Copyright (c) 2021 The OpenID Foundation.

The OpenID Foundation (OIDF) grants to any Contributor, developer, implementer, or other interested party a non-exclusive, royalty free, worldwide copyright license to reproduce, prepare derivative works from, distribute, perform and display, this Implementers Draft or Final Specification solely for the purposes of (i) developing specifications, and (ii) implementing Implementers Drafts and Final Specifications based on such documents, provided that attribution be made to the OIDF as the source of the material, but that such attribution does not indicate an endorsement by the OIDF.

The technology described in this specification was made available from contributions from various sources, including members of the OpenID Foundation and others. Although the OpenID Foundation has taken steps to help ensure that the technology is available for distribution, it takes no position regarding the validity or scope of any intellectual property or other rights that might be claimed to pertain to the implementation or use of the technology described in this specification or the extent to which any license under such rights might or might not be available; neither does it represent that it has made any independent effort to identify any such rights. The OpenID Foundation and the contributors to this specification make no (and hereby expressly disclaim any) warranties (express, implied, or otherwise), including implied warranties of merchantability, non-infringement, fitness for a particular purpose, or title, related to this specification, and the entire risk as to implementing this specification is assumed by the implementer. The OpenID Intellectual Property Rights policy requires contributors to offer a patent promise not to assert certain patent claims against other contributors and against implementers. The OpenID Foundation invites any interested party to bring to its attention any copyrights, patents, patent applications, or other proprietary rights that may cover technology that may be required to practice this specification.

# Document History

    [[ To be removed from the final specification ]]

    -05
    * added RP Metadata resolution methods
    * editorial - language in Relying Party Registration Metadata Error Response
    
    -04

    * added cross device flow
    * clarified handling for did-based sub and sub_jwk
    * Revising of introductory text and scope of SIOPv2
    * corrected typos and reworked registration example data

    -03
    
    * sub_jwk made optional for Subject Syntax Type DID and mandatory for subtype jwk thumbprint
    * Added text that nonce is mandatory
    * Replaced vp claim with reference to OIDC4VP draft
    * Adopted SIOP chooser as SIOP Discovery
    * Deprecated openid:// for SIOP Discovery as not recommended
    * Clarified Discovery and Registration metadata
    * Formatted Normative Reference Section to mmarkdown

    -02
     * Converted into mmarkdown

    -01
     * Version proposed for working group adoption