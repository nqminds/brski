# BRSKI API
This `BRSKI` API implements the bootstrapping functionalities that allows a pledge to discover or being discovered by an element of the network domain (registrar) that it will belong to and that will perform its bootstrap.

The logical elements of the bootstrapping framework are described in [RFC8995](https://www.rfc-editor.org/rfc/rfc8995.html):
```
                                           +------------------------+
   +--------------Drop-Ship----------------| Vendor Service         |
   |                                       +------------------------+
   |                                       | M anufacturer|         |
   |                                       | A uthorized  |Ownership|
   |                                       | S igning     |Tracker  |
   |                                       | A uthority   |         |
   |                                       +--------------+---------+
   |                                                      ^
   |                                                      |  BRSKI-
   V                                                      |   MASA
+-------+     ............................................|...
|       |     .                                           |  .
|       |     .  +------------+       +-----------+       |  .
|       |     .  |            |       |           |       |  .
|Pledge |     .  |   Join     |       | Domain    <-------+  .
|       |     .  |   Proxy    |       | Registrar |          .
|       <-------->............<-------> (PKI RA)  |          .
|       |        |        BRSKI-EST   |           |          .
|       |     .  |            |       +-----+-----+          .
|IDevID |     .  +------------+             | e.g., RFC 7030 .
|       |     .           +-----------------+----------+     .
|       |     .           | Key Infrastructure         |     .
|       |     .           | (e.g., PKI CA)             |     .
+-------+     .           |                            |     .
              .           +----------------------------+     .
              .                                              .
              ................................................
                            "Domain" Components
```

The API details the functions to allows implementing the below state description for a pledge:

1. Discover a communication channel to a registrar.
2. Identify itself. This is done by presenting an X.509 IDevID credential to the discovered registrar (via the proxy) in a TLS handshake. (The registrar credentials are only provisionally accepted at this time.)
3. Request to join the discovered registrar. A unique nonce is included, ensuring that any responses can be associated with this particular bootstrapping attempt.
4. Imprint on the registrar. This requires verification of the manufacturer-service-provided (MASA) voucher. A voucher contains sufficient information for the pledge to complete authentication of a registrar.
5. Enroll. After imprint, an authenticated TLS (HTTPS) connection exists between the pledge and registrar. EST [RFC7030] can then be used to obtain a domain certificate from a registrar.

