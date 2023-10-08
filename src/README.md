## HASES

**HASES** unveil three digital signature algorithms:

* [`PQ-HASES`](pqhases/): is post-quantum forward-secure digital signature that rely on a commitment construct oracle to remove the signer overhead of supplying one-time public key to the verifiers.
* [`LA-HASES`](lahases/): is a lightweight aggregate signature based on elliptic curves. **LA-HASES** avoid running expensive EC scalar multiplication or pairing operations on signers by harnessing CCO as the supplier
of the costly EC commitments.
* [`HY-HASES](hyhases/): is a hybrid digital signature that combines **LA-HASES** and **PQ-HASES** via
a novel nesting approach. This achieves partial aggregation, reinforced by a PQ-FS umbrella signature.
* [`PQ-HASES (ASCON)`](pqhases-ascon/): is an optimized variant of **PQ-HASES** that employ the NIST lightweight standard Ascon, as pseudo-random function for key derivation purposes.
* [`LA-HASES (ASCON)`](lahases-ascon/): is an optimized variant of **LA-HASES** that employ the NIST lightweight standard Ascon, as pseudo-random function for key derivation purposes.