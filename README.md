# Trustworthy and Efficient Digital Twins in Post-Quantum Era with Hybrid Hardware-Assisted Signatures
**Hardware ASsited Efficient Signatures (HASES)** implemnents a series of efficient digital signatures tailored for the context of digital twins. 

## Prerequisites
1. [OpenSSL](https://www.openssl.org/)
2. [Intel(R) SGX SDK](https://github.com/intel/linux-sgx)


## Contents

The repository includes the following implementations:
* [`src`](src/): contains the digital signatures 
* [`data`](data/): contains the data selected to perform our benchmark.
* [`counterparts`](counterparts/): contains information and implementation of our selected counterparts.


## License

**HASES** is licensed under Apache 2.0 license; see [`License`](LICENSE) for details.


## Important Note

The implementation is just for the proof of concept. There are several places in the code that were implemented INSECURELY for the sake of code readability and understanding. We are not responsible for any damages if the code is used for commercial purposes.
