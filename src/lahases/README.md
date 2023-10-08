## LA-HASES

**Lightweight Aggregate Hardware ASsited Efficient Signatures (LA-HASES)** is a lightweight aggregate signature based on elliptic curves. LA-HASES avoid running expensive EC scalar multiplication or pairing operations on signers by harnessing CCO as the supplier
of the costly EC commitments.


## Quick start
### Building the software and executing the tests on Linux

One can quickly test LA-HASES by following the instructions below:

```sh
$ make clean ; make
```


```sh
$ ./App [MSG_LENGTH]
```

