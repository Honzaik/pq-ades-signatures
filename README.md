# Post-quantum AdES playground.
Proof of concept implementation of post-quantum AdES signatures. This project contains a benchmark of AdES and a simple AdES signing tool.


# Dependencies
This implementation requires three dependencies:
- [DSS](https://github.com/Honzaik/pqdss/tree/6.3-ades-poc): a library implementing AdES and related components.
- [Apache Santuario](https://github.com/Honzaik/santuario-xml-security-java-pq/tree/4.20-ades-poc): an XML security library. Dependency of DSS due to XAdES.
- [BouncyCastle](https://github.com/Honzaik/bc-java/tree/1.83-ades-poc): a cryptographic library used by both Apache Santuario and DSS.

We tested all code on Java 21. Note that at the time of writing, e.g., Java 25 is not compatible therefore we recommend sticking with Java 21. 

BouncyCastle is built using its own included Gradle version. Other libraries and the final project is built with Maven 3.9.11.

## Forked BouncyCastle installation
First, we build our BouncyCastle fork and install it into our local Maven repository.

Specifically, we require 3 BouncyCastle components: bcprov, bcpkix and bcutil.

```
git clone git@github.com:Honzaik/bc-java.git bouncycastle
cd bouncycastle
git checkout 1.83-ades-poc
./gradlew prov:build -x test
./gradlew pkix:build -x test
./gradlew util:build -x test
```

After each component is build. Use the following commands to install it into local Maven repository.

```
mvn install:install-file -Dfile="prov/build/libs/bcprov-jdk18on-1.83-SNAPSHOT.jar" -DgroupId="org.bouncycastle" -DartifactId="bcprov-jdk18on" -Dversion="1.83-SNAPSHOT" -Dpackaging=jar
mvn install:install-file -Dfile="pkix/build/libs/bcpkix-jdk18on-1.83-SNAPSHOT.jar" -DgroupId="org.bouncycastle" -DartifactId="bcpkix-jdk18on" -Dversion="1.83-SNAPSHOT" -Dpackaging=jar
mvn install:install-file -Dfile="util/build/libs/bcutil-jdk18on-1.83-SNAPSHOT.jar" -DgroupId="org.bouncycastle" -DartifactId="bcutil-jdk18on" -Dversion="1.83-SNAPSHOT" -Dpackaging=jar
```

## Forked Apache Santuario installation
Apache Santuario installation is easier than BouncyCastle as it supports Maven.

```
git clone git@github.com:Honzaik/santuario-xml-security-java-pq.git santuario
cd santuario
git checkout 4.20-ades-poc
mvn install -DskipTests
```

## Forked DSS installation
Similar to Apache Santuario installation.

```
git clone git@github.com:Honzaik/pqdss.git dss
cd dss
git checkout 6.3-ades-poc
mvn install -P quick-init
```

# Benchmark build and usage
This concerns the benchmark part of our implementation.

## Build
Assuming this repository is cloned. To build the benchmark executable run
```
mvn package spring-boot:repackage -P buildBenchmarksJAR 
```

This creates a standalone executable in the `target/` directory with the name `AdESBenchmark.jar`

## How to execute benchmarks
The benchmark executable expects 5 arguments
```
java -jar AdESBenchmark.jar [warmup] [repetitions] [list;of;classical;pkis] [list;of;pq;pkis] [list;of;composite;pkis]
```
where
- `[warmup]` is an integer indicating the number of repetitions that are done before the actual benchmark to minimize noise due to JVM optimization etc.
- `[repetitions]` is an integer indicating the actual number of repetitions benchmarked. In total, the benchmarking software does `[warmup+repetitions]` executions.
- `[list;of;classical;pkis]` is a semicolon separated list of classical signatures to be tested. Currently, only ECDSA with P-256 is supported under the name `ecdsa256`.
- `[list;of;pq;pkis]` analogous to the previous list except that the list concerns purely post-quantum signatures. The supported purely post-quantum signatures are ML-DSA (`mldsa44`, `mldsa65`, `mldsa87`) and SLH-DSA in various configurations (`slhdsa_sha2_128f`, `slhdsa_sha2_128s`), parameter names correspond to filenames in https://github.com/Honzaik/pq-ades-signatures/tree/main/src/main/resources/pki
- `[list;of;composite;pkis]` analogous to the previous list except that the list concerns composite hybrid post-quantum signatures. Currently, the following three composites are supported: `mldsa44ecdsa256`, `mldsa65ecdsa384`, `mldsa87ecdsa384`.

Example execution command:
```
java -jar AdESBenchmark.jar 50 500 "ecdsa256" "mldsa44;mldsa65;mldsa87" "mldsa44ecdsa256;mldsa65ecdsa384;mldsa87ecdsa384"
```

Regarding post-quantum hybrid AdES, it supports composite hybrids and sequential hybrids (application of a purely post-quantum archival timestamp). Composite hybrids are specified explicitly as parameters whereas sequential hybrids are automatically created by pairing each classical algorithm with a purely post-quantum algorithm. Therefore, in the above example, the benchmark runs 3 different sequential hybrids (each with the same classical component: ECDSA P256).

## Benchmark description
The benchmark program does the following measurements. For each algorithm, each AdES format (JAdES not supported) and each signature level (B-B, B-T, B-LT and B-LTA), it sequentially tests signing and verification speeds and measures the resulting AdES signature size.

These results are output into three separate files named `AdES_benchmark_[signing/size/verification]_[warmup+repetitions]_[timestamp].txt`.

The signing and verification files have identical formats where each line represents a signing algorithm and measured values are in the format of `[mean] ± [std. dev.]` in miliseconds separated by semicolon. The order of values in each row is the following: XAdES, CAdES and PAdES, and for each format there are 4 values corresponding to signature level order: B-B, B-T, B-LT and B-LTA. Note that for sequential hybrid, the only signature level tested is B-LTA as it is only meaningful to apply the archival timestamp to an already B-LTA AdES signature.

The size results file has analogous format except the measured values are in bytes (and without std. dev.).

Note that the files used in this benchmark (the files that are signed) must be located and named `inputs/input.xml` for XAdES and CAdES, and `inputs/input.pdf` for PAdES. For example, as done here https://github.com/Honzaik/pq-ades-signatures/tree/main/inputs

# Signing tool build and usage
This concerns the signing tool part of our implementation.

## Build
Assuming this repository is cloned. To build the benchmark executable run
```
mvn package spring-boot:repackage -P buildBenchmarksJAR 
```

This creates a standalone executable in the `target/` directory with the name `AdESBenchmark.jar`

## How to execute benchmarks