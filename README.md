# ecctools
Small collection of tools written in C for ECC and bitcoin

## Why this programs are written in C language?
Well i like C language because compiled code is faster than interpreted code.


## How to download and run the code?

For Termux users you need to install some utilities 

```
apt update && apt upgrade
apt install root-repo
apt install git -y
apt install build-essential -y
apt install libgmp
```

Clone this repository

```
git clone https://github.com/albertobsd/ecctools.git
```

Compile:

```
make
```

## rehashaddress

A NON standard, deterministic private key generator from a password or passphrase.

what is the objective of this tool? just provide a easy way to generate deterministics privatekeys from a selected password or passphrase and number of rehashes

Advice: USE A SECURE PASSWORD

Example of use

Generate 2 privatekeys and his address after 100 thausand of rehahes

```./rehashaddress -p "}78~Et=jPQP5}MVVj2fc0X38{~I}?c" -n 2 -m 100000```

Output:

```
[I] Password: }78~Et=jPQP5}MVVj2fc0X38{~I}?c
[I] n: 2
[I] m: 100000
Privatekey: ca12010ce2daaf02611d440acd42e8bc791881375c58197cf56995059b28e797
Compress publickey: 035f149fb58e6eb5a7bcc812c1f72e5c9a3ee7ea151991a31a4d3e98e5ace25568
Compress address: 16Ln3w1JLD8s7rNni37A7SiVmVPHXEHFWF
Uncompress publickey: 045f149fb58e6eb5a7bcc812c1f72e5c9a3ee7ea151991a31a4d3e98e5ace2556850fc0b339809eda8cc9f74ee698ed018049b0cfbefe72e66dbc256622f1662d7
Uncompress address: 1NKUnTCtN3Pbm3wEVsFZFuotKkjPPi4g3B
Privatekey: 1037ea7cc723e34f3d81d9e01b5b1df081d47312a3d549b67fd635424446c1b0
Compress publickey: 026813442784ee62c0d69dcf244f91518e85f4a796a1b967758aef1b7d88abd23b
Compress address: 1JWH4qYemWFJAULUtcx1QiboDAD64Bb718
Uncompress publickey: 046813442784ee62c0d69dcf244f91518e85f4a796a1b967758aef1b7d88abd23bd7e12a189fa7d6a80154cbf29999b74bece7bfcca8a70e3df92d8ece238e8700
Uncompress address: 1Ho9VcvHcdu5Xrkv3pcME5zaPvyje1AWnM
```

Please check the comments in the source code `rehashaddress.c`


## calculatefromkey

A easy way to check the address and publickeys of a privatekey 

what is the objective of this tool? just to check a privatekey and his address and publickey

Example of use

```./calculatefromkey ca12010ce2daaf02611d440acd42e8bc791881375c58197cf56995059b28e797```

Output:

```
privatekey: ca12010ce2daaf02611d440acd42e8bc791881375c58197cf56995059b28e797
publickey compressed: 035f149fb58e6eb5a7bcc812c1f72e5c9a3ee7ea151991a31a4d3e98e5ace25568
public address compressed 16Ln3w1JLD8s7rNni37A7SiVmVPHXEHFWF
publickey uncompressed: 045f149fb58e6eb5a7bcc812c1f72e5c9a3ee7ea151991a31a4d3e98e5ace2556850fc0b339809eda8cc9f74ee698ed018049b0cfbefe72e66dbc256622f1662d7
public address uncompressed 1NKUnTCtN3Pbm3wEVsFZFuotKkjPPi4g3B
```

## Do you wanna more programs here?

Well just ask for the program that you want. But please don't be annoying, I do this for hobby and fun.

Use the Issue section or the bitcointalk topic:

https://github.com/albertobsd/ecctools/issues

https://bitcointalk.org/index.php?topic=5361234.0

## Donations:

- BTC: 1Coffee1jV4gB5gaXfHgSHDz9xx9QSECVW
- ETH: 0x6222978c984C22d21b11b5b6b0Dd839C75821069
- DOGE: DKAG4g2HwVFCLzs7YWdgtcsK6v5jym1ErV
