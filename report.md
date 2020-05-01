# The usage of RSA algorithms in SSH key

11811712 江川

### Introduce

I have use some security tools (e.g. SSH key, GPG keys) for several years. But, I have not understood why those tools can work correctly and safely.

At first, I want to explore how GPG works. But after a short attempt, I notice that GPG is too complex. So I choose SSH key finally. The SSH key use RSA algorithms, I want to extract the parameters of RSA from the SSH key.

All materials and codes have been uploaded to [Github](https://github.com/Gogomoe/SUSTech_CS201_project). But to avoid plagiarizing, the repository will be public after deadline.

### Prepare

I use `ssh-keygen` tool to generate a pair of keys.

```bash
ssh-keygen -f id
```

It creates two files `id` and `id.pub`.
The private key stored in `id`, and the public key stored in `id.pub`.

```plain
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA2/pUGITz+pWOSOQlLcIXedumMrbGaXQVUYwH3uhSQKdqQmee
iL4i2pzCk3gtOxwlCQJIMifxcLt7+NILMZhULwvYt65bd7YZT9j2qSq7vhCrtPVK
rC6vaj+ncgE4mgwrcthMQ/jaq8nNqgDR76bo4ZtRBRy64SMQAukgTimFleNMvwhP
0GIg8cGWK6kIXD+Op2NNABVcHZT4prdIl5QMRYWXWapcATbMrQz5P8ciY0KXoiX3
ldVMpL1rJQdQt2+yeyTviguVL8ifSmZ3Phtjm98x/2FuYMLzBfc33Fkk3cdwYdbV
Jvbr04wH/xz+z4Rc9FrKIfIbjwwEKDrL7MZhjQIDAQABAoIBAQCGpPiocWis7rHC
p/KhyXV5HxrhW8KidW0/FskShX0jGdYOg0IkTM0kpmLqxNpaneWFWCI8oPpFmFxP
drFnT+fnTAcAlvZhldJ0b0a7UO7NbYLMJn/oWEMCc6fYPisZD23gw8gaqs2d7M23
yvy1BaLxxJGY4Xb5qu53+Z3OedfMX8tf2D/X99SUDqNiAS3uko5dpbpFP0jXZLVg
0Gq4Sexo4kIRHQmh3GuIdSYq0jH8HIlrJfkcssHMHRlr7V6duj2dq5tq2f4r/QFQ
PjsI91yCs7fVP4vEy6Tpo6CbWeHFVGV0SyRh4uKpZbrJonaVoou4lqFDEvkeI+dT
Zt/2hig5AoGBAPx1178yMD3kUy2hI6mXGJG4deCL4MMcMJR5XDdUVhRKhI+xsxkS
HRA7UKfaETXRJr5OlWERYozA9I/R/4uWG21bw1MMdiRmSgNVaOtHtHlH7YYUj1OW
R373EpJXTI+2difvnHBuT5jiS/rrAabeTckEnQ75UnCkPQ/1o/u2RKKXAoGBAN8P
5W1tYEd6NTfYAV6ENTamLJdicPtYRupJoOMudXKbtOBFhpeaJUC1Rr+MLYomAqTO
XhSkqhoskd+/K+aABFx0fn0Jvq+ionQz/pxX5pshFFwTG09wT5y3AxycYMBm2pBD
QRCDW33nJtQ4fOhCiSmiQD1244SRdN8kXoEYVTV7AoGAb9Mu5lSvw6pwIYT/y+3O
hzVimTy8KRBCgHGlJCjqHADJ6PA4OYGpd/geCMtx1hm3hJJAXoeZ1GjfqxjEjarG
qVD9GrspVYQtgn6Bg732NcZjcoGG3upw7s833bRniDy054meDLr/7ONH7nPL/oL3
h3PQscJD/vrwxTH0GdmpWy8CgYEAw8de9gFm3LV9WitDYGKnlfSZ9LDZOzHK5D2F
cYBIYzQYuDMto4gOpFG2684r9jHQZjgeyP2RsvFlgz12WZQIv+EbV8Gi1OLotRch
pLVd2NBa30mB0eJgbcsPdyAlpxlfQflVdRnlxoaIRQHjV7N2Uc1vlsLvhF5qdqOk
MqhZuVsCgYEA6Itko+HJRGJHjhq5ekM92qC9eAqB94S8mg8UIau9wZ6JwnyhCfKH
Gf6IuxjHRSwqzt7WNtZ2mLTJq9HY3haCr0OvoVepS+M2Qdl/Fs2UZPKsOJEbSNZb
n5DSB/eLwWO+AFF217U3dwRNf+W2r/zjbDcomTR5oFOXslz9UDV/+LI=
-----END RSA PRIVATE KEY-----
```

```plain
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDb+lQYhPP6lY5I5CUtwhd526YytsZpdBVRjAfe6FJAp2pCZ56IviLanMKTeC07HCUJAkgyJ/Fwu3v40gsxmFQvC9i3rlt3thlP2PapKru+EKu09UqsLq9qP6dyATiaDCty2ExD+Nqryc2qANHvpujhm1EFHLrhIxAC6SBOKYWV40y/CE/QYiDxwZYrqQhcP46nY00AFVwdlPimt0iXlAxFhZdZqlwBNsytDPk/xyJjQpeiJfeV1UykvWslB1C3b7J7JO+KC5UvyJ9KZnc+G2Ob3zH/YW5gwvMF9zfcWSTdx3Bh1tUm9uvTjAf/HP7PhFz0Wsoh8huPDAQoOsvsxmGN gogo@Gogo-SurfacePro
```

### Format of public key

The public key is shorter, so I try to explore public key.

There are 3 parts in the public key split by space. First is a string `ssh-rsa` , third is `gogo@Gogo-SurfacePro` username of me and name of computer. Skip these parts, the second part is important.

It looks like a Base64 encoded string. After I searched some materials on Internet, I understood the the format. I extract the base64 part into `id.pub.key` and run this command.

```bash
cat id.pub.key | base64 -d | hexdump -C
```

```plain
00000000 [00 00 00 07]73 73 68 2d  72 73 61[00 00 00 03]01  |....ssh-rsa.....|
00000010  00 01[00 00 01 01]00 db  fa 54 18 84 f3 fa 95 8e  |.........T......|
00000020  48 e4 25 2d c2 17 79 db  a6 32 b6 c6 69 74 15 51  |H.%-..y..2..it.Q|
00000030  8c 07 de e8 52 40 a7 6a  42 67 9e 88 be 22 da 9c  |....R@.jBg..."..|
00000040  c2 93 78 2d 3b 1c 25 09  02 48 32 27 f1 70 bb 7b  |..x-;.%..H2'.p.{|
00000050  f8 d2 0b 31 98 54 2f 0b  d8 b7 ae 5b 77 b6 19 4f  |...1.T/....[w..O|
00000060  d8 f6 a9 2a bb be 10 ab  b4 f5 4a ac 2e af 6a 3f  |...*......J...j?|
00000070  a7 72 01 38 9a 0c 2b 72  d8 4c 43 f8 da ab c9 cd  |.r.8..+r.LC.....|
00000080  aa 00 d1 ef a6 e8 e1 9b  51 05 1c ba e1 23 10 02  |........Q....#..|
00000090  e9 20 4e 29 85 95 e3 4c  bf 08 4f d0 62 20 f1 c1  |. N)...L..O.b ..|
000000a0  96 2b a9 08 5c 3f 8e a7  63 4d 00 15 5c 1d 94 f8  |.+..\?..cM..\...|
000000b0  a6 b7 48 97 94 0c 45 85  97 59 aa 5c 01 36 cc ad  |..H...E..Y.\.6..|
000000c0  0c f9 3f c7 22 63 42 97  a2 25 f7 95 d5 4c a4 bd  |..?."cB..%...L..|
000000d0  6b 25 07 50 b7 6f b2 7b  24 ef 8a 0b 95 2f c8 9f  |k%.P.o.{$..../..|
000000e0  4a 66 77 3e 1b 63 9b df  31 ff 61 6e 60 c2 f3 05  |Jfw>.c..1.an`...|
000000f0  f7 37 dc 59 24 dd c7 70  61 d6 d5 26 f6 eb d3 8c  |.7.Y$..pa..&....|
00000100  07 ff 1c fe cf 84 5c f4  5a ca 21 f2 1b 8f 0c 04  |......\.Z.!.....|
00000110  28 3a cb ec c6 61 8d                              |(:...a.|
```

There are three parts in the file, each part start with 4 bytes to presents the size of content, and followed by the content. I mark each part by `[size]content`.

The first part is 7 bytes contain the ASCII of `ssh-rsa`, The second 3 bytes part is `e` in RSA, is `01 00 01`(65537). The third part has 257 bytes, it is the big number `n`.

I write following code to extract public key.

```kotlin
data class PublicKey(
    val str: String,
    val e: BigInteger,
    val n: BigInteger
) {
    fun encrypt(byteArray: ByteArray): ByteArray {
        return BigInteger(byteArray).modPow(e, n).toByteArray()
    }
}
fun decodePublicKey(publicKey: String): PublicKey {
    val encoded = publicKey.split(' ')[1]
    val hex = Base64.getDecoder().decode(encoded)

    val input = hex.inputStream()

    val str = String(extractFromPublicKey(input))
    val exponent = BigInteger(extractFromPublicKey(input))

    val number = extractFromPublicKey(input)
    check(number.first() == 0.toByte())
    val n = BigInteger(number)

    return PublicKey(str, exponent, n)
}

fun extractFromPublicKey(input: ByteArrayInputStream): ByteArray {
    var len = 0
    len += input.read()
    repeat(3) {
        len = len shl 8
        len += input.read()
    }
    return input.readNBytes(len)
}
```

### Format of private key

The private key is longer than public key. Just like public key, I decoded the base64 part of private key.

```bash
cat id.key | base64 -d | hexdump -C
```

```
00000000  30 82 04 a5[02 01]00[02  82 01 01]00 db fa 54 18  |0.............T.|
00000010  84 f3 fa 95 8e 48 e4 25  2d c2 17 79 db a6 32 b6  |.....H.%-..y..2.|
00000020  c6 69 74 15 51 8c 07 de  e8 52 40 a7 6a 42 67 9e  |.it.Q....R@.jBg.|
00000030  88 be 22 da 9c c2 93 78  2d 3b 1c 25 09 02 48 32  |.."....x-;.%..H2|
00000040  27 f1 70 bb 7b f8 d2 0b  31 98 54 2f 0b d8 b7 ae  |'.p.{...1.T/....|
....
```

Oh no, the format is not as clear as public key.

I find that it use `DER-encode` on Internet again. Then I find the format of private key.

```plain
Version ::= INTEGER { two-prime(0), multi(1) }
      (CONSTRAINED BY
      {-- version must be multi if otherPrimeInfos present --})

  RSAPrivateKey ::= SEQUENCE {
      version           Version,
      modulus           INTEGER,  -- n
      publicExponent    INTEGER,  -- e
      privateExponent   INTEGER,  -- d
      prime1            INTEGER,  -- p
      prime2            INTEGER,  -- q
      exponent1         INTEGER,  -- d mod (p-1)
      exponent2         INTEGER,  -- d mod (q-1)
      coefficient       INTEGER,  -- (inverse of q) mod p
      otherPrimeInfos   OtherPrimeInfos OPTIONAL
  }
```

The first byte `30` means content is a sequence, the next byte `82` means next 2 byte is the length of content,  `04 a5` is 1189 bytes.

The first field is version. Next byte`02` presents it is a integer, `01` is the length 1 bytes, value is `00`. By definition, we know that version=0 means it use two prime.

The second field is `n` in RSA, the first byte `02` presents it is a integer, `82 01 01` means 257 bytes, following 257 bytes is content of.

And following on.

I use `jasn` library to help me parse the private key.

```kotlin
data class PrivateKey(
    val version: Int,
    val n: BigInteger,
    val e: BigInteger,
    val d: BigInteger,
    val p: BigInteger,
    val q: BigInteger,
    val exponent1: BigInteger, // d mod (p-1)
    val exponent2: BigInteger, // d mod (q-1)
    val coefficient: BigInteger // (inverse of q) mod p
) {
    fun decrypt(byteArray: ByteArray): ByteArray {
        return BigInteger(byteArray).modPow(d, n).toByteArray()
    }
}
fun decodePrivateKey(privateKey: String): PrivateKey {
    val encoded = privateKey.lines()
        .filter { !it.startsWith("--") }
        .joinToString("")
        .trim()
    val hex = Base64.getDecoder().decode(encoded)
    val input = hex.inputStream()

    val tag = BerTag().apply { decode(input) }
    val length = BerLength().apply { decode(input) }


    val result = PrivateKey(
        BigInteger(extractFromPrivateKey(input)).toInt(),
        BigInteger(extractFromPrivateKey(input)),
        BigInteger(extractFromPrivateKey(input)),
        BigInteger(extractFromPrivateKey(input)),
        BigInteger(extractFromPrivateKey(input)),
        BigInteger(extractFromPrivateKey(input)),
        BigInteger(extractFromPrivateKey(input)),
        BigInteger(extractFromPrivateKey(input)),
        BigInteger(extractFromPrivateKey(input))
    )
    check(input.read() == -1)

    return result
}

fun extractFromPrivateKey(input: ByteArrayInputStream): ByteArray {
    val tag = BerTag().apply { decode(input) }
    val length = BerLength().apply { decode(input) }
    return input.readNBytes(length.`val`)
}
```

### Summary

Ok, we have extract all information from SSH keys. Let's use RSA to encrypt and decrypt some message.

```kotlin
fun main(args: Array<String>) {
    val publicKey = decodePublicKey(File("id.pub").readText())
    println(publicKey)

    val privateKey = decodePrivateKey(File("id").readText())
    println(privateKey)

    val message = "Discrete math is amazing"

    val encrypted = publicKey.encrypt(message.toByteArray())
    val decrypted = privateKey.decrypt(encrypted)

    check(message == String(decrypted))
    println("origin: $message")
    println("encrypted: ${Base64.getEncoder().encodeToString(encrypted)}")
    println("decrypt: ${String(decrypted)}")
}
```

result:

```plain
PublicKey(
   str='ssh-rsa', 
   e=65537, 
   n=277696303712214090041072298781...
)
PrivateKey(
   version=0, 
   n=277696303712214090041072298781..., 
   e=65537..., 
   d=169972832554309107952875081150..., 
   p=177283667967203624781535591961..., 
   q=156639529685039108022638421959..., 
   exponent1=785261393933191025494483528243..., 
   exponent2=137480543616783412920490481247..., 
   coefficient=163298304337697808225831221922...
)

origin: Discrete math is amazing

encrypted: YQXy5IMKWNbFdrrS+H9gZaH4mqtymsDc5XLpPTDkciWl2fZYp9w8iuVGpIge8v01N+pkbWabR+EBC7JQBCNGeQmiQayQIxk/JJLNbx1BW0hrRyXQ+tq+IanpS9aEf+bAA6O1+CYJHCD4968tTGD/me849uwM47osdY9ujP79qgJVRg/ztI1N1Yf6O5HRZ3U9p+dhjaCCpEdo80KqBCOWRjFjY+rJ8R+/FkOEkJbqDFp7dNdwr2GF1hW8vXlJS23ZVG6x0ZmZPFqKTNuEQI+sma3qqT6swcQqmTOpHG857Kbxj2OyE1cmGI1I3saqB+rGCs8FVlBtT+BQvWiJDASehg==

decrypt: Discrete math is amazing
```

### Reference

[Decoding an SSH Key from PEM to BASE64 to HEX to ASN.1 to prime decimal numbers](https://www.hanselman.com/blog/DecodingAnSSHKeyFromPEMToBASE64ToHEXToASN1ToPrimeDecimalNumbers.aspx)

[ssh-keygen生成的id_rsa文件的格式](https://zhuanlan.zhihu.com/p/33949377)