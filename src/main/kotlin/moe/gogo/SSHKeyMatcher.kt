package moe.gogo

import com.beanit.jasn1.ber.BerLength
import com.beanit.jasn1.ber.BerTag
import java.io.ByteArrayInputStream
import java.io.File
import java.math.BigInteger
import java.util.*

data class PublicKey(
    val str: String,
    val e: BigInteger,
    val n: BigInteger
) {
    fun encrypt(byteArray: ByteArray): ByteArray {
        return BigInteger(byteArray).modPow(e, n).toByteArray()
    }

    override fun toString(): String {
        return "PublicKey(\n" +
                "   str='$str', \n" +
                "   e=$e, \n" +
                "   n=$n\n" +
                ")"
    }

}

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

    override fun toString(): String {
        return "PrivateKey(\n" +
                "   version=$version, \n" +
                "   n=$n, \n" +
                "   e=$e, \n" +
                "   d=$d, \n" +
                "   p=$p, \n" +
                "   q=$q, \n" +
                "   exponent1=$exponent1, \n" +
                "   exponent2=$exponent2, \n" +
                "   coefficient=$coefficient\n" +
                ")"
    }

}

@ExperimentalUnsignedTypes
@ExperimentalStdlibApi
object SSHKeyMatcher {
    @JvmStatic
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

    private fun decodePublicKey(publicKey: String): PublicKey {
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

    private fun extractFromPublicKey(input: ByteArrayInputStream): ByteArray {
        var len = 0
        len += input.read()
        repeat(3) {
            len = len shl 8
            len += input.read()
        }
        return input.readNBytes(len)
    }

    private fun decodePrivateKey(privateKey: String): PrivateKey {
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

    private fun extractFromPrivateKey(input: ByteArrayInputStream): ByteArray {
        val tag = BerTag().apply { decode(input) }
        val length = BerLength().apply { decode(input) }
        return input.readNBytes(length.`val`)
    }
}