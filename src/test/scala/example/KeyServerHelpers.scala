package example

import okhttp3.internal.Util
import okhttp3.mockwebserver.{MockResponse, MockWebServer}
import play.api.libs.json.Json

import java.io.{File, FileInputStream, InputStream}
import java.lang.Thread.currentThread
import java.math.BigInteger
import java.net.URL
import java.nio.file.{Files, Path, StandardCopyOption}
import java.security.interfaces.RSAPublicKey
import java.security.{KeyPair, KeyPairGenerator, KeyStore, SecureRandom}
import java.util.Base64
import javax.net.ssl.{KeyManagerFactory, SSLContext, TrustManagerFactory}

object KeyServerHelpers {
  val TEST_PUB_KEY_ID_1: String = "TEST_PUB_KEY_ID_1"
  val TEST_KEY_PAIR_1: KeyPair = generateRsaKeyPair(2048)
  val TEST_PUB_KEY_ID_2: String = "TEST_PUB_KEY_ID_2"
  val TEST_KEY_PAIR_2: KeyPair = generateRsaKeyPair(2048)

  def generateRsaKeyPair(keySize: Int = 4096): KeyPair = {
    val keyPairGenerator: KeyPairGenerator = KeyPairGenerator.getInstance("RSA")
    keyPairGenerator.initialize(keySize)
    keyPairGenerator.generateKeyPair()
  }

  private val base64URLEncoder = Base64.getUrlEncoder()

  def toIntegerBytes(bigInt: BigInteger): Array[Byte] = {
    val bitLen: Int = {
      val l = bigInt.bitLength()
      // round bitLen
      ((l + 7) >> 3) << 3
    }

    val bigBytes = bigInt.toByteArray()

    if (((bigInt.bitLength() % 8) != 0) && (((bigInt.bitLength() / 8) + 1) == (bitLen / 8))) {
      return bigBytes
    }

    // set up params for copying everything but sign bit
    val (startSrc: Int, len: Int) = {
      // if bigInt is exactly byte-aligned, just skip signbit in copy
      if ((bigInt.bitLength() % 8) == 0) {
        (1, bigBytes.length -1)
      } else {
        (0, bigBytes.length)
      }
    }

    val startDst = bitLen / 8 - len // to pad w/ nulls as per spec
    val resizedBytes: Array[Byte] = new Array[Byte](bitLen / 8)
    System.arraycopy(bigBytes, startSrc, resizedBytes, startDst, len)

    resizedBytes
  }
}

trait KeyServerHelpers {
  import KeyServerHelpers._

  def stubKeyResponse[T <: RSAPublicKey](mockWebServer: MockWebServer, keyId: String, publicKey: T): Unit = {
    val pubKeyE = base64URLEncoder.encodeToString(toIntegerBytes(publicKey.getPublicExponent()))
    val pubKeyN = base64URLEncoder.encodeToString(toIntegerBytes(publicKey.getModulus()))

    val jsonKeysBody = Json.obj(
      "keys" -> Seq(Json.obj(
        "kty" -> "RSA",
        "alg" -> "RS256",
        "use" -> "sig",
        "kid" -> keyId,
        "e" -> pubKeyE,
        "n" -> pubKeyN
      ))
    )

    mockWebServer.enqueue(new MockResponse().setBody(jsonKeysBody.toString()))
  }

  def createMockServer(): MockWebServer = {
    val outKeyStoreFile: Path = File.createTempFile("testing-keystore", "jks").toPath()
    val keyStoreResource: URL = currentThread().getContextClassLoader.getResource("tck-keystore.jks")
    Files.copy(keyStoreResource.openStream(), outKeyStoreFile, StandardCopyOption.REPLACE_EXISTING)

    val keyStorePath: String = outKeyStoreFile.toFile().getAbsolutePath
    System.setProperty("javax.net.ssl.trustStore", keyStorePath)

    val mockServer: MockWebServer = new MockWebServer()
    mockServer.useHttps(
      sslContext(outKeyStoreFile.toFile().getAbsolutePath(), "password").getSocketFactory(),
      false
    )
    mockServer
  }

  def sslContext(keystoreFile: String, password: String): SSLContext = {
    val keystore: KeyStore = KeyStore.getInstance(KeyStore.getDefaultType())
    val inputStream: InputStream = new FileInputStream(keystoreFile)

    try {
      keystore.load(inputStream, password.toCharArray())
    } finally {
      Util.closeQuietly(inputStream)
    }

    val keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
    keyManagerFactory.init(keystore, password.toCharArray())

    val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    trustManagerFactory.init(keystore)

    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(
      keyManagerFactory.getKeyManagers(),
      trustManagerFactory.getTrustManagers(),
      new SecureRandom())

    sslContext
  }
}