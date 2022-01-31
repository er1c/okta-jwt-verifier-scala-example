package example

import com.okta.jwt.{AccessTokenVerifier, JwtVerifiers}
import io.jsonwebtoken.{Jwts, SignatureAlgorithm}
import org.scalatest.matchers.must.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.net.URL
import java.security.interfaces.RSAPublicKey
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.Date

class JwtVerifierSpec extends AnyWordSpec with Matchers with KeyServerHelpers {
  import KeyServerHelpers._

  "parseToken" must {
    val server = createMockServer()
    val url: URL = server.url("/oauth2/default").url()

    stubKeyResponse(server, TEST_PUB_KEY_ID_1, TEST_KEY_PAIR_1.getPublic().asInstanceOf[RSAPublicKey])
    stubKeyResponse(server, TEST_PUB_KEY_ID_2, TEST_KEY_PAIR_2.getPublic().asInstanceOf[RSAPublicKey])

    "return a valid jwt" in {
      val now: Instant = Instant.now()
      val token1: String = Jwts.builder()
        .setAudience("api://default")
        .setSubject("joe.coder@example.com")
        .setIssuer(url.toExternalForm())
        .setIssuedAt(Date.from(now))
        .setNotBefore(Date.from(now))
        .setExpiration(Date.from(now.plus(1L, ChronoUnit.HOURS)))
        .setHeader(Jwts.jwsHeader().setKeyId(TEST_PUB_KEY_ID_1))
        .signWith(SignatureAlgorithm.RS256, TEST_KEY_PAIR_1.getPrivate())
        .compact()

      val token2: String = Jwts.builder()
        .setAudience("api://default")
        .setSubject("joe.coder@example.com")
        .setIssuer(url.toExternalForm())
        .setIssuedAt(Date.from(now))
        .setNotBefore(Date.from(now))
        .setExpiration(Date.from(now.plus(1L, ChronoUnit.HOURS)))
        .setHeader(Jwts.jwsHeader().setKeyId(TEST_PUB_KEY_ID_2))
        .signWith(SignatureAlgorithm.RS256, TEST_KEY_PAIR_2.getPrivate())
        .compact()

      try {
        val verifier: AccessTokenVerifier = JwtVerifiers.accessTokenVerifierBuilder()
          .setIssuer(url.toExternalForm())
          .build()

        verifier.decode(token1) must not be null
        server.takeRequest().getPath() mustBe "/oauth2/default/v1/keys"

        verifier.decode(token2) must not be null
        server.takeRequest().getPath() mustBe "/oauth2/default/v1/keys"
      } finally {
        server.shutdown()
      }
    }
  }
}