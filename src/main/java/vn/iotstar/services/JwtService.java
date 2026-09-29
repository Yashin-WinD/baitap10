package vn.iotstar.services;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jose.proc.BadJOSEException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${security.jwt.secret-key}")
    private String secretKey;

    @Value("${security.jwt.expiration-time}")
    private long jwtExpiration;

    public String extractUsername(String token) {
        return extractClaim(token, JWTClaimsSet::getSubject);
    }

    public <T> T extractClaim(String token, Function<JWTClaimsSet, T> claimsResolver) {
        final JWTClaimsSet claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    public long getExpirationTime() {
        return jwtExpiration;
    }

    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expiration
    ) {
        try {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
                    .type(JOSEObjectType.JWT)
                    .build();

            Date now = new Date();
            Date validity = new Date(now.getTime() + expiration);

            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .subject(userDetails.getUsername())
                    .issueTime(now)
                    .expirationTime(validity);

            extraClaims.forEach(claimsBuilder::claim);

            JWTClaimsSet claimsSet = claimsBuilder.build();
            SignedJWT signedJWT = new SignedJWT(header, claimsSet);

            JWSSigner signer = new MACSigner(getSigningKeyBytes());
            signedJWT.sign(signer);

            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException("Error while creating JWT with Nimbus", e);
        }
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            JWSVerifier verifier = new MACVerifier(getSigningKeyBytes());

            if (!signedJWT.verify(verifier)) {
                return false;
            }

            final String username = signedJWT.getJWTClaimsSet().getSubject();
            return (username.equals(userDetails.getUsername())) && !isTokenExpired(signedJWT.getJWTClaimsSet());
        } catch (ParseException | JOSEException e) {
            return false;
        }
    }

    private boolean isTokenExpired(JWTClaimsSet claims) {
        Date expiration = claims.getExpirationTime();
        return expiration != null && expiration.before(new Date());
    }

    private JWTClaimsSet extractAllClaims(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            JWSVerifier verifier = new MACVerifier(getSigningKeyBytes());
            if (!signedJWT.verify(verifier)) {
                throw new RuntimeException(new BadJOSEException("JWT signature verification failed"));
            }
            if (isTokenExpired(signedJWT.getJWTClaimsSet())) {
                throw new RuntimeException(new BadJOSEException("JWT token has expired"));
            }
            return signedJWT.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new RuntimeException("Malformed JWT string", e);
        } catch (JOSEException e) {
            throw new RuntimeException("JOSE verification error", e);
        }
    }

    private byte[] getSigningKeyBytes() {
        return secretKey.getBytes(StandardCharsets.UTF_8);
    }
}
