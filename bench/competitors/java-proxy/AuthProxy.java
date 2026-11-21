import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Minimal zero-dependency OpenJDK 17 RS256 JWKS Forward-Auth & Reverse-Proxy
 * competitor for cross-language benchmarking.
 */
public class AuthProxy {
    private static final Base64.Decoder B64URL = Base64.getUrlDecoder();
    private static final Pattern STR_FIELD = Pattern.compile("\"([^\"]+)\"\\s*:\\s*\"([^\"]*)\"");
    private static final Pattern EXP_FIELD = Pattern.compile("\"exp\"\\s*:\\s*(\\d+)");

    public static void main(String[] args) throws Exception {
        String issuer = System.getenv("ISSUER");
        String audience = System.getenv("AUDIENCE");
        String listen = System.getenv().getOrDefault("LISTEN_ADDR", "127.0.0.1:18091");
        String upstream = System.getenv().getOrDefault("UPSTREAM_URL", "");
        if (issuer == null || audience == null) {
            throw new IllegalArgumentException("ISSUER and AUDIENCE are required");
        }

        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .version(HttpClient.Version.HTTP_1_1)
                .build();

        String jwksUrl = issuer.replaceAll("/+$", "") + "/protocol/openid-connect/certs";
        HttpResponse<String> jwksResp = client.send(
                HttpRequest.newBuilder(URI.create(jwksUrl)).GET().build(),
                HttpResponse.BodyHandlers.ofString());

        Map<String, PublicKey> keys = parseJWKS(jwksResp.body());

        String[] hostPort = listen.split(":");
        String host = hostPort[0].isEmpty() ? "127.0.0.1" : hostPort[0];
        int port = Integer.parseInt(hostPort[1]);

        HttpServer server = HttpServer.create(new InetSocketAddress(host, port), 1024);
        server.setExecutor(Executors.newFixedThreadPool(Math.max(4, Runtime.getRuntime().availableProcessors() * 4)));

        server.createContext("/healthz", ex -> {
            ex.sendResponseHeaders(200, -1);
            ex.close();
        });

        server.createContext("/", ex -> handle(ex, keys, issuer, audience, upstream, client));
        server.start();
    }

    private static void handle(
            HttpExchange ex,
            Map<String, PublicKey> keys,
            String issuer,
            String audience,
            String upstream,
            HttpClient client) throws IOException {
        try {
            String auth = ex.getRequestHeaders().getFirst("Authorization");
            if (auth == null || !auth.startsWith("Bearer ")) {
                ex.sendResponseHeaders(401, -1);
                return;
            }
            String token = auth.substring(7);
            int dot1 = token.indexOf('.');
            int dot2 = dot1 > 0 ? token.indexOf('.', dot1 + 1) : -1;
            if (dot1 <= 0 || dot2 <= dot1 + 1 || token.indexOf('.', dot2 + 1) >= 0) {
                ex.sendResponseHeaders(401, -1);
                return;
            }

            String hdrJson = new String(B64URL.decode(token.substring(0, dot1)), StandardCharsets.UTF_8);
            String kid = extractString(hdrJson, "kid");
            String alg = extractString(hdrJson, "alg");
            PublicKey pub = kid != null ? keys.get(kid) : null;
            if (!"RS256".equals(alg) || pub == null) {
                ex.sendResponseHeaders(401, -1);
                return;
            }

            byte[] sigBytes = B64URL.decode(token.substring(dot2 + 1));
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(pub);
            sig.update(token.substring(0, dot2).getBytes(StandardCharsets.US_ASCII));
            if (!sig.verify(sigBytes)) {
                ex.sendResponseHeaders(401, -1);
                return;
            }

            String payloadJson = new String(B64URL.decode(token.substring(dot1 + 1, dot2)), StandardCharsets.UTF_8);
            String iss = extractString(payloadJson, "iss");
            String aud = extractString(payloadJson, "aud");
            String typ = extractString(payloadJson, "typ");
            long exp = extractExp(payloadJson);
            if (!issuer.equals(iss) || !audience.equals(aud) || !"Bearer".equals(typ) || exp < Instant.now().getEpochSecond()) {
                ex.sendResponseHeaders(401, -1);
                return;
            }

            String user = extractString(payloadJson, "preferred_username");
            if (user == null || user.isEmpty()) {
                user = extractString(payloadJson, "sub");
            }
            String email = extractString(payloadJson, "email");
            if (email == null) email = "";

            if (!upstream.isEmpty()) {
                HttpRequest upReq = HttpRequest.newBuilder(URI.create(upstream + ex.getRequestURI().toString()))
                        .GET()
                        .header("X-Auth-Request-User", user != null ? user : "")
                        .header("X-Auth-Request-Email", email)
                        .build();
                HttpResponse<byte[]> upResp = client.send(upReq, HttpResponse.BodyHandlers.ofByteArray());
                byte[] body = upResp.body();
                ex.sendResponseHeaders(upResp.statusCode(), body.length);
                try (OutputStream os = ex.getResponseBody()) {
                    os.write(body);
                }
            } else {
                ex.getResponseHeaders().set("X-Auth-Request-User", user != null ? user : "");
                ex.getResponseHeaders().set("X-Auth-Request-Email", email);
                ex.getResponseHeaders().set("Cache-Control", "no-store");
                ex.sendResponseHeaders(200, -1);
            }
        } catch (Exception e) {
            ex.sendResponseHeaders(401, -1);
        } finally {
            ex.close();
        }
    }

    private static Map<String, PublicKey> parseJWKS(String body) throws Exception {
        Map<String, PublicKey> out = new ConcurrentHashMap<>();
        String kid = extractString(body, "kid");
        String nStr = extractString(body, "n");
        String eStr = extractString(body, "e");
        if (kid != null && nStr != null && eStr != null) {
            BigInteger n = new BigInteger(1, B64URL.decode(nStr));
            BigInteger e = new BigInteger(1, B64URL.decode(eStr));
            PublicKey pub = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
            out.put(kid, pub);
        }
        return out;
    }

    private static String extractString(String json, String field) {
        Matcher m = STR_FIELD.matcher(json);
        while (m.find()) {
            if (field.equals(m.group(1))) {
                return m.group(2);
            }
        }
        return null;
    }

    private static long extractExp(String json) {
        Matcher m = EXP_FIELD.matcher(json);
        return m.find() ? Long.parseLong(m.group(1)) : 0L;
    }
}
