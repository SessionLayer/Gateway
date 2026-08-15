import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

/**
 * A standalone Azure Key Vault REST double for the full-stack harness: HTTPS,
 * a real P-256 key, and the two operations the Control Plane's Key Vault CA
 * backend performs against a live vault — fetch the public JWK at CA
 * adoption, sign a SHA-256 digest per certificate.
 *
 * <p>It is a separate process rather than the in-JVM double the Control
 * Plane's own unit tests use ({@code KeyVaultRestDouble}) because the
 * full-stack harness runs a packaged jar in a different process: the vault
 * has to be reachable over a socket.
 *
 * <p>It DOES issue the real {@code WWW-Authenticate} challenge: any request
 * with no {@code Authorization: Bearer} header gets a 401 naming a tenant and
 * a resource, exactly like a real vault. This is load-bearing, not
 * decorative — the SDK's challenge policy sends the very first request with
 * an empty body (an unauthenticated endpoint must never see the real
 * payload), and only replays with the real body once it has a token for the
 * scope the challenge named. A double that skipped the challenge would only
 * ever see that empty probe. See {@code README.md} in this directory for the
 * hostname requirement this implies (a real vault's challenge {@code
 * resource} can only be satisfied by a request host that is a subdomain of
 * it, which no IP literal can be).
 *
 * <p>The challenge means the Control Plane's credential now has to actually
 * obtain a token, so this double also serves the App Service managed-identity
 * protocol — a second, PLAIN HTTP listener (real Azure's own equivalent
 * endpoint is plain HTTP to a loopback address, so this is the faithful
 * choice, not a shortcut) answering {@code GET /msi/token}. It is a separate
 * {@link HttpServer}, never routed through {@link #dispatch}, so it cannot
 * end up behind the vault's own challenge — a credential would need a token
 * to fetch a token, which is unrecoverable. It hands back an unvalidated
 * token unconditionally; nothing downstream of it checks the value.
 *
 * <p>Run with the single-file source launcher:
 * {@code java KeyVaultDouble.java --keystore kv.p12 --storepass <pw> --hostname sl.vault.azure.net --key-name session-ca --request-log requests.log}
 */
public final class KeyVaultDouble {

	private static final String KEY_VERSION = "0123456789abcdef0123456789abcdef";
	private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
	private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();

	// Matches ControlPlane's own KeyVaultRestDouble (unit-tested against the genuine SDK)
	// so both doubles exercise the identical challenge shape.
	private static final String CHALLENGE_AUTHORIZATION =
			"https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000";
	private static final String CHALLENGE_RESOURCE = "https://vault.azure.net";

	private enum FaultMode {
		NONE, WRONG_KEY
	}

	private final KeyPair caKey;
	// Generated once, unrelated to caKey. FaultMode.WRONG_KEY signs with this instead
	// of caKey — the fault injection (the Control Plane must verify every
	// signature against the pinned public key and refuse, never accept a signature from
	// whichever key actually signed it).
	private final KeyPair wrongKey;
	private final String keyName;
	private final AtomicInteger signCount = new AtomicInteger();
	private final PrintWriter requestLog;
	private volatile String baseUrl = "";
	private volatile FaultMode faultMode = FaultMode.NONE;

	private KeyVaultDouble(KeyPair caKey, KeyPair wrongKey, String keyName, PrintWriter requestLog) {
		this.caKey = caKey;
		this.wrongKey = wrongKey;
		this.keyName = keyName;
		this.requestLog = requestLog;
	}

	public static void main(String[] args) throws Exception {
		Map<String, String> opts = parseArgs(args);
		String keyName = opts.getOrDefault("key-name", "session-ca");
		int port = Integer.parseInt(opts.getOrDefault("port", "0"));
		// The socket always binds 127.0.0.1 — only the URI the double advertises (and the
		// challenge's request-host check judges) uses the hostname. --hostname must resolve
		// to 127.0.0.1 (the harness's /etc/hosts entry does this), because the SDK's challenge
		// policy refuses to attach a token unless the request host is the challenge resource's
		// host or a subdomain of it, and an IP literal can never be either.
		String hostname = opts.getOrDefault("hostname", "sl.vault.azure.net");

		KeyPair caKey = ecKeyPair();
		KeyPair wrongKey = ecKeyPair();

		PrintWriter log = new PrintWriter(Files.newBufferedWriter(
				Path.of(opts.getOrDefault("request-log", "keyvault-double-requests.log"))), true);
		KeyVaultDouble vault = new KeyVaultDouble(caKey, wrongKey, keyName, log);

		HttpsServer server = HttpsServer.create(new InetSocketAddress("127.0.0.1", port), 0);
		server.setHttpsConfigurator(new HttpsConfigurator(tlsContext(opts)));
		server.createContext("/", vault::dispatch);
		server.setExecutor(Executors.newFixedThreadPool(4));
		server.start();

		vault.baseUrl = "https://" + hostname + ":" + server.getAddress().getPort();

		// Plain HTTP, on 127.0.0.1 — real Azure App Service's own instance-metadata
		// endpoint is plain HTTP to a loopback address, so this is the faithful shape,
		// not a shortcut. A separate HttpServer (never HttpsServer, never routed through
		// dispatch) so it structurally cannot end up behind the vault's own challenge.
		HttpServer msi = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		msi.createContext("/msi/token", vault::handleMsiToken);
		msi.setExecutor(Executors.newFixedThreadPool(2));
		msi.start();
		String msiUrl = "http://127.0.0.1:" + msi.getAddress().getPort() + "/msi/token";

		// This double will sit in the repo alongside real code forever, so its nature is
		// never left to be inferred from the port it opens: it is not Azure Key Vault, it
		// answers every request with no credential check at all, and it carries a
		// fault-injection admin surface (/_test/fault-mode) that can make it sign with the
		// wrong key on request. Say so loudly, every time it starts.
		System.out.println("=================================================================");
		System.out.println("TEST DOUBLE — this is NOT Azure Key Vault.");
		System.out.println("It is a fake Key Vault key/crypto endpoint (plus a fake managed-");
		System.out.println("identity token endpoint) for the SessionLayer full-stack test");
		System.out.println("harness only. It accepts every request with no credential check,");
		System.out.println("and exposes a fault-injection admin surface at /_test/fault-mode.");
		System.out.println("Never point a real deployment at it.");
		System.out.println("=================================================================");

		// The harness reads these off stdout: the vault URI the Control Plane is
		// configured with, the versioned key identifier it rotates the CA onto, the
		// public half so the harness can verify a certificate independently of the CP,
		// and the managed-identity token endpoint the CP's credential is pointed at.
		System.out.println("KEYVAULT_URL=" + vault.baseUrl);
		System.out.println("KEY_ID=" + vault.baseUrl + "/keys/" + keyName + "/" + KEY_VERSION);
		System.out.println("MSI_ENDPOINT=" + msiUrl);
		System.out.println("PUBKEY_SPKI_B64=" + Base64.getEncoder().encodeToString(caKey.getPublic().getEncoded()));
		System.out.flush();
	}

	private static KeyPair ecKeyPair() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(new ECGenParameterSpec("secp256r1"));
		return generator.generateKeyPair();
	}

	private static SSLContext tlsContext(Map<String, String> opts) throws Exception {
		char[] pass = opts.getOrDefault("storepass", "changeit").toCharArray();
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		try (var in = Files.newInputStream(Path.of(opts.get("keystore")))) {
			keyStore.load(in, pass);
		}
		KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		kmf.init(keyStore, pass);
		SSLContext ctx = SSLContext.getInstance("TLSv1.3");
		ctx.init(kmf.getKeyManagers(), null, null);
		return ctx;
	}

	private void dispatch(HttpExchange exchange) throws IOException {
		String path = exchange.getRequestURI().getPath();
		byte[] body = exchange.getRequestBody().readAllBytes();
		boolean bearerPresent = hasBearerToken(exchange);
		requestLog.printf("%s %s bearer=%s headers=%s body=%s%n", exchange.getRequestMethod(),
				exchange.getRequestURI(), bearerPresent, exchange.getRequestHeaders().entrySet(),
				new String(body, StandardCharsets.UTF_8));
		try {
			// /_test/* is this double's own admin surface, not the Key Vault API it emulates —
			// the harness drives it directly with curl, so it is deliberately exempt from the
			// challenge below.
			if ("GET".equals(exchange.getRequestMethod()) && "/_test/fault-mode".equals(path)) {
				respond(exchange, 200, setFaultMode(exchange.getRequestURI().getRawQuery()));
				return;
			}
			// The real challenge dance: an unauthenticated request gets a 401 naming the tenant
			// and resource to get a token for, never the real response — matching Key Vault
			// means the SDK's first (deliberately bodyless) probe MUST be refused here, not
			// quietly served.
			if (!bearerPresent) {
				respondChallenge(exchange);
				return;
			}
			String expected = "/keys/" + keyName + "/" + KEY_VERSION;
			if ("GET".equals(exchange.getRequestMethod()) && expected.equals(path)) {
				respond(exchange, 200, jwkResponse());
			} else if ("POST".equals(exchange.getRequestMethod()) && (expected + "/sign").equals(path)) {
				respond(exchange, 200, signResponse(new String(body, StandardCharsets.UTF_8)));
			} else {
				respond(exchange, 404, "{\"error\":{\"code\":\"KeyNotFound\",\"message\":\"no such key\"}}");
			}
		} catch (Exception failure) {
			failure.printStackTrace();
			respond(exchange, 400, "{\"error\":{\"code\":\"BadParameter\",\"message\":\"rejected\"}}");
		}
	}

	private static boolean hasBearerToken(HttpExchange exchange) {
		String authorization = exchange.getRequestHeaders().getFirst("Authorization");
		return authorization != null && authorization.startsWith("Bearer ");
	}

	private void respondChallenge(HttpExchange exchange) throws IOException {
		exchange.getResponseHeaders().add("WWW-Authenticate",
				"Bearer authorization=\"" + CHALLENGE_AUTHORIZATION + "\", resource=\"" + CHALLENGE_RESOURCE + "\"");
		respond(exchange, 401, "{\"error\":{\"code\":\"Unauthorized\",\"message\":\"authentication required\"}}");
	}

	/**
	 * The App Service managed-identity protocol (msal4j's {@code
	 * AppServiceManagedIdentitySource}): a plain GET carrying {@code
	 * X-IDENTITY-HEADER} and {@code resource}/{@code api-version} query params,
	 * answered with an unvalidated bearer token. This is a genuinely different
	 * code path from the tenant/authority-validated OAuth2 flow the vault's own
	 * challenge triggers — no authority, no tenant, nothing here checks the
	 * header value, matching "any token satisfies the double" for the vault
	 * side too.
	 */
	private void handleMsiToken(HttpExchange exchange) throws IOException {
		byte[] body = exchange.getRequestBody().readAllBytes();
		requestLog.printf("%s %s bearer=%s headers=%s body=%s%n", exchange.getRequestMethod(),
				exchange.getRequestURI(), false, exchange.getRequestHeaders().entrySet(),
				new String(body, StandardCharsets.UTF_8));
		String rawResource = queryParam(exchange.getRequestURI().getRawQuery(), "resource");
		String resource = rawResource == null ? "" : URLDecoder.decode(rawResource, StandardCharsets.UTF_8);
		long expiresOn = Instant.now().plusSeconds(3600).getEpochSecond();
		respond(exchange, 200, "{\"access_token\":\"fake-token-for-the-double\",\"expires_on\":\"" + expiresOn
				+ "\",\"token_type\":\"Bearer\",\"resource\":\"" + resource + "\"}");
	}

	/**
	 * Test-only admin surface, not part of the Key Vault REST API: toggles
	 * whether {@link #signResponse} signs with the real CA key or
	 * {@link #wrongKey}. Kept as a runtime toggle rather
	 * than a process restart with a different key so the harness never has to
	 * rebind the vault to a new port mid-run — the Control Plane's {@code
	 * vault-uri}/{@code keyReference} are fixed at boot.
	 */
	private String setFaultMode(String rawQuery) {
		String mode = queryParam(rawQuery, "mode");
		faultMode = "wrong_key".equalsIgnoreCase(mode) ? FaultMode.WRONG_KEY : FaultMode.NONE;
		return "{\"mode\":\"" + faultMode.name().toLowerCase(Locale.ROOT) + "\"}";
	}

	private static String queryParam(String rawQuery, String name) {
		if (rawQuery == null) {
			return null;
		}
		for (String pair : rawQuery.split("&")) {
			int eq = pair.indexOf('=');
			if (eq > 0 && pair.substring(0, eq).equals(name)) {
				return pair.substring(eq + 1);
			}
		}
		return null;
	}

	private String jwkResponse() {
		// Always the REAL CA key, regardless of faultMode: the fault this double injects
		// is a vault that signs with the wrong key while still reporting the pinned key's
		// coordinates honestly — the failure mode the CP's pinned-key check exists to
		// catch, isolated to signing.
		ECPublicKey pub = (ECPublicKey) caKey.getPublic();
		String kid = baseUrl + "/keys/" + keyName + "/" + KEY_VERSION;
		return "{\"key\":{\"kid\":\"" + kid + "\",\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\""
				+ B64URL.encodeToString(coordinate(pub.getW().getAffineX())) + "\",\"y\":\""
				+ B64URL.encodeToString(coordinate(pub.getW().getAffineY()))
				+ "\",\"key_ops\":[\"sign\",\"verify\"]},\"attributes\":{\"enabled\":true}}";
	}

	/**
	 * A JWK coordinate is fixed-width unsigned big-endian, 32 bytes for P-256.
	 * {@link BigInteger#toByteArray()} is signed and minimal, so it is 33 bytes
	 * when the high bit is set and short when the value has leading zero bytes —
	 * both of which decode to the wrong point if copied verbatim.
	 */
	private static byte[] coordinate(BigInteger value) {
		byte[] signed = value.toByteArray();
		byte[] fixed = new byte[32];
		int length = Math.min(signed.length, 32);
		System.arraycopy(signed, signed.length - length, fixed, 32 - length, length);
		return fixed;
	}

	private String signResponse(String body) throws Exception {
		if (!body.contains("\"ES256\"")) {
			throw new IllegalArgumentException("unsupported algorithm");
		}
		byte[] digest = B64URL_DEC.decode(extract(body, "value"));
		if (digest.length != 32) {
			throw new IllegalArgumentException("digest is not SHA-256");
		}
		KeyPair signingKey = faultMode == FaultMode.WRONG_KEY ? wrongKey : caKey;
		Signature signer = Signature.getInstance("NONEwithECDSA");
		signer.initSign((ECPrivateKey) signingKey.getPrivate());
		signer.update(digest);
		byte[] p1363 = derToP1363(signer.sign());
		signCount.incrementAndGet();
		return "{\"kid\":\"" + baseUrl + "/keys/" + keyName + "/" + KEY_VERSION + "\",\"value\":\""
				+ B64URL.encodeToString(p1363) + "\"}";
	}

	/**
	 * The JDK emits DER {@code SEQUENCE{INTEGER r, INTEGER s}}; Key Vault returns
	 * P1363 {@code r‖s} fixed-width. Returning DER here is the exact bug the
	 * Control Plane's normalization exists to catch, so this conversion is what
	 * makes the double faithful rather than merely functional.
	 */
	private static byte[] derToP1363(byte[] der) {
		int index = 3;
		int rLength = der[index++] & 0xFF;
		BigInteger r = new BigInteger(Arrays.copyOfRange(der, index, index + rLength));
		index += rLength + 1;
		int sLength = der[index++] & 0xFF;
		BigInteger s = new BigInteger(Arrays.copyOfRange(der, index, index + sLength));
		byte[] out = new byte[64];
		System.arraycopy(coordinate(r), 0, out, 0, 32);
		System.arraycopy(coordinate(s), 0, out, 32, 32);
		return out;
	}

	private static String extract(String json, String field) {
		int start = json.indexOf("\"" + field + "\"");
		int open = json.indexOf('"', json.indexOf(':', start) + 1);
		return json.substring(open + 1, json.indexOf('"', open + 1));
	}

	private static void respond(HttpExchange exchange, int status, String json) throws IOException {
		byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
		exchange.getResponseHeaders().add("Content-Type", "application/json");
		exchange.sendResponseHeaders(status, bytes.length);
		try (OutputStream out = exchange.getResponseBody()) {
			out.write(bytes);
		}
	}

	private static Map<String, String> parseArgs(String[] args) {
		Map<String, String> opts = new java.util.HashMap<>();
		for (int i = 0; i < args.length - 1; i += 2) {
			opts.put(args[i].replaceFirst("^--", "").toLowerCase(Locale.ROOT), args[i + 1]);
		}
		return opts;
	}
}
