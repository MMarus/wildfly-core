package org.wildfly.extension.elytron._private.test;

import org.mockserver.integration.ClientAndServer;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.x500.cert.BasicConstraintsExtension;
import org.wildfly.security.x500.cert.SelfSignedX509CertificateAndSigningKey;
import org.wildfly.security.x500.cert.X509CertificateBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * Created by Marek Marusic <mmarusic@redhat.com> on 4/26/19.
 */
public class AcmeTestUtils {
    //keyStoreTestCase stuff ====================

    public static final String WORKING_DIRECTORY_LOCATION = AcmeTestUtils.class.getResource(".").getPath();


    public static final Provider wildFlyElytronProvider = new WildFlyElytronProvider();
    public static final String CS_PASSWORD = "super_secret";
    public static final String KEYSTORE_NAME = "ModifiedKeystore";
    public static final String KEY_PASSWORD = "secret";
    public static final String CERTIFICATE_AUTHORITY_ACCOUNT_NAME = "CertAuthorityAccount";
    public static final String ACCOUNTS_KEYSTORE = "account.keystore";
    public static final String ACCOUNTS_KEYSTORE_NAME = "AccountsKeyStore";
    public static final String ACCOUNTS_KEYSTORE_PASSWORD = "elytron";
    public static String oldHomeDir;

    public static final String KEYSTORE_PASSWORD = "Elytron";
    public static final X500Principal ROOT_DN = new X500Principal("O=Root Certificate Authority, EMAILADDRESS=elytron@wildfly.org, C=UK, ST=Elytron, CN=Elytron CA");
    public static final X500Principal ANOTHER_ROOT_DN = new X500Principal("O=Another Root Certificate Authority, EMAILADDRESS=anotherca@wildfly.org, C=UK, ST=Elytron, CN=Another Elytron CA");
    public static final X500Principal SALLY_DN = new X500Principal("CN=sally smith, OU=jboss, O=red hat, L=raleigh, ST=north carolina, C=us");
    public static final X500Principal SSMITH_DN = new X500Principal("CN=ssmith, OU=jboss, O=red hat, L=raleigh, ST=north carolina, C=us");
    public static final X500Principal FIREFLY_DN = new X500Principal("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=Firefly");
    public static final X500Principal INTERMEDIATE_DN = new X500Principal("O=Intermediate Certificate Authority, EMAILADDRESS=intermediateca@wildfly.org, C=UK, ST=Elytron, CN=Intermediate Elytron CA");
    public static final File FIREFLY_FILE = new File(WORKING_DIRECTORY_LOCATION, "firefly.keystore");
    public static final File TEST_FILE = new File(WORKING_DIRECTORY_LOCATION, "test.keystore");
    public static final File TEST_SINGLE_CERT_REPLY_FILE = new File(WORKING_DIRECTORY_LOCATION, "test-single-cert-reply.cert");
    public static final File TEST_CERT_CHAIN_REPLY_FILE = new File(WORKING_DIRECTORY_LOCATION, "test-cert-chain-reply.cert");
    public static final File TEST_EXPORTED_FILE = new File(WORKING_DIRECTORY_LOCATION, "test-exported.cert");
    public static final File TEST_TRUSTED_FILE = new File(WORKING_DIRECTORY_LOCATION, "test-trusted.cert");
    public static final File TEST_UNTRUSTED_FILE = new File(WORKING_DIRECTORY_LOCATION, "test-untrusted.cert");
    public static final File TEST_UNTRUSTED_CERT_CHAIN_REPLY_FILE = new File(WORKING_DIRECTORY_LOCATION, "test-untrusted-cert-chain-reply.cert");

    public static void setUpFiles() throws Exception {
        File workingDir = new File(WORKING_DIRECTORY_LOCATION);
        if (workingDir.exists() == false) {
            workingDir.mkdirs();
        }

        SelfSignedX509CertificateAndSigningKey rootSelfSignedX509CertificateAndSigningKey = createCertRoot(ROOT_DN);
        SelfSignedX509CertificateAndSigningKey anotherRootSelfSignedX509CertificateAndSigningKey = createCertRoot(ANOTHER_ROOT_DN);
        SelfSignedX509CertificateAndSigningKey sallySelfSignedX509CertificateAndSigningKey = createSallyCertificate();

        PublicKey publicKey = sallySelfSignedX509CertificateAndSigningKey.getSelfSignedCertificate().getPublicKey();

        // Key Stores
        KeyStore fireflyKeyStore = createFireflyKeyStore();
        KeyStore testKeyStore = createTestKeyStore(rootSelfSignedX509CertificateAndSigningKey, sallySelfSignedX509CertificateAndSigningKey);

        createTemporaryKeyStoreFile(fireflyKeyStore, FIREFLY_FILE);
        createTemporaryKeyStoreFile(testKeyStore, TEST_FILE);

        // Cert Files
        X509Certificate sSmithCertificate = createSSmithCertificate(rootSelfSignedX509CertificateAndSigningKey, publicKey);

        X509Certificate testTrustedCert = createTestTrustedCertificate(rootSelfSignedX509CertificateAndSigningKey);
        X509Certificate testUntrustedCert = anotherRootSelfSignedX509CertificateAndSigningKey.getSelfSignedCertificate();
        X509Certificate testUntrustedCertChainReplyCert = createTestUntrustedCertChainReplyCertificate(anotherRootSelfSignedX509CertificateAndSigningKey, publicKey);

        createTemporaryCertFile(sSmithCertificate, TEST_SINGLE_CERT_REPLY_FILE);

        createTemporaryCertFile(rootSelfSignedX509CertificateAndSigningKey.getSelfSignedCertificate(), TEST_CERT_CHAIN_REPLY_FILE);
        createTemporaryCertFile(sSmithCertificate, TEST_CERT_CHAIN_REPLY_FILE);

        createTemporaryCertFile(sallySelfSignedX509CertificateAndSigningKey.getSelfSignedCertificate(), TEST_EXPORTED_FILE);
        createTemporaryCertFile(testTrustedCert, TEST_TRUSTED_FILE);
        createTemporaryCertFile(testUntrustedCert, TEST_UNTRUSTED_FILE);

        createTemporaryCertFile(testUntrustedCertChainReplyCert, TEST_UNTRUSTED_CERT_CHAIN_REPLY_FILE);
        createTemporaryCertFile(anotherRootSelfSignedX509CertificateAndSigningKey.getSelfSignedCertificate(), TEST_UNTRUSTED_CERT_CHAIN_REPLY_FILE);
    }

    private static SelfSignedX509CertificateAndSigningKey createCertRoot(X500Principal DN) {
        return SelfSignedX509CertificateAndSigningKey.builder()
                .setDn(DN)
                .setKeyAlgorithmName("DSA")
                .setSignatureAlgorithmName("SHA1withDSA")
                .setKeySize(1024)
                .addExtension(false, "BasicConstraints", "CA:true,pathlen:2147483647")
                .build();
    }

    private static SelfSignedX509CertificateAndSigningKey createSallyCertificate() {
        return SelfSignedX509CertificateAndSigningKey.builder()
                .setDn(SALLY_DN)
                .setKeyAlgorithmName("RSA")
                .setSignatureAlgorithmName("SHA256withRSA")
                .setKeySize(1024)
                .addExtension(false, "ExtendedKeyUsage", "clientAuth")
                .addExtension(true, "KeyUsage", "digitalSignature")
                .addExtension(false, "SubjectAlternativeName", "email:sallysmith@example.com,DNS:sallysmith.example.com")
                .build();
    }

    private static KeyStore createFireflyKeyStore() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair fireflyKeys = keyPairGenerator.generateKeyPair();
        PrivateKey fireflySigningKey = fireflyKeys.getPrivate();
        PublicKey fireflyPublicKey = fireflyKeys.getPublic();

        KeyStore fireflyKeyStore = loadKeyStore();

        SelfSignedX509CertificateAndSigningKey issuerSelfSignedX509CertificateAndSigningKey = SelfSignedX509CertificateAndSigningKey.builder()
                .setDn(ROOT_DN)
                .setKeyAlgorithmName("RSA")
                .setSignatureAlgorithmName("SHA1withRSA")
                .addExtension(false, "BasicConstraints", "CA:true,pathlen:2147483647")
                .build();
        X509Certificate issuerCertificate = issuerSelfSignedX509CertificateAndSigningKey.getSelfSignedCertificate();
        fireflyKeyStore.setCertificateEntry("ca", issuerCertificate);

        X509Certificate fireflyCertificate = new X509CertificateBuilder()
                .setIssuerDn(ROOT_DN)
                .setSubjectDn(FIREFLY_DN)
                .setSignatureAlgorithmName("SHA1withRSA")
                .setSigningKey(issuerSelfSignedX509CertificateAndSigningKey.getSigningKey())
                .setPublicKey(fireflyPublicKey)
                .setSerialNumber(new BigInteger("1"))
                .addExtension(new BasicConstraintsExtension(false, false, -1))
                .build();
        fireflyKeyStore.setKeyEntry("firefly", fireflySigningKey, KEY_PASSWORD.toCharArray(), new X509Certificate[]{fireflyCertificate,issuerCertificate});

        return fireflyKeyStore;
    }

    private static KeyStore loadKeyStore() throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, null);
        return ks;
    }

    private static KeyStore createTestKeyStore(SelfSignedX509CertificateAndSigningKey rootSelfSignedX509CertificateAndSigningKey, SelfSignedX509CertificateAndSigningKey sallySelfSignedX509CertificateAndSigningKey) throws Exception {
        KeyStore testKeyStore = loadKeyStore();

        X509Certificate sallyCertificate = sallySelfSignedX509CertificateAndSigningKey.getSelfSignedCertificate();
        testKeyStore.setKeyEntry("ssmith", sallySelfSignedX509CertificateAndSigningKey.getSigningKey(), KEY_PASSWORD.toCharArray(), new X509Certificate[]{sallyCertificate});

        X509Certificate rootCertificate = rootSelfSignedX509CertificateAndSigningKey.getSelfSignedCertificate();
        testKeyStore.setKeyEntry("ca", rootSelfSignedX509CertificateAndSigningKey.getSigningKey(), KEY_PASSWORD.toCharArray(), new X509Certificate[]{rootCertificate});

        return testKeyStore;
    }

    private static void createTemporaryKeyStoreFile(KeyStore keyStore, File outputFile) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(outputFile)){
            keyStore.store(fos, KEYSTORE_PASSWORD.toCharArray());
        }
    }

    private static X509Certificate createSSmithCertificate(SelfSignedX509CertificateAndSigningKey rootSelfSignedX509CertificateAndSigningKey, PublicKey publicKey) throws Exception {
        return new X509CertificateBuilder()
                .setIssuerDn(ROOT_DN)
                .setSubjectDn(SSMITH_DN)
                .setSignatureAlgorithmName("SHA1withDSA")
                .setSigningKey(rootSelfSignedX509CertificateAndSigningKey.getSigningKey())
                .setPublicKey(publicKey)
                .build();
    }

    private static X509Certificate createTestTrustedCertificate(SelfSignedX509CertificateAndSigningKey rootSelfSignedX509CertificateAndSigningKey) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keys = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keys.getPublic();

        return new X509CertificateBuilder()
                .setIssuerDn(ROOT_DN)
                .setSubjectDn(INTERMEDIATE_DN)
                .setSignatureAlgorithmName("SHA1withDSA")
                .setSigningKey(rootSelfSignedX509CertificateAndSigningKey.getSigningKey())
                .setPublicKey(publicKey)
                .build();
    }

    private static X509Certificate createTestUntrustedCertChainReplyCertificate(SelfSignedX509CertificateAndSigningKey selfSignedX509CertificateAndSigningKey, PublicKey publicKey) throws Exception {
        return new X509CertificateBuilder()
                .setIssuerDn(ANOTHER_ROOT_DN)
                .setSubjectDn(SSMITH_DN)
                .setSignatureAlgorithmName("SHA1withDSA")
                .setSigningKey(selfSignedX509CertificateAndSigningKey.getSigningKey())
                .setPublicKey(publicKey)
                .build();
    }

    private static void createTemporaryCertFile(X509Certificate certificate, File outputFile) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(outputFile, true)){
            fos.write(certificate.getEncoded());
        }
    }

    public static void removeTestFiles() {
        File[] testFiles = {
                FIREFLY_FILE,
                TEST_FILE,
                TEST_SINGLE_CERT_REPLY_FILE,
                TEST_CERT_CHAIN_REPLY_FILE,
                TEST_EXPORTED_FILE,
                TEST_TRUSTED_FILE,
                TEST_UNTRUSTED_FILE,
                TEST_UNTRUSTED_CERT_CHAIN_REPLY_FILE
        };
        for (File file : testFiles) {
            if (file.exists()) {
                file.delete();
            }
        }
    }

    public static ClientAndServer setupTestObtainCertificateWithKeySize(ClientAndServer server, boolean ignoreTOSAcceptance) {

        // set up a mock Let's Encrypt server
        final String ACCT_PATH = "/acme/acct/2";
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"R0Qoi70t57s\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"caaIdentities\": [" + System.lineSeparator() +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator() +
                "    ]," + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String NEW_NONCE_RESPONSE = "xqvTn53klxJBCc4a3pNhijzpr4xqKPAOS-uVqH64y94";

        String QUERY_ACCT_REQUEST_BODY_1 = ignoreTOSAcceptance ? "" :
                "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJoNWlULUY4UzZMczJLZlRMNUZpNV9hRzhpdWNZTl9yajJVXy16ck8yckpxczg2WHVHQnY1SDdMZm9vOWxqM3lsaXlxNVQ2ejdkY3RZOW1rZUZXUEIxaEk0Rjg3em16azFWR05PcnM5TV9KcDlPSVc4QVllNDFsMHBvWVpNQTllQkE0ZnV6YmZDTUdONTdXRjBfMjhRRmJuWTVXblhXR3VPa0N6QS04Uk5IQlRxX3Q1a1BWRV9jNFFVemRJcVoyZG54el9FZ05jdU1hMXVHZEs3YmNybEZIdmNrWjNxMkpsT0NEckxEdEJpYW96ZnlLR0lRUlpheGRYSlE2cl9tZVdHOWhmZUJuMTZKcG5nLTU4TFd6X0VIUVFtLTN1bl85UVl4d2pIY2RDdVBUQ1RXNEFwcFdnZ1FWdE00ZTd6U1ZzMkZYczdpaVZKVzhnMUF1dFFINU53Z1EifSwibm9uY2UiOiJ4cXZUbjUza2x4SkJDYzRhM3BOaGlqenByNHhxS1BBT1MtdVZxSDY0eTk0IiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LWFjY3QifQ\",\"payload\":\"eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJtYWlsdG86YWRtaW5AbXlleGFtcGxlLmNvbSJdfQ\",\"signature\":\"bhB01ghPOvmxuw8pH5Vyl1bT7alCfY-I5cdG0HOexdjYApov1c54PhCozT2dn-AklH7O7OsBHgEimq9aS2n3kuEMA3dhC2osxx4xkSK4LtZwo7TLZHuxKCe9znQTCPni7FPfr3sJTyrLZR0vAeq7KDhxd7gvPxgzfgVtPhILXI8JsWwq6Kgy2SPJ9KOgg2xW0NQqPLtZzP23J84xpxmYHzWCxWcRNtaQQ5QtRhq6ucN_yznujH5j8535V76VJCrkAaObxUuCpZzHbRPuRm0V2QviNTHhDIomuXIQCJMzRUleBnxjezZrIxr4yCJtpJSCffG02lpsX3ytuMZeTysfiQ\"}";

        final String QUERY_ACCT_RESPONSE_BODY_1= "";

        final String QUERY_ACCT_REPLAY_NONCE_1 = "0bL9ah0ITjdvggt0P77_o8dspCfmnOen-rimw7E9qwM";
        final String ACCT_LOCATION = "http://localhost:4001" + ACCT_PATH;

        final String QUERY_ACCT_REQUEST_BODY_2 = "";

        final String QUERY_ACCT_RESPONSE_BODY_2= "{" + System.lineSeparator() +
                "  \"id\": 1," + System.lineSeparator() +
                "  \"key\": {" + System.lineSeparator() +
                "    \"kty\": \"RSA\"," + System.lineSeparator() +
                "    \"n\": \"h5iT-F8S6Ls2KfTL5Fi5_aG8iucYN_rj2U_-zrO2rJqs86XuGBv5H7Lfoo9lj3yliyq5T6z7dctY9mkeFWPB1hI4F87zmzk1VGNOrs9M_Jp9OIW8AYe41l0poYZMA9eBA4fuzbfCMGN57WF0_28QFbnY5WnXWGuOkCzA-8RNHBTq_t5kPVE_c4QUzdIqZ2dnxz_EgNcuMa1uGdK7bcrlFHvckZ3q2JlOCDrLDtBiaozfyKGIQRZaxdXJQ6r_meWG9hfeBn16Jpng-58LWz_EHQQm-3un_9QYxwjHcdCuPTCTW4AppWggQVtM4e7zSVs2FXs7iiVJW8g1AutQH5NwgQ\"," + System.lineSeparator() +
                "    \"e\": \"AQAB\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"contact\": [" + System.lineSeparator() +
                "    \"mailto:admin@myexample.com\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"initialIp\": \"10.77.77.1\"," + System.lineSeparator() +
                "  \"createdAt\": \"2018-11-26T20:25:24Z\"," + System.lineSeparator() +
                "  \"status\": \"valid\"" + System.lineSeparator() +
                "}";

        final String QUERY_ACCT_REPLAY_NONCE_2 = "na_bjoXbpRlEFD8Bb2shGzT2Xiy6_ju4Gs6YJCPPs1E";

        final String ORDER_CERT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMiIsIm5vbmNlIjoibmFfYmpvWGJwUmxFRkQ4QmIyc2hHelQyWGl5Nl9qdTRHczZZSkNQUHMxRSIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL25ldy1vcmRlciJ9\",\"payload\":\"eyJpZGVudGlmaWVycyI6W3sidHlwZSI6ImRucyIsInZhbHVlIjoiaW5sbmVzZXBwd2tmd2V3LmNvbSJ9XX0\",\"signature\":\"Xobxsl_guUz2T3bUMTAwA5A4MzZt4HBzcGPHlcaldvPm8nqh2HZ9BfRBh7pAqGJUxzFJkyPK4BhO8F4ekzEQsEOhhCsV42f9lelVp2lWFbxPdWJVIOIhfLrzMLgTfqkrfL2GIZqsWAT4B94VgbBw1dfB7NwAzujGv6kJo9USA86slStLYDE06q7lL7q0tWe63vKtPhzEJv5odgcLL8vBb9ANiM9ZeSlFprw6nzTGn3M7gVY3IlenkK8XHJjN_9Xw0aeYcOMqB5o14LowDpyKFlgPYeVuu-bhl1YcGMrDvUVj0lnZS-_YoW0vfMKyvWxWhZKbVf8UcH-e_eAVdx2cbA\"}";
        final String ORDER_CERT_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"expires\": \"2018-11-30T22:18:11.372756901Z\"," + System.lineSeparator() +
                "  \"identifiers\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns\"," + System.lineSeparator() +
                "      \"value\": \"inlneseppwkfwew.com\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"authorizations\": [" + System.lineSeparator() +
                "    \"http://localhost:4001/acme/authz/YzLqvk7GedLIVfAkreFgNcrt-KcV5MoKdMWZcOlqJpk\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"finalize\": \"http://localhost:4001/acme/finalize/2/8\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String ORDER_CERT_REPLAY_NONCE = "RvM3fgI2Z08HTzhbwKA-EnOrJtnGqV81tOlfErZIAK4";
        final String ORDER_LOCATION = "http://localhost:4001/acme/order/2/8";

        final String AUTHZ_URL = "/acme/authz/YzLqvk7GedLIVfAkreFgNcrt-KcV5MoKdMWZcOlqJpk";
        final String AUTHZ_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMiIsIm5vbmNlIjoiUnZNM2ZnSTJaMDhIVHpoYndLQS1Fbk9ySnRuR3FWODF0T2xmRXJaSUFLNCIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2F1dGh6L1l6THF2azdHZWRMSVZmQWtyZUZnTmNydC1LY1Y1TW9LZE1XWmNPbHFKcGsifQ\",\"payload\":\"\",\"signature\":\"C5nBE_22rqq5LsqDGackn_v09Jltf09fg-aPIW_xdL9jKWu2cOlU_ktFTYGI1JEzYyVplzoLLzkXgfmOdQKlm9IrxMWB7FsY_JzfEl2bHGsacE3we-OzPXFMQjPblAyc--7Prk56_mMtVpGaJMJAYOu4Nr3ZkcdWkjTvkNyRFGj2dinKS2aFytngBG26zZbLVTgZpXXHuvSxAd8C0cgc5KxJbk8iI3E9r39k_7RcbMRQ-2_scmoiWMTyipav7kBqEj8LSPqHLNeUo7hbui0Jwh8vQ6VFc1kMURqTGioXfzGQytsm3C2A6wOYGLdPgKldVu1J9ruD_bGw2NjUmMp_kw\"}";
        final String AUTHZ_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"identifier\": {" + System.lineSeparator() +
                "    \"type\": \"dns\"," + System.lineSeparator() +
                "    \"value\": \"inlneseppwkfwew.com\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"expires\": \"2018-11-30T22:18:11Z\"," + System.lineSeparator() +
                "  \"challenges\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-alpn-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/YzLqvk7GedLIVfAkreFgNcrt-KcV5MoKdMWZcOlqJpk/17\"," + System.lineSeparator() +
                "      \"token\": \"vKGXiPTz4xRD23TLKdFKUflWK6DdEPIWOdChQxWBJTA\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-sni-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/YzLqvk7GedLIVfAkreFgNcrt-KcV5MoKdMWZcOlqJpk/18\"," + System.lineSeparator() +
                "      \"token\": \"6BIn9ySZG5m9yweJX1KKkRsJa_B0alX4DrfQF1YtmJc\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/YzLqvk7GedLIVfAkreFgNcrt-KcV5MoKdMWZcOlqJpk/19\"," + System.lineSeparator() +
                "      \"token\": \"59uoXgFHuyYVwZDxIyXIhFe-OZkFlJhk_3iFiENmRZ4\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"http-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/YzLqvk7GedLIVfAkreFgNcrt-KcV5MoKdMWZcOlqJpk/20\"," + System.lineSeparator() +
                "      \"token\": \"DGdnia8PWJaVYXnFZOdQGOedbryAWa7AUEk9UjSxA0w\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String AUTHZ_REPLAY_NONCE = "KvD4oVF2ahe2w2RtqbjYP9nJH_xzVWeHJIlhDRNn-N4";

        final String CHALLENGE_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMiIsIm5vbmNlIjoiS3ZENG9WRjJhaGUydzJSdHFiallQOW5KSF94elZXZUhKSWxoRFJObi1ONCIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2NoYWxsZW5nZS9Zekxxdms3R2VkTElWZkFrcmVGZ05jcnQtS2NWNU1vS2RNV1pjT2xxSnBrLzIwIn0\",\"payload\":\"e30\",\"signature\":\"FyKdGn_TlCbEg21RtgXSIZS8Js0YGMFHv5V1SJaefy1LDw_YeSx5_X1g_rEB1BLGuxUoIv96CMDeX-_GAb5PNYSVQfzc_kEIs8YLpVWrWCq_KVNbRx1NWBl5Vc4hYgwWa246wWMD2AjMBOtD46ncuYinJkueHX3sbW_CKBMEo-LG3SdupX-sNckcpuQqlRdNaEwfi1hxEZLjoHvlyzfg9kUH4m39wsoSXELQm2ZeYv8pUOqvXH3M02Ik4CjT_2_lhh0NzU6Kh_WXrHawK-2FPkSYN0xdqh4qK1i_YcUSG9_trtgxcHBVJLfn9jroqpmpy7Y4Li8M4C4J-M90nzPMXQ\"}";
        final String CHALLENGE_URL = "/acme/challenge/YzLqvk7GedLIVfAkreFgNcrt-KcV5MoKdMWZcOlqJpk/20";

        final String CHALLENGE_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"type\": \"http-01\"," + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"url\": \"http://localhost:4001/acme/challenge/YzLqvk7GedLIVfAkreFgNcrt-KcV5MoKdMWZcOlqJpk/20\"," + System.lineSeparator() +
                "  \"token\": \"DGdnia8PWJaVYXnFZOdQGOedbryAWa7AUEk9UjSxA0w\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String CHALLENGE_REPLAY_NONCE = "A-3-ge_TjcQwoYdlSJX4YtznB5fPVME627MwK-U_GkM";
        final String CHALLENGE_LOCATION = "http://localhost:4001/acme/challenge/YzLqvk7GedLIVfAkreFgNcrt-KcV5MoKdMWZcOlqJpk/20";
        final String CHALLENGE_LINK = "<http://localhost:4001/acme/authz/LJRH3-gjUPt5U5v8wH1Ch3eFcxu8UK-uotjutm5NB9s>;rel=\"up\"";
        final String VERIFY_CHALLENGE_URL = "/.well-known/acme-challenge/DGdnia8PWJaVYXnFZOdQGOedbryAWa7AUEk9UjSxA0w";
        final String CHALLENGE_FILE_CONTENTS = "DGdnia8PWJaVYXnFZOdQGOedbryAWa7AUEk9UjSxA0w.w2Peh-j-AQnRWPMr_Xjf-IdvQBZYnSj__5h29xxhwkk";

        final String UPDATED_AUTHZ_REPLAY_NONCE = "jBxAXwYy9_19Bue5Wcij8aiAegiC4nqGTFD_42k3HQQ";
        final String UPDATED_AUTHZ_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"identifier\": {" + System.lineSeparator() +
                "    \"type\": \"dns\"," + System.lineSeparator() +
                "    \"value\": \"inlneseppwkfwew.com\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"status\": \"valid\"," + System.lineSeparator() +
                "  \"expires\": \"2018-12-23T22:18:11Z\"," + System.lineSeparator() +
                "  \"challenges\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-alpn-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/YzLqvk7GedLIVfAkreFgNcrt-KcV5MoKdMWZcOlqJpk/17\"," + System.lineSeparator() +
                "      \"token\": \"vKGXiPTz4xRD23TLKdFKUflWK6DdEPIWOdChQxWBJTA\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-sni-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/YzLqvk7GedLIVfAkreFgNcrt-KcV5MoKdMWZcOlqJpk/18\"," + System.lineSeparator() +
                "      \"token\": \"6BIn9ySZG5m9yweJX1KKkRsJa_B0alX4DrfQF1YtmJc\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/YzLqvk7GedLIVfAkreFgNcrt-KcV5MoKdMWZcOlqJpk/19\"," + System.lineSeparator() +
                "      \"token\": \"59uoXgFHuyYVwZDxIyXIhFe-OZkFlJhk_3iFiENmRZ4\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"http-01\"," + System.lineSeparator() +
                "      \"status\": \"valid\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/YzLqvk7GedLIVfAkreFgNcrt-KcV5MoKdMWZcOlqJpk/20\"," + System.lineSeparator() +
                "      \"token\": \"DGdnia8PWJaVYXnFZOdQGOedbryAWa7AUEk9UjSxA0w\"," + System.lineSeparator() +
                "      \"validationRecord\": [" + System.lineSeparator() +
                "        {" + System.lineSeparator() +
                "          \"url\": \"http://172.17.0.1:5002/.well-known/acme-challenge/DGdnia8PWJaVYXnFZOdQGOedbryAWa7AUEk9UjSxA0w\"," + System.lineSeparator() +
                "          \"hostname\": \"inlneseppwkfwew.com\"," + System.lineSeparator() +
                "          \"port\": \"5002\"," + System.lineSeparator() +
                "          \"addressesResolved\": [" + System.lineSeparator() +
                "            \"172.17.0.1\"" + System.lineSeparator() +
                "          ]," + System.lineSeparator() +
                "          \"addressUsed\": \"172.17.0.1\"" + System.lineSeparator() +
                "        }" + System.lineSeparator() +
                "      ]" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String FINALIZE_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMiIsIm5vbmNlIjoiakJ4QVh3WXk5XzE5QnVlNVdjaWo4YWlBZWdpQzRucUdURkRfNDJrM0hRUSIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2ZpbmFsaXplLzIvOCJ9\",\"payload\":\"eyJjc3IiOiJNSUlFc3pDQ0Fwc0NBUUF3SGpFY01Cb0dBMVVFQXd3VGFXNXNibVZ6WlhCd2QydG1kMlYzTG1OdmJUQ0NBaUl3RFFZSktvWklodmNOQVFFQkJRQURnZ0lQQURDQ0Fnb0NnZ0lCQUtaSU15U2NOczM0UHNPTUtXZjE5cy1ORTBMNDVaUGYxdDVVZjhGYllfYkV2UFpiSG1qbS1RalhTQ1dVZmowelVzdHo2N3h2RXZicS01d2h5Zk9tQ2VBOWw4djBrZHBacHRwdUtIdjN6T05URDBCd2N3c01adzhYTm9DQXdQWk1DTUNqMTZPNDIzYjRzbTE0RDBEUGg2bEkwanI3dXB1QVhTWXU4YkNJeUVISllJY2ZDd2pGOXNUeUctV3p6SjdwMWhwV2F1N0s5MmFNekRQTGZBandUSkFqdGNxNEhuNl9GX3NIQXNQM0RhWU5lMnp4QUxaWXRiYzBKSGFELWdreVNILUZ6TU9pWlNJR0FTNFJCV3E4S2pwUkE3YWFTaDNfWDBjNG9kbFVPVjVXYVJWbjF0eWlGaGItMlNFT2IzQW0tb19uanBqUjBTYlVrNlZlZ0xicWVyQ2V1WGdZUzNYcXF5MlU3cTZtY0FFQUF6TzktcFlpM1Fza01hQXB3XzFhUUFSUU5JWFo3NWRpcGlmN295UzdtS0hTM0RaZUtPTDRuUlY1dFRyMjY2NFc4VUxZdjlhRmJGcFp2ak5EYThlYUl4QVdGWnEwYlN1UFhISjBjVjFGOHlaMUItT2Y4bGRhZmFjWGQxTms4S0swamw3MXRoVzhraFdtekJmNTdjR1Q3bUQ0a1dmcXY3YVJ0cVVfVE1RWjM4cDdGbnp0ZFhFTUpMQTZLRVhkV04yMU5hZkxodU1uRVBqSW9Rc2d2UEVsOEJVTDdZMkwtMC1MX2JuMEc5aV9LVG4tWFdteFdDNHk4dmdZMVQ0VVV1RkptT0lYSnl3TVFmMllvWDVIZUZ1bW10S3hHRHhrMjltSURTdHotSWVQd2lUOUE4SGtlVG5hcXN5RG1CQXpyWE5KQWdNQkFBR2dVREJPQmdrcWhraUc5dzBCQ1E0eFFUQV9NQjRHQTFVZEVRUVhNQldDRTJsdWJHNWxjMlZ3Y0hkclpuZGxkeTVqYjIwd0hRWURWUjBPQkJZRUZNRmszanFiXzRQWFZnRzhPa1ZsUXMzSzZPZkRNQTBHQ1NxR1NJYjNEUUVCREFVQUE0SUNBUUFGaXpjQW5sbmYwNUxad0duR3pKZHhQTHNndGhtanp3Uy0xcWJ2dy1kNlpmNGEtSGVBdjZTakNoVXgtVUI5UklpTy1HWERranp5eVpMUFlkbE50SlAteGNCeGs0YXZDc1ZvR0x5TUdMMVE1ejItcURXOXdoakR1M210TndvVFQ5REx3Sk1UUEJLV1ROWU9Za25tQkk1WDF1alpJVkFfSjJmUHA3SzNVMlJJQXdDNE9FX01sMzVYOElJU0hsTmplMUtMOVlNN0F4a0thcm03Wl9ic1lYcFVkQmR1T2VZRGNsbkdrRU1hT0Q4WDAxVUhuS1FmRVRlLUlmb0lXYVBSZWZWNGh4SnU5MndDR3EySnUtWVY3X0k2VVRGU1B1cUZJM0JrWXBXcUVIUUdWV2Qtck1MQ194UVVSbHNxWHhfbG5KQjlPdGFmcHpYblNCU0lRRk1xdm81Z2J3VWVscENpTDA0T280ZTNfS0NfSGtLQ3c0ZTNZdXdnY2FFUVJ3YUVZS1Y0UEc5QmNsbE1Ia19McE5LVXM1SGE1NDh6V1JNQWhRc2c3d0NIZHEzb2xwZWUyWUowbUN4cjdDLUlqT2dmcFhrdUtwYWhITUs2UzlybU9zZjdLaHVLeXpWLVBHalAybXZmTXo1b2RfZVlRV3M1UHVlbDVjMEhnbkRjdlBhVGRwTDdrZ1V5TEpHRWVBUVQ3WkE5cGxscm1hSDA1aDZRREtwNHBCLUJieTBaaHVYWlFxV2hmbmZsak91dklHN0hWUzlXWXlhTl9mdlBJOFJJa1F0MTdXQ094cEZYNDJ5YmRtWC1IVUdqLWYwS3NfOExudUVsMjBhazZ3bjZFRldLOWRRZnBaOXZIcndybTVMV0xaenlhdG1zSmI4QW1KUGhjQ3lOUFVjcFJfZmg3ZyJ9\",\"signature\":\"Cs0G6_pY_ql1INkfziVjpTW2lzlNdnW7HAn1pKwlCcb2h5IFjUA-JAfCxUrWR_uMNnvlk7-KuwtTNN_AXSaocuRlc6uJd7ZsF2xpTrkGFrTDolVjfM8VxSQYZlLhN_TMKyFyH-Dxn0fAptM2Xm3PZBSkkXMuuiSuqjMUV4fGKGEik4WERuUJZsEgdiPUsZu61usfk3kyjZ1MetgU7VzMMXg0e3tTd5t490B4X6fad8sllmee1TpTFhdfNRFcf6GYDcPnkyApvRsI9sc5gB0WM_Q_zrFip5Rk2irA2QQZeVkYmdQ7E5wEucnoxbjoY-m3A4d-4y4mcBSSZ5OA1AOKHQ\"}";
        final String FINALIZE_URL = "/acme/finalize/2/8";

        final String FINALIZE_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"status\": \"valid\"," + System.lineSeparator() +
                "  \"expires\": \"2018-11-30T22:18:11Z\"," + System.lineSeparator() +
                "  \"identifiers\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns\"," + System.lineSeparator() +
                "      \"value\": \"inlneseppwkfwew.com\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"authorizations\": [" + System.lineSeparator() +
                "    \"http://localhost:4001/acme/authz/YzLqvk7GedLIVfAkreFgNcrt-KcV5MoKdMWZcOlqJpk\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"finalize\": \"http://localhost:4001/acme/finalize/2/8\"," + System.lineSeparator() +
                "  \"certificate\": \"http://localhost:4001/acme/cert/fff0ba7aa54a2ce6597c0fa0dd6f7c8e87a7\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String FINALIZE_REPLAY_NONCE = "l_OFFmSJQuq27CFQSG6N-2vbNCbyHG7E_RyF3J45wvg";
        final String FINALIZE_LOCATION = "http://localhost:4001/acme/order/2/8";

        final String CHECK_ORDER_URL = "/acme/order/2/8";
        final String CHECK_ORDER_REPLAY_NONCE = "yuXkl473reHRMcaVgTyTZ1AWO8Z_HbiHo9oj3RdoUog";

        final String CHECK_ORDER_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMiIsIm5vbmNlIjoibF9PRkZtU0pRdXEyN0NGUVNHNk4tMnZiTkNieUhHN0VfUnlGM0o0NXd2ZyIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL29yZGVyLzIvOCJ9\",\"payload\":\"\",\"signature\":\"drMLY2890JViRe2N8BZB2gfpveieZ0hzOUYHJYz9eUPOhAzYJyS658OAs27oil7LnRVFFVdLu6iIYKmeCjS3tRWNkFQLPba8EDRSaGaJQGshaVhHtvxfv-p3M_0pJ3Mu7lJDzDwzzbZ_cYeeqI0txp1qXNqp68Ac7aT946nRrsLPaefiff0n0tGtlYvnc3TXML3hohhLtz_4xXmWnr3f_-dT17BSAZNDPrp1d7wFaoD1LVEBwTG1X-NFNOPweQ0imAEUQCg8ZPDNSbBBxxO1iLqNjQXITPxBV3hz-fmLDzh82Pgfs4KkSBtUPPkxDAX4Re6LHzkW7J-Vqu_E2NH01Q\"}";
        final String CHECK_ORDER_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"status\": \"valid\"," + System.lineSeparator() +
                "  \"expires\": \"2018-11-30T22:18:11Z\"," + System.lineSeparator() +
                "  \"identifiers\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns\"," + System.lineSeparator() +
                "      \"value\": \"inlneseppwkfwew.com\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"authorizations\": [" + System.lineSeparator() +
                "    \"http://localhost:4001/acme/authz/YzLqvk7GedLIVfAkreFgNcrt-KcV5MoKdMWZcOlqJpk\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"finalize\": \"http://localhost:4001/acme/finalize/2/8\"," + System.lineSeparator() +
                "  \"certificate\": \"http://localhost:4001/acme/cert/fff0ba7aa54a2ce6597c0fa0dd6f7c8e87a7\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String CERT_URL = "/acme/cert/fff0ba7aa54a2ce6597c0fa0dd6f7c8e87a7";
        final String CERT_REPLAY_NONCE = "9Ir87CU21P5mNNGfhBASf2dkD7QpJdZfB9BGMIzQW9Q";

        final String CERT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMiIsIm5vbmNlIjoieXVYa2w0NzNyZUhSTWNhVmdUeVRaMUFXTzhaX0hiaUhvOW9qM1Jkb1VvZyIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2NlcnQvZmZmMGJhN2FhNTRhMmNlNjU5N2MwZmEwZGQ2ZjdjOGU4N2E3In0\",\"payload\":\"\",\"signature\":\"NyRAnCigeTinK1pdkEhzO1ZKwCzuG70hNBbySxzkoS00SNq-KNA_eYu9Hk5FK7SA8HPWWadgJ4UA2GNEotqaQKzMpinPPonW2hX_SrLOcUTcRAYsggpoQl6jLRCT7O4bJ4Glve_IrAW1F2GEEqWHAhEnTSQDpZul9d5qrORjUxt7qu8A_5nAbssPDErplv2uXJH4BZAyLS2v4g-MG-Yf-Iun8kN7QC4-9uFNlIZMQyclqO1nYEUbVYanZnvxTv0WysabMZlsTmCJtElsfGdraJqBMnFvstd5E5dKqcGibq5uzleJgxYd2e5sFJfKe7cew7pbVTqvjl-nk1EwqUVizw\"}";
        final String CERT_RESPONSE_BODY = "-----BEGIN CERTIFICATE-----" + System.lineSeparator() +
                "MIIGRjCCBS6gAwIBAgITAP/wunqlSizmWXwPoN1vfI6HpzANBgkqhkiG9w0BAQsF" + System.lineSeparator() +
                "ADAfMR0wGwYDVQQDDBRoMnBweSBoMmNrZXIgZmFrZSBDQTAeFw0xODExMjMyMTE4" + System.lineSeparator() +
                "MTJaFw0xOTAyMjEyMTE4MTJaMB4xHDAaBgNVBAMTE2lubG5lc2VwcHdrZndldy5j" + System.lineSeparator() +
                "b20wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCmSDMknDbN+D7DjCln" + System.lineSeparator() +
                "9fbPjRNC+OWT39beVH/BW2P2xLz2Wx5o5vkI10gllH49M1LLc+u8bxL26vucIcnz" + System.lineSeparator() +
                "pgngPZfL9JHaWababih798zjUw9AcHMLDGcPFzaAgMD2TAjAo9ejuNt2+LJteA9A" + System.lineSeparator() +
                "z4epSNI6+7qbgF0mLvGwiMhByWCHHwsIxfbE8hvls8ye6dYaVmruyvdmjMwzy3wI" + System.lineSeparator() +
                "8EyQI7XKuB5+vxf7BwLD9w2mDXts8QC2WLW3NCR2g/oJMkh/hczDomUiBgEuEQVq" + System.lineSeparator() +
                "vCo6UQO2mkod/19HOKHZVDleVmkVZ9bcohYW/tkhDm9wJvqP546Y0dEm1JOlXoC2" + System.lineSeparator() +
                "6nqwnrl4GEt16qstlO6upnABAAMzvfqWIt0LJDGgKcP9WkAEUDSF2e+XYqYn+6Mk" + System.lineSeparator() +
                "u5ih0tw2Xiji+J0VebU69uuuFvFC2L/WhWxaWb4zQ2vHmiMQFhWatG0rj1xydHFd" + System.lineSeparator() +
                "RfMmdQfjn/JXWn2nF3dTZPCitI5e9bYVvJIVpswX+e3Bk+5g+JFn6r+2kbalP0zE" + System.lineSeparator() +
                "Gd/KexZ87XVxDCSwOihF3VjdtTWny4bjJxD4yKELILzxJfAVC+2Ni/tPi/259BvY" + System.lineSeparator() +
                "vyk5/l1psVguMvL4GNU+FFLhSZjiFycsDEH9mKF+R3hbpprSsRg8ZNvZiA0rc/iH" + System.lineSeparator() +
                "j8Ik/QPB5Hk52qrMg5gQM61zSQIDAQABo4ICejCCAnYwDgYDVR0PAQH/BAQDAgWg" + System.lineSeparator() +
                "MB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0G" + System.lineSeparator() +
                "A1UdDgQWBBTBZN46m/+D11YBvDpFZULNyujnwzAfBgNVHSMEGDAWgBT7eE8S+WAV" + System.lineSeparator() +
                "gyyfF380GbMuNupBiTBkBggrBgEFBQcBAQRYMFYwIgYIKwYBBQUHMAGGFmh0dHA6" + System.lineSeparator() +
                "Ly8xMjcuMC4wLjE6NDAwMi8wMAYIKwYBBQUHMAKGJGh0dHA6Ly9ib3VsZGVyOjQ0" + System.lineSeparator() +
                "MzAvYWNtZS9pc3N1ZXItY2VydDAeBgNVHREEFzAVghNpbmxuZXNlcHB3a2Z3ZXcu" + System.lineSeparator() +
                "Y29tMCcGA1UdHwQgMB4wHKAaoBiGFmh0dHA6Ly9leGFtcGxlLmNvbS9jcmwwQAYD" + System.lineSeparator() +
                "VR0gBDkwNzAIBgZngQwBAgEwKwYDKgMEMCQwIgYIKwYBBQUHAgEWFmh0dHA6Ly9l" + System.lineSeparator() +
                "eGFtcGxlLmNvbS9jcHMwggEEBgorBgEEAdZ5AgQCBIH1BIHyAPAAdgAodhoYkCf7" + System.lineSeparator() +
                "7zzQ1hoBjXawUFcpx6dBG8y99gT0XUJhUwAAAWdCpuW/AAAEAwBHMEUCIQDSlIhR" + System.lineSeparator() +
                "AaD+KnEI3cUBIigDrbXJxXDYUIwoIcYErsHF7gIgXbY/rmJ6LCbYyt8PwZkDVStn" + System.lineSeparator() +
                "2Khogm0Tk5hK4FynyxYAdgAW6GnB0ZXq18P4lxrj8HYB94zhtp0xqFIYtoN/MagV" + System.lineSeparator() +
                "CAAAAWdCpuuZAAAEAwBHMEUCIQDmVp+En4lRjkqn23HuzJk2mEkGbuDOQvLcZ+XH" + System.lineSeparator() +
                "hj4DcgIgBpfHfTG7i3mtCTYz20hP72/9qbEyKI8I/0yt/bMMjlEwDQYJKoZIhvcN" + System.lineSeparator() +
                "AQELBQADggEBAEMZGO3pbTME1J97CDjpK8SX/0HUyOa8fyLXn8et6R6Q+LfhtZuE" + System.lineSeparator() +
                "Tb+RsKtx+QcEiqwFTQF5/tIqHh3T8QoXZvSvanUmn+/wAjgmhllRHbVuNe/8QB+f" + System.lineSeparator() +
                "NE+hhbpB5IPiQjBFPNuTyHSq5HZisrPKXr9hjKc+UhqHu6VC6kgQT7JrAlQ3YXcA" + System.lineSeparator() +
                "rIUGyi325G8mOUqs+vl24Lu6ll2BP9kHTBatYJyj0b1JnuVpIiCCXSS13v3VYg+b" + System.lineSeparator() +
                "ejRaEGe9QhHNHEola5ZxYb/Ryacvd/ZGZBAIRCy8zOV4zaOmP6WXk9yajUswhymx" + System.lineSeparator() +
                "uDS1f3V/hiCjfuDZ7ljN4FQYBF2eIMZT6Ks=" + System.lineSeparator() +
                "-----END CERTIFICATE-----" + System.lineSeparator() +
                "" + System.lineSeparator() +
                "-----BEGIN CERTIFICATE-----" + System.lineSeparator() +
                "MIIERTCCAy2gAwIBAgICElowDQYJKoZIhvcNAQELBQAwKzEpMCcGA1UEAwwgY2Fj" + System.lineSeparator() +
                "a2xpbmcgY3J5cHRvZ3JhcGhlciBmYWtlIFJPT1QwHhcNMTYwMzIyMDI0NzUyWhcN" + System.lineSeparator() +
                "MjEwMzIxMDI0NzUyWjAfMR0wGwYDVQQDDBRoMnBweSBoMmNrZXIgZmFrZSBDQTCC" + System.lineSeparator() +
                "ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMIKR3maBcUSsncXYzQT13D5" + System.lineSeparator() +
                "Nr+Z3mLxMMh3TUdt6sACmqbJ0btRlgXfMtNLM2OU1I6a3Ju+tIZSdn2v21JBwvxU" + System.lineSeparator() +
                "zpZQ4zy2cimIiMQDZCQHJwzC9GZn8HaW091iz9H0Go3A7WDXwYNmsdLNRi00o14U" + System.lineSeparator() +
                "joaVqaPsYrZWvRKaIRqaU0hHmS0AWwQSvN/93iMIXuyiwywmkwKbWnnxCQ/gsctK" + System.lineSeparator() +
                "FUtcNrwEx9Wgj6KlhwDTyI1QWSBbxVYNyUgPFzKxrSmwMO0yNff7ho+QT9x5+Y/7" + System.lineSeparator() +
                "XE59S4Mc4ZXxcXKew/gSlN9U5mvT+D2BhDtkCupdfsZNCQWp27A+b/DmrFI9NqsC" + System.lineSeparator() +
                "AwEAAaOCAX0wggF5MBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGG" + System.lineSeparator() +
                "MH8GCCsGAQUFBwEBBHMwcTAyBggrBgEFBQcwAYYmaHR0cDovL2lzcmcudHJ1c3Rp" + System.lineSeparator() +
                "ZC5vY3NwLmlkZW50cnVzdC5jb20wOwYIKwYBBQUHMAKGL2h0dHA6Ly9hcHBzLmlk" + System.lineSeparator() +
                "ZW50cnVzdC5jb20vcm9vdHMvZHN0cm9vdGNheDMucDdjMB8GA1UdIwQYMBaAFOmk" + System.lineSeparator() +
                "P+6epeby1dd5YDyTpi4kjpeqMFQGA1UdIARNMEswCAYGZ4EMAQIBMD8GCysGAQQB" + System.lineSeparator() +
                "gt8TAQEBMDAwLgYIKwYBBQUHAgEWImh0dHA6Ly9jcHMucm9vdC14MS5sZXRzZW5j" + System.lineSeparator() +
                "cnlwdC5vcmcwPAYDVR0fBDUwMzAxoC+gLYYraHR0cDovL2NybC5pZGVudHJ1c3Qu" + System.lineSeparator() +
                "Y29tL0RTVFJPT1RDQVgzQ1JMLmNybDAdBgNVHQ4EFgQU+3hPEvlgFYMsnxd/NBmz" + System.lineSeparator() +
                "LjbqQYkwDQYJKoZIhvcNAQELBQADggEBAKvePfYXBaAcYca2e0WwkswwJ7lLU/i3" + System.lineSeparator() +
                "GIFM8tErKThNf3gD3KdCtDZ45XomOsgdRv8oxYTvQpBGTclYRAqLsO9t/LgGxeSB" + System.lineSeparator() +
                "jzwY7Ytdwwj8lviEGtiun06sJxRvvBU+l9uTs3DKBxWKZ/YRf4+6wq/vERrShpEC" + System.lineSeparator() +
                "KuQ5+NgMcStQY7dywrsd6x1p3bkOvowbDlaRwru7QCIXTBSb8TepKqCqRzr6YREt" + System.lineSeparator() +
                "doIw2FE8MKMCGR2p+U3slhxfLTh13MuqIOvTuA145S/qf6xCkRc9I92GpjoQk87Z" + System.lineSeparator() +
                "v1uhpkgT9uwbRw0Cs5DMdxT/LgIUSfUTKU83GNrbrQNYinkJ77i6wG0=" + System.lineSeparator() +
                "-----END CERTIFICATE-----" + System.lineSeparator();

        return new AcmeMockServerBuilder(server)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .addNewAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY_1, QUERY_ACCT_RESPONSE_BODY_1, QUERY_ACCT_REPLAY_NONCE_1, ACCT_LOCATION, 200)
                .updateAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY_2, QUERY_ACCT_RESPONSE_BODY_2, QUERY_ACCT_REPLAY_NONCE_2, ACCT_PATH, 200)
                .orderCertificateRequestAndResponse(ORDER_CERT_REQUEST_BODY, ORDER_CERT_RESPONSE_BODY, ORDER_CERT_REPLAY_NONCE, ORDER_LOCATION, 201, false)
                .addAuthorizationResponseBody(AUTHZ_URL, AUTHZ_REQUEST_BODY, AUTHZ_RESPONSE_BODY, AUTHZ_REPLAY_NONCE)
                .addChallengeRequestAndResponse(CHALLENGE_REQUEST_BODY, CHALLENGE_URL, CHALLENGE_RESPONSE_BODY, CHALLENGE_REPLAY_NONCE, CHALLENGE_LOCATION, CHALLENGE_LINK, 200, false, VERIFY_CHALLENGE_URL, CHALLENGE_FILE_CONTENTS, AUTHZ_URL, UPDATED_AUTHZ_RESPONSE_BODY, UPDATED_AUTHZ_REPLAY_NONCE)
                .addFinalizeRequestAndResponse(FINALIZE_RESPONSE_BODY, FINALIZE_REPLAY_NONCE, FINALIZE_URL, FINALIZE_LOCATION, 200)
                .addCheckOrderRequestAndResponse(CHECK_ORDER_URL, CHECK_ORDER_REQUEST_BODY, CHECK_ORDER_RESPONSE_BODY, CHECK_ORDER_REPLAY_NONCE, 200)
                .addCertificateRequestAndResponse(CERT_URL, CERT_REQUEST_BODY, CERT_RESPONSE_BODY, CERT_REPLAY_NONCE, 200)
                .build();
    }

    public static String getJBossHome() {
        String jbossHome = getSystemProperty("jboss.dist");
        if (jbossHome == null) {
            jbossHome = getSystemProperty("jboss.home");
        }
        return jbossHome == null ? System.getenv("JBOSS_HOME") : jbossHome;
    }

    public static String getSystemProperty(String name) {
        return System.getProperty(name);
    }

}
