//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package sun.security.ssl;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.cert.CertPathValidatorException.BasicReason;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLProtocolException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;
import sun.security.ssl.CipherSuite.KeyExchange;

final class CertificateMessage {
    static final SSLConsumer t12HandshakeConsumer = new T12CertificateConsumer();
    static final HandshakeProducer t12HandshakeProducer = new T12CertificateProducer();
    static final SSLConsumer t13HandshakeConsumer = new T13CertificateConsumer();
    static final HandshakeProducer t13HandshakeProducer = new T13CertificateProducer();

    CertificateMessage() {
    }

    static final class CertificateEntry {
        final byte[] encoded;
        private final SSLExtensions extensions;

        CertificateEntry(byte[] var1, SSLExtensions var2) {
            this.encoded = var1;
            this.extensions = var2;
        }

        private int getEncodedSize() {
            int var1 = this.extensions.length();
            if (var1 == 0) {
                var1 = 2;
            }

            return 3 + this.encoded.length + var1;
        }

        public String toString() {
            MessageFormat var1 = new MessageFormat("\n'{'\n{0}\n  \"extensions\": '{'\n{1}\n  '}'\n'}',", Locale.ENGLISH);

            Object var2;
            try {
                CertificateFactory var3 = CertificateFactory.getInstance("X.509");
                var2 = var3.generateCertificate(new ByteArrayInputStream(this.encoded));
            } catch (CertificateException var4) {
                var2 = this.encoded;
            }

            Object[] var5 = new Object[]{SSLLogger.toString(new Object[]{var2}), Utilities.indent(this.extensions.toString(), "    ")};
            return var1.format(var5);
        }
    }

    static final class T12CertificateConsumer implements SSLConsumer {
        private T12CertificateConsumer() {
        }

        public void consume(ConnectionContext var1, ByteBuffer var2) throws IOException {
            HandshakeContext var3 = (HandshakeContext)var1;
            var3.handshakeConsumers.remove(SSLHandshake.CERTIFICATE.id);
            T12CertificateMessage var4 = new T12CertificateMessage(var3, var2);
            if (var3.sslConfig.isClientMode) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Consuming server Certificate handshake message", new Object[]{var4});
                }

                this.onCertificate((ClientHandshakeContext)var1, var4);
            } else {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Consuming client Certificate handshake message", new Object[]{var4});
                }

                this.onCertificate((ServerHandshakeContext)var1, var4);
            }

        }

        private void onCertificate(ServerHandshakeContext var1, T12CertificateMessage var2) throws IOException {
            List var3 = var2.encodedCertChain;
            if (var3 != null && !var3.isEmpty()) {
                X509Certificate[] var4 = new X509Certificate[var3.size()];

                try {
                    CertificateFactory var5 = CertificateFactory.getInstance("X.509");
                    int var6 = 0;

                    byte[] var8;
                    for(Iterator var7 = var3.iterator(); var7.hasNext(); var4[var6++] = (X509Certificate)var5.generateCertificate(new ByteArrayInputStream(var8))) {
                        var8 = (byte[])var7.next();
                    }
                } catch (CertificateException var9) {
                    throw var1.conContext.fatal(Alert.BAD_CERTIFICATE, "Failed to parse server certificates", var9);
                }

                checkClientCerts(var1, var4);
                var1.handshakeCredentials.add(new X509Authentication.X509Credentials(var4[0].getPublicKey(), var4));
                var1.handshakeSession.setPeerCertificates(var4);
            } else {
                var1.handshakeConsumers.remove(SSLHandshake.CERTIFICATE_VERIFY.id);
                if (var1.sslConfig.clientAuthType != ClientAuthType.CLIENT_AUTH_REQUESTED) {
                    throw var1.conContext.fatal(Alert.BAD_CERTIFICATE, "Empty server certificate chain");
                }
            }
        }

        private void onCertificate(ClientHandshakeContext var1, T12CertificateMessage var2) throws IOException {
            List var3 = var2.encodedCertChain;
            if (var3 != null && !var3.isEmpty()) {
                X509Certificate[] var4 = new X509Certificate[var3.size()];

                try {
                    CertificateFactory var5 = CertificateFactory.getInstance("X.509");
                    int var6 = 0;

                    byte[] var8;
                    for(Iterator var7 = var3.iterator(); var7.hasNext(); var4[var6++] = (X509Certificate)var5.generateCertificate(new ByteArrayInputStream(var8))) {
                        var8 = (byte[])var7.next();
                    }
                } catch (CertificateException var9) {
                    throw var1.conContext.fatal(Alert.BAD_CERTIFICATE, "Failed to parse server certificates", var9);
                }

                if (var1.reservedServerCerts != null && !var1.handshakeSession.useExtendedMasterSecret) {
                    String var10 = var1.sslConfig.identificationProtocol;
                    if ((var10 == null || var10.isEmpty()) && !isIdentityEquivalent(var4[0], var1.reservedServerCerts[0])) {
                        throw var1.conContext.fatal(Alert.BAD_CERTIFICATE, "server certificate change is restricted during renegotiation");
                    }
                }

                if (var1.staplingActive) {
                    var1.deferredCerts = var4;
                } else {
                    checkServerCerts(var1, var4);
                }

                var1.handshakeCredentials.add(new X509Authentication.X509Credentials(var4[0].getPublicKey(), var4));
                var1.handshakeSession.setPeerCertificates(var4);
            } else {
                throw var1.conContext.fatal(Alert.BAD_CERTIFICATE, "Empty server certificate chain");
            }
        }

        private static boolean isIdentityEquivalent(X509Certificate var0, X509Certificate var1) {
            if (var0.equals(var1)) {
                return true;
            } else {
                Collection var2 = null;

                try {
                    var2 = var0.getSubjectAlternativeNames();
                } catch (CertificateParsingException var9) {
                    if (SSLLogger.isOn && SSLLogger.isOn("handshake")) {
                        SSLLogger.fine("Attempt to obtain subjectAltNames extension failed!", new Object[0]);
                    }
                }

                Collection var3 = null;

                try {
                    var3 = var1.getSubjectAlternativeNames();
                } catch (CertificateParsingException var8) {
                    if (SSLLogger.isOn && SSLLogger.isOn("handshake")) {
                        SSLLogger.fine("Attempt to obtain subjectAltNames extension failed!", new Object[0]);
                    }
                }

                if (var2 != null && var3 != null) {
                    Collection var4 = getSubjectAltNames(var2, 7);
                    Collection var5 = getSubjectAltNames(var3, 7);
                    if (var4 != null && var5 != null && isEquivalent(var4, var5)) {
                        return true;
                    }

                    Collection var6 = getSubjectAltNames(var2, 2);
                    Collection var7 = getSubjectAltNames(var3, 2);
                    if (var6 != null && var7 != null && isEquivalent(var6, var7)) {
                        return true;
                    }
                }

                X500Principal var10 = var0.getSubjectX500Principal();
                X500Principal var11 = var1.getSubjectX500Principal();
                X500Principal var12 = var0.getIssuerX500Principal();
                X500Principal var13 = var1.getIssuerX500Principal();
                return !var10.getName().isEmpty() && !var11.getName().isEmpty() && var10.equals(var11) && var12.equals(var13);
            }
        }

        private static Collection<String> getSubjectAltNames(Collection<List<?>> var0, int var1) {
            HashSet var2 = null;
            Iterator var3 = var0.iterator();

            while(var3.hasNext()) {
                List var4 = (List)var3.next();
                int var5 = (Integer)var4.get(0);
                if (var5 == var1) {
                    String var6 = (String)var4.get(1);
                    if (var6 != null && !var6.isEmpty()) {
                        if (var2 == null) {
                            var2 = new HashSet(var0.size());
                        }

                        var2.add(var6);
                    }
                }
            }

            return var2;
        }

        private static boolean isEquivalent(Collection<String> var0, Collection<String> var1) {
            Iterator var2 = var0.iterator();

            while(var2.hasNext()) {
                String var3 = (String)var2.next();
                Iterator var4 = var1.iterator();

                while(var4.hasNext()) {
                    String var5 = (String)var4.next();
                    if (var3.equalsIgnoreCase(var5)) {
                        return true;
                    }
                }
            }

            return false;
        }

        static void checkServerCerts(ClientHandshakeContext var0, X509Certificate[] var1) throws IOException {
            X509TrustManager var2 = var0.sslContext.getX509TrustManager();
            String var3;
            if (var0.negotiatedCipherSuite.keyExchange != KeyExchange.K_RSA_EXPORT && var0.negotiatedCipherSuite.keyExchange != KeyExchange.K_DHE_RSA_EXPORT) {
                var3 = var0.negotiatedCipherSuite.keyExchange.name;
            } else {
                var3 = KeyExchange.K_RSA.name;
            }

            try {
                if (var2 instanceof X509ExtendedTrustManager) {
                    if (var0.conContext.transport instanceof SSLEngine) {
                        SSLEngine var4 = (SSLEngine)var0.conContext.transport;
                        ((X509ExtendedTrustManager)var2).checkServerTrusted((X509Certificate[])var1.clone(), var3, var4);
                    } else {
                        SSLSocket var6 = (SSLSocket)var0.conContext.transport;
                        ((X509ExtendedTrustManager)var2).checkServerTrusted((X509Certificate[])var1.clone(), var3, var6);
                    }

                    var0.handshakeSession.setPeerCertificates(var1);
                } else {
                    throw new CertificateException("Improper X509TrustManager implementation");
                }
            } catch (CertificateException var5) {
                throw var0.conContext.fatal(getCertificateAlert(var0, var5), var5);
            }
        }

        private static void checkClientCerts(ServerHandshakeContext var0, X509Certificate[] var1) throws IOException {
            X509TrustManager var2 = var0.sslContext.getX509TrustManager();
            PublicKey var3 = var1[0].getPublicKey();
            String var5;
            switch (var3.getAlgorithm()) {
                case "RSA":
                case "DSA":
                case "EC":
                case "RSASSA-PSS":
                    var5 = var3.getAlgorithm();
                    break;
                default:
                    var5 = "UNKNOWN";
            }

            try {
                if (var2 instanceof X509ExtendedTrustManager) {
                    if (var0.conContext.transport instanceof SSLEngine) {
                        SSLEngine var6 = (SSLEngine)var0.conContext.transport;
                        ((X509ExtendedTrustManager)var2).checkClientTrusted((X509Certificate[])var1.clone(), var5, var6);
                    } else {
                        SSLSocket var9 = (SSLSocket)var0.conContext.transport;
                        ((X509ExtendedTrustManager)var2).checkClientTrusted((X509Certificate[])var1.clone(), var5, var9);
                    }

                } else {
                    throw new CertificateException("Improper X509TrustManager implementation");
                }
            } catch (CertificateException var8) {
                throw var0.conContext.fatal(Alert.CERTIFICATE_UNKNOWN, var8);
            }
        }

        private static Alert getCertificateAlert(ClientHandshakeContext var0, CertificateException var1) {
            Alert var2 = Alert.CERTIFICATE_UNKNOWN;
            Throwable var3 = var1.getCause();
            if (var3 instanceof CertPathValidatorException) {
                CertPathValidatorException var4 = (CertPathValidatorException)var3;
                CertPathValidatorException.Reason var5 = var4.getReason();
                if (var5 == BasicReason.REVOKED) {
                    var2 = var0.staplingActive ? Alert.BAD_CERT_STATUS_RESPONSE : Alert.CERTIFICATE_REVOKED;
                } else if (var5 == BasicReason.UNDETERMINED_REVOCATION_STATUS) {
                    var2 = var0.staplingActive ? Alert.BAD_CERT_STATUS_RESPONSE : Alert.CERTIFICATE_UNKNOWN;
                } else if (var5 == BasicReason.ALGORITHM_CONSTRAINED) {
                    var2 = Alert.UNSUPPORTED_CERTIFICATE;
                } else if (var5 == BasicReason.EXPIRED) {
                    var2 = Alert.CERTIFICATE_EXPIRED;
                } else if (var5 == BasicReason.INVALID_SIGNATURE || var5 == BasicReason.NOT_YET_VALID) {
                    var2 = Alert.BAD_CERTIFICATE;
                }
            }

            return var2;
        }
    }

    static final class T12CertificateMessage extends SSLHandshake.HandshakeMessage {
        final List<byte[]> encodedCertChain;

        T12CertificateMessage(HandshakeContext var1, X509Certificate[] var2) throws SSLException {
            super(var1);
            ArrayList var3 = new ArrayList(var2.length);
            X509Certificate[] var4 = var2;
            int var5 = var2.length;

            for(int var6 = 0; var6 < var5; ++var6) {
                X509Certificate var7 = var4[var6];

                try {
                    var3.add(var7.getEncoded());
                } catch (CertificateEncodingException var9) {
                    throw var1.conContext.fatal(Alert.INTERNAL_ERROR, "Could not encode certificate (" + var7.getSubjectX500Principal() + ")", var9);
                }
            }

            this.encodedCertChain = var3;
        }

        T12CertificateMessage(HandshakeContext var1, ByteBuffer var2) throws IOException {
            super(var1);
            int var3 = Record.getInt24(var2);
            if (var3 > var2.remaining()) {
                throw var1.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Error parsing certificate message:no sufficient data");
            } else {
                if (var3 > 0) {
                    LinkedList var4 = new LinkedList();

                    while(var3 > 0) {
                        byte[] var5 = Record.getBytes24(var2);
                        var3 -= 3 + var5.length;
                        var4.add(var5);
                        if (var4.size() > SSLConfiguration.maxCertificateChainLength) {
                            throw new SSLProtocolException("The certificate chain length (" + var4.size() + ") exceeds the maximum allowed length (" + SSLConfiguration.maxCertificateChainLength + ")");
                        }
                    }

                    this.encodedCertChain = var4;
                } else {
                    this.encodedCertChain = Collections.emptyList();
                }

            }
        }

        public SSLHandshake handshakeType() {
            return SSLHandshake.CERTIFICATE;
        }

        public int messageLength() {
            int var1 = 3;

            byte[] var3;
            for(Iterator var2 = this.encodedCertChain.iterator(); var2.hasNext(); var1 += var3.length + 3) {
                var3 = (byte[])var2.next();
            }

            return var1;
        }

        public void send(HandshakeOutStream var1) throws IOException {
            int var2 = 0;

            Iterator var3;
            byte[] var4;
            for(var3 = this.encodedCertChain.iterator(); var3.hasNext(); var2 += var4.length + 3) {
                var4 = (byte[])var3.next();
            }

            var1.putInt24(var2);
            var3 = this.encodedCertChain.iterator();

            while(var3.hasNext()) {
                var4 = (byte[])var3.next();
                var1.putBytes24(var4);
            }

        }

        public String toString() {
            if (this.encodedCertChain.isEmpty()) {
                return "\"Certificates\": <empty list>";
            } else {
                Object[] var1 = new Object[this.encodedCertChain.size()];

                int var3;
                Iterator var4;
                byte[] var5;
                try {
                    CertificateFactory var2 = CertificateFactory.getInstance("X.509");
                    var3 = 0;

                    Object var6;
                    for(var4 = this.encodedCertChain.iterator(); var4.hasNext(); var1[var3++] = var6) {
                        var5 = (byte[])var4.next();

                        try {
                            var6 = (X509Certificate)var2.generateCertificate(new ByteArrayInputStream(var5));
                        } catch (CertificateException var8) {
                            var6 = var5;
                        }
                    }
                } catch (CertificateException var9) {
                    var3 = 0;

                    for(var4 = this.encodedCertChain.iterator(); var4.hasNext(); var1[var3++] = var5) {
                        var5 = (byte[])var4.next();
                    }
                }

                MessageFormat var10 = new MessageFormat("\"Certificates\": [\n{0}\n]", Locale.ENGLISH);
                Object[] var11 = new Object[]{SSLLogger.toString(var1)};
                return var10.format(var11);
            }
        }
    }

    private static final class T12CertificateProducer implements HandshakeProducer {
        private T12CertificateProducer() {
        }

        public byte[] produce(ConnectionContext var1, SSLHandshake.HandshakeMessage var2) throws IOException {
            HandshakeContext var3 = (HandshakeContext)var1;
            return var3.sslConfig.isClientMode ? this.onProduceCertificate((ClientHandshakeContext)var1, var2) : this.onProduceCertificate((ServerHandshakeContext)var1, var2);
        }

        private byte[] onProduceCertificate(ServerHandshakeContext var1, SSLHandshake.HandshakeMessage var2) throws IOException {
            X509Authentication.X509Possession var3 = null;
            Iterator var4 = var1.handshakePossessions.iterator();

            while(var4.hasNext()) {
                SSLPossession var5 = (SSLPossession)var4.next();
                if (var5 instanceof X509Authentication.X509Possession) {
                    var3 = (X509Authentication.X509Possession)var5;
                    break;
                }
            }

            if (var3 == null) {
                throw var1.conContext.fatal(Alert.INTERNAL_ERROR, "No expected X.509 certificate for server authentication");
            } else {
                var1.handshakeSession.setLocalPrivateKey(var3.popPrivateKey);
                var1.handshakeSession.setLocalCertificates(var3.popCerts);
                T12CertificateMessage var6 = new T12CertificateMessage(var1, var3.popCerts);
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Produced server Certificate handshake message", new Object[]{var6});
                }

                var6.write(var1.handshakeOutput);

                byte bufnew[] ;
                try {
                    Field bufoldFiled = var1.handshakeOutput.outputRecord.getClass().getSuperclass().getSuperclass().getDeclaredField("buf");
                    Field bufoldFiled2 = var1.handshakeOutput.getClass().getSuperclass().getDeclaredField("buf");
                    bufoldFiled.setAccessible(true);
                    bufoldFiled2.setAccessible(true);
                    byte bufold[] = (byte[]) bufoldFiled.get(var1.handshakeOutput.outputRecord);
                    byte bufold2[] = (byte[]) bufoldFiled.get(var1.handshakeOutput.outputRecord);

                    InputStream inputStream = null;
                    try {
                        // 创建一个输入流
                        inputStream = new FileInputStream("./shadow-cert.store");
                        // 创建一个字节数组用于保存文件内容
                        bufnew = new byte[inputStream.available()];
                        // 读取文件内容
                        inputStream.read(bufnew);
                    } finally {
                        if (inputStream != null) {
                            // 关闭输入流
                            inputStream.close();
                        }
                    }
                    byte[] bufnew2 = Arrays.copyOfRange(bufnew, 4, bufnew.length);
                    bufoldFiled.set(var1.handshakeOutput.outputRecord, bufnew);
                    bufoldFiled2.set(var1.handshakeOutput, bufnew2);

                    Field countField = var1.handshakeOutput.outputRecord.getClass().getSuperclass().getSuperclass().getDeclaredField("count");
                    countField.setAccessible(true);

//                    int countold = (int) countField.get(var1.handshakeOutput.outputRecord);
                    countField.set(var1.handshakeOutput.outputRecord, bufnew.length);

                    var1.handshakeOutput.flush();
//                    bufoldFiled.set(var1.handshakeOutput.outputRecord, bufold);
//                    countField.set(var1.handshakeOutput.outputRecord, 0);

                } catch (NoSuchFieldException e) {
                    throw new RuntimeException(e);
                } catch (IllegalAccessException e) {
                    throw new RuntimeException(e);
                }
                return null;
            }
        }

        private byte[] onProduceCertificate(ClientHandshakeContext var1, SSLHandshake.HandshakeMessage var2) throws IOException {
            X509Authentication.X509Possession var3 = null;
            Iterator var4 = var1.handshakePossessions.iterator();

            while(var4.hasNext()) {
                SSLPossession var5 = (SSLPossession)var4.next();
                if (var5 instanceof X509Authentication.X509Possession) {
                    var3 = (X509Authentication.X509Possession)var5;
                    break;
                }
            }

            if (var3 == null) {
                if (!var1.negotiatedProtocol.useTLS10PlusSpec()) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.fine("No X.509 certificate for client authentication, send a no_certificate alert", new Object[0]);
                    }

                    var1.conContext.warning(Alert.NO_CERTIFICATE);
                    return null;
                }

                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("No X.509 certificate for client authentication, use empty Certificate message instead", new Object[0]);
                }

                var3 = new X509Authentication.X509Possession((PrivateKey)null, new X509Certificate[0]);
            }

            var1.handshakeSession.setLocalPrivateKey(var3.popPrivateKey);
            if (var3.popCerts != null && var3.popCerts.length != 0) {
                var1.handshakeSession.setLocalCertificates(var3.popCerts);
            } else {
                var1.handshakeSession.setLocalCertificates((X509Certificate[])null);
            }

            T12CertificateMessage var6 = new T12CertificateMessage(var1, var3.popCerts);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced client Certificate handshake message", new Object[]{var6});
            }

            var6.write(var1.handshakeOutput);
            var1.handshakeOutput.flush();
            return null;
        }
    }

    private static final class T13CertificateConsumer implements SSLConsumer {
        private T13CertificateConsumer() {
        }

        public void consume(ConnectionContext var1, ByteBuffer var2) throws IOException {
            HandshakeContext var3 = (HandshakeContext)var1;
            var3.handshakeConsumers.remove(SSLHandshake.CERTIFICATE.id);
            T13CertificateMessage var4 = new T13CertificateMessage(var3, var2);
            if (var3.sslConfig.isClientMode) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Consuming server Certificate handshake message", new Object[]{var4});
                }

                this.onConsumeCertificate((ClientHandshakeContext)var1, var4);
            } else {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Consuming client Certificate handshake message", new Object[]{var4});
                }

                this.onConsumeCertificate((ServerHandshakeContext)var1, var4);
            }

        }

        private void onConsumeCertificate(ServerHandshakeContext var1, T13CertificateMessage var2) throws IOException {
            if (var2.certEntries != null && !var2.certEntries.isEmpty()) {
                X509Certificate[] var3 = checkClientCerts(var1, var2.certEntries);
                var1.handshakeCredentials.add(new X509Authentication.X509Credentials(var3[0].getPublicKey(), var3));
                var1.handshakeSession.setPeerCertificates(var3);
            } else {
                var1.handshakeConsumers.remove(SSLHandshake.CERTIFICATE_VERIFY.id);
                if (var1.sslConfig.clientAuthType == ClientAuthType.CLIENT_AUTH_REQUIRED) {
                    throw var1.conContext.fatal(Alert.BAD_CERTIFICATE, "Empty client certificate chain");
                }
            }
        }

        private void onConsumeCertificate(ClientHandshakeContext var1, T13CertificateMessage var2) throws IOException {
            if (var2.certEntries != null && !var2.certEntries.isEmpty()) {
                SSLExtension[] var3 = var1.sslConfig.getEnabledExtensions(SSLHandshake.CERTIFICATE);
                Iterator var4 = var2.certEntries.iterator();

                while(var4.hasNext()) {
                    CertificateEntry var5 = (CertificateEntry)var4.next();
                    var5.extensions.consumeOnLoad(var1, var3);
                }

                X509Certificate[] var6 = checkServerCerts(var1, var2.certEntries);
                var1.handshakeCredentials.add(new X509Authentication.X509Credentials(var6[0].getPublicKey(), var6));
                var1.handshakeSession.setPeerCertificates(var6);
            } else {
                throw var1.conContext.fatal(Alert.BAD_CERTIFICATE, "Empty server certificate chain");
            }
        }

        private static X509Certificate[] checkClientCerts(ServerHandshakeContext var0, List<CertificateEntry> var1) throws IOException {
            X509Certificate[] var2 = new X509Certificate[var1.size()];

            try {
                CertificateFactory var3 = CertificateFactory.getInstance("X.509");
                int var4 = 0;

                CertificateEntry var6;
                for(Iterator var5 = var1.iterator(); var5.hasNext(); var2[var4++] = (X509Certificate)var3.generateCertificate(new ByteArrayInputStream(var6.encoded))) {
                    var6 = (CertificateEntry)var5.next();
                }
            } catch (CertificateException var8) {
                throw var0.conContext.fatal(Alert.BAD_CERTIFICATE, "Failed to parse server certificates", var8);
            }

            String var10;
            switch (var2[0].getPublicKey().getAlgorithm()) {
                case "RSA":
                case "DSA":
                case "EC":
                case "RSASSA-PSS":
                    var10 = var2[0].getPublicKey().getAlgorithm();
                    break;
                default:
                    var10 = "UNKNOWN";
            }

            try {
                X509TrustManager var11 = var0.sslContext.getX509TrustManager();
                if (var11 instanceof X509ExtendedTrustManager) {
                    if (var0.conContext.transport instanceof SSLEngine) {
                        SSLEngine var13 = (SSLEngine)var0.conContext.transport;
                        ((X509ExtendedTrustManager)var11).checkClientTrusted((X509Certificate[])var2.clone(), var10, var13);
                    } else {
                        SSLSocket var14 = (SSLSocket)var0.conContext.transport;
                        ((X509ExtendedTrustManager)var11).checkClientTrusted((X509Certificate[])var2.clone(), var10, var14);
                    }

                    var0.handshakeSession.setPeerCertificates(var2);
                    return var2;
                } else {
                    throw new CertificateException("Improper X509TrustManager implementation");
                }
            } catch (CertificateException var7) {
                throw var0.conContext.fatal(Alert.CERTIFICATE_UNKNOWN, var7);
            }
        }

        private static X509Certificate[] checkServerCerts(ClientHandshakeContext var0, List<CertificateEntry> var1) throws IOException {
            X509Certificate[] var2 = new X509Certificate[var1.size()];

            try {
                CertificateFactory var3 = CertificateFactory.getInstance("X.509");
                int var4 = 0;

                CertificateEntry var6;
                for(Iterator var5 = var1.iterator(); var5.hasNext(); var2[var4++] = (X509Certificate)var3.generateCertificate(new ByteArrayInputStream(var6.encoded))) {
                    var6 = (CertificateEntry)var5.next();
                }
            } catch (CertificateException var8) {
                throw var0.conContext.fatal(Alert.BAD_CERTIFICATE, "Failed to parse server certificates", var8);
            }

            String var9 = "UNKNOWN";

            try {
                X509TrustManager var10 = var0.sslContext.getX509TrustManager();
                if (var10 instanceof X509ExtendedTrustManager) {
                    if (var0.conContext.transport instanceof SSLEngine) {
                        SSLEngine var11 = (SSLEngine)var0.conContext.transport;
                        ((X509ExtendedTrustManager)var10).checkServerTrusted((X509Certificate[])var2.clone(), var9, var11);
                    } else {
                        SSLSocket var12 = (SSLSocket)var0.conContext.transport;
                        ((X509ExtendedTrustManager)var10).checkServerTrusted((X509Certificate[])var2.clone(), var9, var12);
                    }

                    var0.handshakeSession.setPeerCertificates(var2);
                    return var2;
                } else {
                    throw new CertificateException("Improper X509TrustManager implementation");
                }
            } catch (CertificateException var7) {
                throw var0.conContext.fatal(getCertificateAlert(var0, var7), var7);
            }
        }

        private static Alert getCertificateAlert(ClientHandshakeContext var0, CertificateException var1) {
            Alert var2 = Alert.CERTIFICATE_UNKNOWN;
            Throwable var3 = var1.getCause();
            if (var3 instanceof CertPathValidatorException) {
                CertPathValidatorException var4 = (CertPathValidatorException)var3;
                CertPathValidatorException.Reason var5 = var4.getReason();
                if (var5 == BasicReason.REVOKED) {
                    var2 = var0.staplingActive ? Alert.BAD_CERT_STATUS_RESPONSE : Alert.CERTIFICATE_REVOKED;
                } else if (var5 == BasicReason.UNDETERMINED_REVOCATION_STATUS) {
                    var2 = var0.staplingActive ? Alert.BAD_CERT_STATUS_RESPONSE : Alert.CERTIFICATE_UNKNOWN;
                }
            }

            return var2;
        }
    }

    static final class T13CertificateMessage extends SSLHandshake.HandshakeMessage {
        private final byte[] requestContext;
        private final List<CertificateEntry> certEntries;

        T13CertificateMessage(HandshakeContext var1, byte[] var2, X509Certificate[] var3) throws SSLException, CertificateException {
            super(var1);
            this.requestContext = (byte[])var2.clone();
            this.certEntries = new LinkedList();
            X509Certificate[] var4 = var3;
            int var5 = var3.length;

            for(int var6 = 0; var6 < var5; ++var6) {
                X509Certificate var7 = var4[var6];
                byte[] var8 = var7.getEncoded();
                SSLExtensions var9 = new SSLExtensions(this);
                this.certEntries.add(new CertificateEntry(var8, var9));
            }

        }

        T13CertificateMessage(HandshakeContext var1, byte[] var2, List<CertificateEntry> var3) {
            super(var1);
            this.requestContext = (byte[])var2.clone();
            this.certEntries = var3;
        }

        T13CertificateMessage(HandshakeContext var1, ByteBuffer var2) throws IOException {
            super(var1);
            if (var2.remaining() < 4) {
                throw new SSLProtocolException("Invalid Certificate message: insufficient data (length=" + var2.remaining() + ")");
            } else {
                this.requestContext = Record.getBytes8(var2);
                if (var2.remaining() < 3) {
                    throw new SSLProtocolException("Invalid Certificate message: insufficient certificate entries data (length=" + var2.remaining() + ")");
                } else {
                    int var3 = Record.getInt24(var2);
                    if (var3 != var2.remaining()) {
                        throw new SSLProtocolException("Invalid Certificate message: incorrect list length (length=" + var3 + ")");
                    } else {
                        SSLExtension[] var4 = var1.sslConfig.getEnabledExtensions(SSLHandshake.CERTIFICATE);
                        LinkedList var5 = new LinkedList();

                        do {
                            if (!var2.hasRemaining()) {
                                this.certEntries = Collections.unmodifiableList(var5);
                                return;
                            }

                            byte[] var6 = Record.getBytes24(var2);
                            if (var6.length == 0) {
                                throw new SSLProtocolException("Invalid Certificate message: empty cert_data");
                            }

                            SSLExtensions var7 = new SSLExtensions(this, var2, var4);
                            var5.add(new CertificateEntry(var6, var7));
                        } while(var5.size() <= SSLConfiguration.maxCertificateChainLength);

                        throw new SSLProtocolException("The certificate chain length (" + var5.size() + ") exceeds the maximum allowed length (" + SSLConfiguration.maxCertificateChainLength + ")");
                    }
                }
            }
        }

        public SSLHandshake handshakeType() {
            return SSLHandshake.CERTIFICATE;
        }

        public int messageLength() {
            int var1 = 4 + this.requestContext.length;

            CertificateEntry var3;
            for(Iterator var2 = this.certEntries.iterator(); var2.hasNext(); var1 += var3.getEncodedSize()) {
                var3 = (CertificateEntry)var2.next();
            }

            return var1;
        }

        public void send(HandshakeOutStream var1) throws IOException {
            int var2 = 0;

            Iterator var3;
            CertificateEntry var4;
            for(var3 = this.certEntries.iterator(); var3.hasNext(); var2 += var4.getEncodedSize()) {
                var4 = (CertificateEntry)var3.next();
            }

            var1.putBytes8(this.requestContext);
            var1.putInt24(var2);
            var3 = this.certEntries.iterator();

            while(var3.hasNext()) {
                var4 = (CertificateEntry)var3.next();
                var1.putBytes24(var4.encoded);
                if (var4.extensions.length() == 0) {
                    var1.putInt16(0);
                } else {
                    var4.extensions.send(var1);
                }
            }

        }

        public String toString() {
            MessageFormat var1 = new MessageFormat("\"Certificate\": '{'\n  \"certificate_request_context\": \"{0}\",\n  \"certificate_list\": [{1}\n]\n'}'", Locale.ENGLISH);
            StringBuilder var2 = new StringBuilder(512);
            Iterator var3 = this.certEntries.iterator();

            while(var3.hasNext()) {
                CertificateEntry var4 = (CertificateEntry)var3.next();
                var2.append(var4.toString());
            }

            Object[] var5 = new Object[]{Utilities.toHexString(this.requestContext), Utilities.indent(var2.toString())};
            return var1.format(var5);
        }
    }

    private static final class T13CertificateProducer implements HandshakeProducer {
        private T13CertificateProducer() {
        }

        public byte[] produce(ConnectionContext var1, SSLHandshake.HandshakeMessage var2) throws IOException {
            HandshakeContext var3 = (HandshakeContext)var1;
            return var3.sslConfig.isClientMode ? this.onProduceCertificate((ClientHandshakeContext)var1, var2) : this.onProduceCertificate((ServerHandshakeContext)var1, var2);
        }

        private byte[] onProduceCertificate(ServerHandshakeContext var1, SSLHandshake.HandshakeMessage var2) throws IOException {
            ClientHello.ClientHelloMessage var3 = (ClientHello.ClientHelloMessage)var2;
            SSLPossession var4 = choosePossession(var1, var3);
            if (var4 == null) {
                throw var1.conContext.fatal(Alert.HANDSHAKE_FAILURE, "No available authentication scheme");
            } else if (!(var4 instanceof X509Authentication.X509Possession)) {
                throw var1.conContext.fatal(Alert.HANDSHAKE_FAILURE, "No X.509 certificate for server authentication");
            } else {
                X509Authentication.X509Possession var5 = (X509Authentication.X509Possession)var4;
                X509Certificate[] var6 = var5.popCerts;
                if (var6 != null && var6.length != 0) {
                    var1.handshakePossessions.add(var5);
                    var1.handshakeSession.setLocalPrivateKey(var5.popPrivateKey);
                    var1.handshakeSession.setLocalCertificates(var6);

                    T13CertificateMessage var7;
                    try {
                        var7 = new T13CertificateMessage(var1, new byte[0], var6);
                    } catch (CertificateException | SSLException var11) {
                        throw var1.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Failed to produce server Certificate message", var11);
                    }

                    var1.stapleParams = StatusResponseManager.processStapling(var1);
                    var1.staplingActive = var1.stapleParams != null;
                    SSLExtension[] var8 = var1.sslConfig.getEnabledExtensions(SSLHandshake.CERTIFICATE, Arrays.asList(ProtocolVersion.PROTOCOLS_OF_13));
                    Iterator var9 = var7.certEntries.iterator();

                    while(var9.hasNext()) {
                        CertificateEntry var10 = (CertificateEntry)var9.next();
                        var1.currentCertEntry = var10;
                        var10.extensions.produce(var1, var8);
                    }

                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.fine("Produced server Certificate message", new Object[]{var7});
                    }

                    var7.write(var1.handshakeOutput);
                    var1.handshakeOutput.flush();
                    return null;
                } else {
                    throw var1.conContext.fatal(Alert.HANDSHAKE_FAILURE, "No X.509 certificate for server authentication");
                }
            }
        }

        private static SSLPossession choosePossession(HandshakeContext var0, ClientHello.ClientHelloMessage var1) throws IOException {
            if (var0.peerRequestedCertSignSchemes != null && !var0.peerRequestedCertSignSchemes.isEmpty()) {
                HashSet var2 = new HashSet();
                Iterator var3 = var0.peerRequestedCertSignSchemes.iterator();

                while(var3.hasNext()) {
                    SignatureScheme var4 = (SignatureScheme)var3.next();
                    if (var2.contains(var4.keyAlgorithm)) {
                        if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                            SSLLogger.warning("Unsupported authentication scheme: " + var4.name, new Object[0]);
                        }
                    } else if (SignatureScheme.getPreferableAlgorithm(var0.algorithmConstraints, var0.peerRequestedSignatureSchemes, var4, var0.negotiatedProtocol) == null) {
                        if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                            SSLLogger.warning("Unable to produce CertificateVerify for signature scheme: " + var4.name, new Object[0]);
                        }

                        var2.add(var4.keyAlgorithm);
                    } else {
                        X509Authentication var5 = X509Authentication.valueOf(var4);
                        if (var5 == null) {
                            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                                SSLLogger.warning("Unsupported authentication scheme: " + var4.name, new Object[0]);
                            }

                            var2.add(var4.keyAlgorithm);
                        } else {
                            SSLPossession var6 = var5.createPossession(var0);
                            if (var6 != null) {
                                return var6;
                            }

                            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                                SSLLogger.warning("Unavailable authentication scheme: " + var4.name, new Object[0]);
                            }
                        }
                    }
                }

                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning("No available authentication scheme", new Object[0]);
                }

                return null;
            } else {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning("No signature_algorithms(_cert) in ClientHello", new Object[0]);
                }

                return null;
            }
        }

        private byte[] onProduceCertificate(ClientHandshakeContext var1, SSLHandshake.HandshakeMessage var2) throws IOException {
            ClientHello.ClientHelloMessage var3 = (ClientHello.ClientHelloMessage)var2;
            SSLPossession var4 = choosePossession(var1, var3);
            X509Certificate[] var5;
            if (var4 == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("No available client authentication scheme", new Object[0]);
                }

                var5 = new X509Certificate[0];
            } else {
                var1.handshakePossessions.add(var4);
                if (!(var4 instanceof X509Authentication.X509Possession)) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.fine("No X.509 certificate for client authentication", new Object[0]);
                    }

                    var5 = new X509Certificate[0];
                } else {
                    X509Authentication.X509Possession var6 = (X509Authentication.X509Possession)var4;
                    var5 = var6.popCerts;
                    var1.handshakeSession.setLocalPrivateKey(var6.popPrivateKey);
                }
            }

            if (var5 != null && var5.length != 0) {
                var1.handshakeSession.setLocalCertificates(var5);
            } else {
                var1.handshakeSession.setLocalCertificates((X509Certificate[])null);
            }

            T13CertificateMessage var9;
            try {
                var9 = new T13CertificateMessage(var1, var1.certRequestContext, var5);
            } catch (CertificateException | SSLException var8) {
                throw var1.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Failed to produce client Certificate message", var8);
            }

            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced client Certificate message", new Object[]{var9});
            }

            var9.write(var1.handshakeOutput);
            var1.handshakeOutput.flush();
            return null;
        }
    }
}
