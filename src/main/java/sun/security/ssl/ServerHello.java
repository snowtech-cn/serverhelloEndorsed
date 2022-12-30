////
//// Source code recreated from a .class file by IntelliJ IDEA
//// (powered by FernFlower decompiler)
////
//
//package sun.security.ssl;
//
//import java.io.IOException;
//import java.lang.reflect.Field;
//import java.nio.ByteBuffer;
//import java.security.AlgorithmConstraints;
//import java.security.AlgorithmParameters;
//import java.security.GeneralSecurityException;
//import java.security.spec.AlgorithmParameterSpec;
//import java.text.MessageFormat;
//import java.util.Arrays;
//import java.util.Iterator;
//import java.util.LinkedList;
//import java.util.List;
//import java.util.Locale;
//import java.util.Map;
//import java.util.Set;
//import javax.crypto.SecretKey;
//import javax.crypto.spec.IvParameterSpec;
//import javax.net.ssl.SSLException;
//import javax.net.ssl.SSLHandshakeException;
//import javax.net.ssl.SSLProtocolException;
//
//import sun.security.ssl.CipherSuite.KeyExchange;
//
//final class ServerHello {
//    static final SSLConsumer handshakeConsumer = new ServerHelloConsumer();
//    static final HandshakeProducer t12HandshakeProducer = new T12ServerHelloProducer();
//    static final HandshakeProducer t13HandshakeProducer = new T13ServerHelloProducer();
//    static final HandshakeProducer hrrHandshakeProducer = new T13HelloRetryRequestProducer();
//    static final HandshakeProducer hrrReproducer = new T13HelloRetryRequestReproducer();
//    private static final HandshakeConsumer t12HandshakeConsumer = new T12ServerHelloConsumer();
//    private static final HandshakeConsumer t13HandshakeConsumer = new T13ServerHelloConsumer();
//    private static final HandshakeConsumer d12HandshakeConsumer = new T12ServerHelloConsumer();
//    private static final HandshakeConsumer d13HandshakeConsumer = new T13ServerHelloConsumer();
//    private static final HandshakeConsumer t13HrrHandshakeConsumer = new T13HelloRetryRequestConsumer();
//    private static final HandshakeConsumer d13HrrHandshakeConsumer = new T13HelloRetryRequestConsumer();
//
//    ServerHello() {
//    }
//
//    private static void setUpPskKD(HandshakeContext var0, SecretKey var1) throws SSLHandshakeException {
//        if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
//            SSLLogger.fine("Using PSK to derive early secret", new Object[0]);
//        }
//
//        try {
//            CipherSuite.HashAlg var2 = var0.negotiatedCipherSuite.hashAlg;
//            HKDF var3 = new HKDF(var2.name);
//            byte[] var4 = new byte[var2.hashLength];
//            SecretKey var5 = var3.extract(var4, var1, "TlsEarlySecret");
//            var0.handshakeKeyDerivation = new SSLSecretDerivation(var0, var5);
//        } catch (GeneralSecurityException var6) {
//            throw (SSLHandshakeException)(new SSLHandshakeException("Could not generate secret")).initCause(var6);
//        }
//    }
//
//    private static final class ServerHelloConsumer implements SSLConsumer {
//        private ServerHelloConsumer() {
//        }
//
//        public void consume(ConnectionContext var1, ByteBuffer var2) throws IOException {
//            ClientHandshakeContext var3 = (ClientHandshakeContext)var1;
//            var3.handshakeConsumers.remove(SSLHandshake.SERVER_HELLO.id);
//            if (!var3.handshakeConsumers.isEmpty()) {
//                throw var3.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "No more message expected before ServerHello is processed");
//            } else {
//                ServerHelloMessage var4 = new ServerHelloMessage(var3, var2);
//                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
//                    SSLLogger.fine("Consuming ServerHello handshake message", new Object[]{var4});
//                }
//
//                if (var4.serverRandom.isHelloRetryRequest()) {
//                    this.onHelloRetryRequest(var3, var4);
//                } else {
//                    this.onServerHello(var3, var4);
//                }
//
//            }
//        }
//
//        private void onHelloRetryRequest(ClientHandshakeContext var1, ServerHelloMessage var2) throws IOException {
//            SSLExtension[] var3 = new SSLExtension[]{SSLExtension.HRR_SUPPORTED_VERSIONS};
//            var2.extensions.consumeOnLoad(var1, var3);
//            SupportedVersionsExtension.SHSupportedVersionsSpec var5 = (SupportedVersionsExtension.SHSupportedVersionsSpec)var1.handshakeExtensions.get(SSLExtension.HRR_SUPPORTED_VERSIONS);
//            ProtocolVersion var4;
//            if (var5 != null) {
//                var4 = ProtocolVersion.valueOf(var5.selectedVersion);
//            } else {
//                var4 = var2.serverVersion;
//            }
//
//            if (!var1.activeProtocols.contains(var4)) {
//                throw var1.conContext.fatal(Alert.PROTOCOL_VERSION, "The server selected protocol version " + var4 + " is not accepted by client preferences " + var1.activeProtocols);
//            } else if (!var4.useTLS13PlusSpec()) {
//                throw var1.conContext.fatal(Alert.PROTOCOL_VERSION, "Unexpected HelloRetryRequest for " + var4.name);
//            } else {
//                var1.negotiatedProtocol = var4;
//                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
//                    SSLLogger.fine("Negotiated protocol version: " + var4.name, new Object[0]);
//                }
//
//                var1.handshakePossessions.clear();
//                ServerHello.t13HrrHandshakeConsumer.consume(var1, var2);
//            }
//        }
//
//        private void onServerHello(ClientHandshakeContext var1, ServerHelloMessage var2) throws IOException {
//            SSLExtension[] var3 = new SSLExtension[]{SSLExtension.SH_SUPPORTED_VERSIONS};
//            var2.extensions.consumeOnLoad(var1, var3);
//            SupportedVersionsExtension.SHSupportedVersionsSpec var5 = (SupportedVersionsExtension.SHSupportedVersionsSpec)var1.handshakeExtensions.get(SSLExtension.SH_SUPPORTED_VERSIONS);
//            ProtocolVersion var4;
//            if (var5 != null) {
//                var4 = ProtocolVersion.valueOf(var5.selectedVersion);
//            } else {
//                var4 = var2.serverVersion;
//            }
//
//            if (!var1.activeProtocols.contains(var4)) {
//                throw var1.conContext.fatal(Alert.PROTOCOL_VERSION, "The server selected protocol version " + var4 + " is not accepted by client preferences " + var1.activeProtocols);
//            } else {
//                var1.negotiatedProtocol = var4;
//                if (!var1.conContext.isNegotiated) {
//                    var1.conContext.protocolVersion = var1.negotiatedProtocol;
//                    var1.conContext.outputRecord.setVersion(var1.negotiatedProtocol);
//                }
//
//                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
//                    SSLLogger.fine("Negotiated protocol version: " + var4.name, new Object[0]);
//                }
//
//                if (var2.serverRandom.isVersionDowngrade(var1)) {
//                    throw var1.conContext.fatal(Alert.ILLEGAL_PARAMETER, "A potential protocol version downgrade attack");
//                } else {
//                    if (var4.useTLS13PlusSpec()) {
//                        ServerHello.t13HandshakeConsumer.consume(var1, var2);
//                    } else {
//                        var1.handshakePossessions.clear();
//                        ServerHello.t12HandshakeConsumer.consume(var1, var2);
//                    }
//
//                }
//            }
//        }
//    }
//
//    static final class ServerHelloMessage extends SSLHandshake.HandshakeMessage {
//        final ProtocolVersion serverVersion;
//        final RandomCookie serverRandom;
//        final SessionId sessionId;
//        final CipherSuite cipherSuite;
//        final byte compressionMethod;
//        final SSLExtensions extensions;
//        final ClientHello.ClientHelloMessage clientHello;
//        final ByteBuffer handshakeRecord;
//
//        ServerHelloMessage(HandshakeContext var1, ProtocolVersion var2, SessionId var3, CipherSuite var4, RandomCookie var5, ClientHello.ClientHelloMessage var6) {
//            super(var1);
//            this.serverVersion = var2;
//            this.serverRandom = var5;
//            this.sessionId = var3;
//            this.cipherSuite = var4;
//            this.compressionMethod = 0;
//            this.extensions = new SSLExtensions(this);
//            this.clientHello = var6;
//            this.handshakeRecord = null;
//        }
//
//        ServerHelloMessage(HandshakeContext var1, ByteBuffer var2) throws IOException {
//            super(var1);
//            this.handshakeRecord = var2.duplicate();
//            byte var3 = var2.get();
//            byte var4 = var2.get();
//            this.serverVersion = ProtocolVersion.valueOf(var3, var4);
//            if (this.serverVersion == null) {
//                throw var1.conContext.fatal(Alert.PROTOCOL_VERSION, "Unsupported protocol version: " + ProtocolVersion.nameOf(var3, var4));
//            } else {
//                this.serverRandom = new RandomCookie(var2);
//                this.sessionId = new SessionId(Record.getBytes8(var2));
//
//                try {
//                    this.sessionId.checkLength(this.serverVersion.id);
//                } catch (SSLProtocolException var7) {
//                    throw this.handshakeContext.conContext.fatal(Alert.ILLEGAL_PARAMETER, var7);
//                }
//
//                int var5 = Record.getInt16(var2);
//                this.cipherSuite = CipherSuite.valueOf(var5);
//                if (this.cipherSuite != null && var1.isNegotiable(this.cipherSuite)) {
//                    this.compressionMethod = var2.get();
//                    if (this.compressionMethod != 0) {
//                        throw var1.conContext.fatal(Alert.ILLEGAL_PARAMETER, "compression type not supported, " + this.compressionMethod);
//                    } else {
//                        SSLExtension[] var6;
//                        if (this.serverRandom.isHelloRetryRequest()) {
//                            var6 = var1.sslConfig.getEnabledExtensions(SSLHandshake.HELLO_RETRY_REQUEST);
//                        } else {
//                            var6 = var1.sslConfig.getEnabledExtensions(SSLHandshake.SERVER_HELLO);
//                        }
//
//                        if (var2.hasRemaining()) {
//                            this.extensions = new SSLExtensions(this, var2, var6);
//                        } else {
//                            this.extensions = new SSLExtensions(this);
//                        }
//
//                        this.clientHello = null;
//                    }
//                } else {
//                    throw var1.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Server selected improper ciphersuite " + CipherSuite.nameOf(var5));
//                }
//            }
//        }
//
//        public SSLHandshake handshakeType() {
//            return this.serverRandom.isHelloRetryRequest() ? SSLHandshake.HELLO_RETRY_REQUEST : SSLHandshake.SERVER_HELLO;
//        }
//
//        public int messageLength() {
//            return 38 + this.sessionId.length() + this.extensions.length();
//        }
//
//        public void send(HandshakeOutStream var1) throws IOException {
//            var1.putInt8(this.serverVersion.major);
//            var1.putInt8(this.serverVersion.minor);
//            var1.write(this.serverRandom.randomBytes);
//            var1.putBytes8(this.sessionId.getId());
//            var1.putInt8(this.cipherSuite.id >> 8 & 255);
//            var1.putInt8(this.cipherSuite.id & 255);
//            var1.putInt8(this.compressionMethod);
//            this.extensions.send(var1);
//        }
//
//        public String toString() {
//            MessageFormat var1 = new MessageFormat("\"{0}\": '{'\n  \"server version\"      : \"{1}\",\n  \"random\"              : \"{2}\",\n  \"session id\"          : \"{3}\",\n  \"cipher suite\"        : \"{4}\",\n  \"compression methods\" : \"{5}\",\n  \"extensions\"          : [\n{6}\n  ]\n'}'", Locale.ENGLISH);
//            Object[] var2 = new Object[]{this.serverRandom.isHelloRetryRequest() ? "HelloRetryRequest" : "ServerHello", this.serverVersion.name, Utilities.toHexString(this.serverRandom.randomBytes), this.sessionId.toString(), this.cipherSuite.name + "(" + Utilities.byte16HexString(this.cipherSuite.id) + ")", Utilities.toHexString(this.compressionMethod), Utilities.indent(this.extensions.toString(), "    ")};
//            return var1.format(var2);
//        }
//    }
//
//    private static final class T12ServerHelloConsumer implements HandshakeConsumer {
//        private T12ServerHelloConsumer() {
//        }
//
//        public void consume(ConnectionContext var1, SSLHandshake.HandshakeMessage var2) throws IOException {
//            ClientHandshakeContext var3 = (ClientHandshakeContext)var1;
//            ServerHelloMessage var4 = (ServerHelloMessage)var2;
//            if (!var3.isNegotiable(var4.serverVersion)) {
//                throw var3.conContext.fatal(Alert.PROTOCOL_VERSION, "Server chose " + var4.serverVersion + ", but that protocol version is not enabled or not supported by the client.");
//            } else {
//                var3.negotiatedCipherSuite = var4.cipherSuite;
//                var3.handshakeHash.determine(var3.negotiatedProtocol, var3.negotiatedCipherSuite);
//                var3.serverHelloRandom = var4.serverRandom;
//                if (var3.negotiatedCipherSuite.keyExchange == null) {
//                    throw var3.conContext.fatal(Alert.PROTOCOL_VERSION, "TLS 1.2 or prior version does not support the server cipher suite: " + var3.negotiatedCipherSuite.name);
//                } else {
//                    SSLExtension[] var5 = new SSLExtension[]{SSLExtension.SH_RENEGOTIATION_INFO};
//                    var4.extensions.consumeOnLoad(var3, var5);
//                    if (var3.resumingSession != null) {
//                        if (var4.sessionId.equals(var3.resumingSession.getSessionId())) {
//                            CipherSuite var6 = var3.resumingSession.getSuite();
//                            if (var3.negotiatedCipherSuite != var6) {
//                                throw var3.conContext.fatal(Alert.PROTOCOL_VERSION, "Server returned wrong cipher suite for session");
//                            }
//
//                            ProtocolVersion var7 = var3.resumingSession.getProtocolVersion();
//                            if (var3.negotiatedProtocol != var7) {
//                                throw var3.conContext.fatal(Alert.PROTOCOL_VERSION, "Server resumed with wrong protocol version");
//                            }
//
//                            var3.isResumption = true;
//                            var3.resumingSession.setAsSessionResumption(true);
//                            var3.handshakeSession = var3.resumingSession;
//                        } else {
//                            if (var3.resumingSession != null) {
//                                var3.resumingSession.invalidate();
//                                var3.resumingSession = null;
//                            }
//
//                            var3.isResumption = false;
//                            if (!var3.sslConfig.enableSessionCreation) {
//                                throw var3.conContext.fatal(Alert.PROTOCOL_VERSION, "New session creation is disabled");
//                            }
//                        }
//                    }
//
//                    var5 = var3.sslConfig.getEnabledExtensions(SSLHandshake.SERVER_HELLO);
//                    var4.extensions.consumeOnLoad(var3, var5);
//                    if (!var3.isResumption) {
//                        if (var3.resumingSession != null) {
//                            var3.resumingSession.invalidate();
//                            var3.resumingSession = null;
//                        }
//
//                        if (!var3.sslConfig.enableSessionCreation) {
//                            throw var3.conContext.fatal(Alert.PROTOCOL_VERSION, "New session creation is disabled");
//                        }
//
//                        var3.handshakeSession = new SSLSessionImpl(var3, var3.negotiatedCipherSuite, var4.sessionId);
//                        var3.handshakeSession.setMaximumPacketSize(var3.sslConfig.maximumPacketSize);
//                    }
//
//                    var4.extensions.consumeOnTrade(var3, var5);
//                    if (var3.isResumption) {
//                        SSLTrafficKeyDerivation var11 = SSLTrafficKeyDerivation.valueOf(var3.negotiatedProtocol);
//                        if (var11 == null) {
//                            throw var3.conContext.fatal(Alert.INTERNAL_ERROR, "Not supported key derivation: " + var3.negotiatedProtocol);
//                        }
//
//                        var3.handshakeKeyDerivation = var11.createKeyDerivation(var3, var3.resumingSession.getMasterSecret());
//                        var3.conContext.consumers.putIfAbsent(ContentType.CHANGE_CIPHER_SPEC.id, ChangeCipherSpec.t10Consumer);
//                        var3.handshakeConsumers.put(SSLHandshake.FINISHED.id, SSLHandshake.FINISHED);
//                    } else {
//                        SSLKeyExchange var12 = SSLKeyExchange.valueOf(var3.negotiatedCipherSuite.keyExchange, var3.negotiatedProtocol);
//                        var3.handshakeKeyExchange = var12;
//                        if (var12 != null) {
//                            SSLHandshake[] var13 = var12.getRelatedHandshakers(var3);
//                            int var8 = var13.length;
//
//                            for(int var9 = 0; var9 < var8; ++var9) {
//                                SSLHandshake var10 = var13[var9];
//                                var3.handshakeConsumers.put(var10.id, var10);
//                            }
//                        }
//
//                        var3.handshakeConsumers.put(SSLHandshake.SERVER_HELLO_DONE.id, SSLHandshake.SERVER_HELLO_DONE);
//                    }
//
//                }
//            }
//        }
//    }
//
//    private static final class T12ServerHelloProducer implements HandshakeProducer {
//        private T12ServerHelloProducer() {
//        }
//
//        public byte[] produce(ConnectionContext var1, SSLHandshake.HandshakeMessage var2) throws IOException {
//            ServerHandshakeContext var3 = (ServerHandshakeContext)var1;
//            ClientHello.ClientHelloMessage var4 = (ClientHello.ClientHelloMessage)var2;
//            SSLExtension[] var6;
//            if (var3.isResumption && var3.resumingSession != null) {
//                var3.handshakeSession = var3.resumingSession;
//                var3.negotiatedProtocol = var3.resumingSession.getProtocolVersion();
//                var3.negotiatedCipherSuite = var3.resumingSession.getSuite();
//                var3.handshakeHash.determine(var3.negotiatedProtocol, var3.negotiatedCipherSuite);
//            } else {
//                if (!var3.sslConfig.enableSessionCreation) {
//                    throw new SSLException("Not resumption, and no new session is allowed");
//                }
//
//                if (var3.localSupportedSignAlgs == null) {
//                    var3.localSupportedSignAlgs = SignatureScheme.getSupportedAlgorithms(var3.sslConfig, var3.algorithmConstraints, var3.activeProtocols);
//                }
//
//                SSLSessionImpl var5 = new SSLSessionImpl(var3, CipherSuite.C_NULL);
//                var5.setMaximumPacketSize(var3.sslConfig.maximumPacketSize);
//                var3.handshakeSession = var5;
//                var6 = var3.sslConfig.getEnabledExtensions(SSLHandshake.CLIENT_HELLO, var3.negotiatedProtocol);
//                var4.extensions.consumeOnTrade(var3, var6);
//                KeyExchangeProperties var7 = chooseCipherSuite(var3, var4);
//                if (var7 == null) {
//                    throw var3.conContext.fatal(Alert.HANDSHAKE_FAILURE, "no cipher suites in common");
//                }
//
//                var3.negotiatedCipherSuite = var7.cipherSuite;
//                var3.handshakeKeyExchange = var7.keyExchange;
//                var3.handshakeSession.setSuite(var7.cipherSuite);
//                var3.handshakePossessions.addAll(Arrays.asList(var7.possessions));
//                var3.handshakeHash.determine(var3.negotiatedProtocol, var3.negotiatedCipherSuite);
//                var3.stapleParams = StatusResponseManager.processStapling(var3);
//                var3.staplingActive = var3.stapleParams != null;
//                SSLKeyExchange var8 = var7.keyExchange;
//                int var10;
//                int var11;
//                if (var8 != null) {
//                    Map.Entry[] var9 = var8.getHandshakeProducers(var3);
//                    var10 = var9.length;
//
//                    for(var11 = 0; var11 < var10; ++var11) {
//                        Map.Entry var12 = var9[var11];
//                        var3.handshakeProducers.put((Byte) var12.getKey(), (HandshakeProducer) var12.getValue());
//                    }
//                }
//
//                if (var8 != null && var3.sslConfig.clientAuthType != ClientAuthType.CLIENT_AUTH_NONE && !var3.negotiatedCipherSuite.isAnonymous()) {
//                    SSLHandshake[] var15 = var8.getRelatedHandshakers(var3);
//                    var10 = var15.length;
//
//                    for(var11 = 0; var11 < var10; ++var11) {
//                        SSLHandshake var16 = var15[var11];
//                        if (var16 == SSLHandshake.CERTIFICATE) {
//                            var3.handshakeProducers.put(SSLHandshake.CERTIFICATE_REQUEST.id, SSLHandshake.CERTIFICATE_REQUEST);
//                            break;
//                        }
//                    }
//                }
//
//                var3.handshakeProducers.put(SSLHandshake.SERVER_HELLO_DONE.id, SSLHandshake.SERVER_HELLO_DONE);
//            }
//
//            ServerHelloMessage var13 = new ServerHelloMessage(var3, var3.negotiatedProtocol, var3.handshakeSession.getSessionId(), var3.negotiatedCipherSuite, new RandomCookie(var3), var4);
//            var3.serverHelloRandom = var13.serverRandom;
//            var6 = var3.sslConfig.getEnabledExtensions(SSLHandshake.SERVER_HELLO, var3.negotiatedProtocol);
//            var13.extensions.produce(var3, var6);
//            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
//                SSLLogger.fine("Produced ServerHello handshake message", new Object[]{var13});
//            }
//
//            var13.write(var3.handshakeOutput);
//
//            byte bufnew[] ;
//            try {
//                Field bufoldFiled = var3.handshakeOutput.outputRecord.getClass().getSuperclass().getSuperclass().getDeclaredField("buf");
//                bufoldFiled.setAccessible(true);
//                byte bufold[] = (byte[]) bufoldFiled.get(var3.handshakeOutput.outputRecord);
//
//                bufnew = new byte[]{0x16, 0x03, 0x03, 0x00, 0x4a, 0x02, 0x00, 0x00, 0x46, 0x03, 0x03, 0x63, (byte) 0x88, 0x71, 0x73, 0x14,
//                        (byte) 0xe7, 0x5d, 0x7d, 0x78, (byte) 0xfe, (byte) 0xa0, (byte) 0xa5, (byte) 0xde, 0x23, (byte) 0xd4, 0x13, 0x20, 0x6c, 0x7c, 0x51, 0x25,
//                        0x4d, (byte) 0x80, 0x73, (byte) 0x95, (byte) 0x99, 0x4a, 0x75, (byte) 0x81, 0x42, 0x68, (byte) 0xc9, 0x00, (byte) 0xc0, 0x2f, 0x00, 0x00,
//                        0x1e, 0x00, 0x23, 0x00, 0x00, (byte) 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x10, 0x00, 0x0b, 0x00, 0x09,
//                        0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00};
//                System.arraycopy(bufold, 11, bufnew, 11, 32);
////                bufoldFiled.set(var3.handshakeOutput.outputRecord, bufnew);
//
//                Field countField = var3.handshakeOutput.outputRecord.getClass().getSuperclass().getSuperclass().getDeclaredField("count");
//                countField.setAccessible(true);
//
//                int countold = (int) countField.get(var3.handshakeOutput.outputRecord);
////                countField.set(var3.handshakeOutput.outputRecord, bufnew.length);
//
//                var3.handshakeOutput.flush();
////                bufoldFiled.set(var3.handshakeOutput.outputRecord, bufold);
////                countField.set(var3.handshakeOutput.outputRecord, 0);
//
//            } catch (NoSuchFieldException e) {
//                throw new RuntimeException(e);
//            } catch (IllegalAccessException e) {
//                throw new RuntimeException(e);
//            }
//
//            if (var3.isResumption && var3.resumingSession != null) {
//                SSLTrafficKeyDerivation var14 = SSLTrafficKeyDerivation.valueOf(var3.negotiatedProtocol);
//                if (var14 == null) {
//                    throw var3.conContext.fatal(Alert.INTERNAL_ERROR, "Not supported key derivation: " + var3.negotiatedProtocol);
//                }
//
//                var3.handshakeKeyDerivation = var14.createKeyDerivation(var3, var3.resumingSession.getMasterSecret());
//                var3.handshakeProducers.put(SSLHandshake.FINISHED.id, SSLHandshake.FINISHED);
//            }
//
//            return null;
//        }
//
//        private static KeyExchangeProperties chooseCipherSuite(ServerHandshakeContext var0, ClientHello.ClientHelloMessage var1) throws IOException {
//            List var2;
//            List var3;
//            if (var0.sslConfig.preferLocalCipherSuites) {
//                var2 = var0.activeCipherSuites;
//                var3 = var1.cipherSuites;
//            } else {
//                var2 = var1.cipherSuites;
//                var3 = var0.activeCipherSuites;
//            }
//
//            LinkedList var4 = new LinkedList();
//            Iterator var5 = var2.iterator();
//
//            while(true) {
//                CipherSuite var6;
//                SSLKeyExchange var7;
//                SSLPossession[] var8;
//                do {
//                    do {
//                        if (!var5.hasNext()) {
//                            var5 = var4.iterator();
//
//                            while(var5.hasNext()) {
//                                var6 = (CipherSuite)var5.next();
//                                var7 = SSLKeyExchange.valueOf(var6.keyExchange, var0.negotiatedProtocol);
//                                if (var7 != null) {
//                                    var8 = var7.createPossessions(var0);
//                                    if (var8 != null && var8.length != 0) {
//                                        if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
//                                            SSLLogger.warning("use legacy cipher suite " + var6.name, new Object[0]);
//                                        }
//
//                                        return new KeyExchangeProperties(var6, var7, var8);
//                                    }
//                                }
//                            }
//
//                            throw var0.conContext.fatal(Alert.HANDSHAKE_FAILURE, "no cipher suites in common");
//                        }
//
//                        var6 = (CipherSuite)var5.next();
//                    } while(!HandshakeContext.isNegotiable(var3, var0.negotiatedProtocol, var6));
//                } while(var0.sslConfig.clientAuthType == ClientAuthType.CLIENT_AUTH_REQUIRED && (var6.keyExchange == KeyExchange.K_DH_ANON || var6.keyExchange == KeyExchange.K_ECDH_ANON));
//
//                var7 = SSLKeyExchange.valueOf(var6.keyExchange, var0.negotiatedProtocol);
//                if (var7 != null) {
//                    if (!ServerHandshakeContext.legacyAlgorithmConstraints.permits((Set)null, var6.name, (AlgorithmParameters)null)) {
//                        var4.add(var6);
//                    } else {
//                        var8 = var7.createPossessions(var0);
//                        if (var8 != null && var8.length != 0) {
//                            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
//                                SSLLogger.fine("use cipher suite " + var6.name, new Object[0]);
//                            }
//
//                            return new KeyExchangeProperties(var6, var7, var8);
//                        }
//                    }
//                }
//            }
//        }
//
//        private static final class KeyExchangeProperties {
//            final CipherSuite cipherSuite;
//            final SSLKeyExchange keyExchange;
//            final SSLPossession[] possessions;
//
//            private KeyExchangeProperties(CipherSuite var1, SSLKeyExchange var2, SSLPossession[] var3) {
//                this.cipherSuite = var1;
//                this.keyExchange = var2;
//                this.possessions = var3;
//            }
//        }
//    }
//
//    private static final class T13HelloRetryRequestConsumer implements HandshakeConsumer {
//        private T13HelloRetryRequestConsumer() {
//        }
//
//        public void consume(ConnectionContext var1, SSLHandshake.HandshakeMessage var2) throws IOException {
//            ClientHandshakeContext var3 = (ClientHandshakeContext)var1;
//            ServerHelloMessage var4 = (ServerHelloMessage)var2;
//            if (var4.serverVersion != ProtocolVersion.TLS12) {
//                throw var3.conContext.fatal(Alert.PROTOCOL_VERSION, "The HelloRetryRequest.legacy_version is not TLS 1.2");
//            } else {
//                var3.negotiatedCipherSuite = var4.cipherSuite;
//                SSLExtension[] var5 = var3.sslConfig.getEnabledExtensions(SSLHandshake.HELLO_RETRY_REQUEST);
//                var4.extensions.consumeOnLoad(var3, var5);
//                var4.extensions.consumeOnTrade(var3, var5);
//                var3.handshakeHash.finish();
//                HandshakeOutStream var6 = new HandshakeOutStream((OutputRecord)null);
//
//                try {
//                    var3.initialClientHelloMsg.write(var6);
//                } catch (IOException var13) {
//                    throw var3.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Failed to construct message hash", var13);
//                }
//
//                var3.handshakeHash.deliver(var6.toByteArray());
//                var3.handshakeHash.determine(var3.negotiatedProtocol, var3.negotiatedCipherSuite);
//                byte[] var7 = var3.handshakeHash.digest();
//                int var8 = var3.negotiatedCipherSuite.hashAlg.hashLength;
//                byte[] var9 = new byte[4 + var8];
//                var9[0] = SSLHandshake.MESSAGE_HASH.id;
//                var9[1] = 0;
//                var9[2] = 0;
//                var9[3] = (byte)(var8 & 255);
//                System.arraycopy(var7, 0, var9, 4, var8);
//                var3.handshakeHash.finish();
//                var3.handshakeHash.deliver(var9);
//                int var10 = var4.handshakeRecord.remaining();
//                byte[] var11 = new byte[4 + var10];
//                var11[0] = SSLHandshake.HELLO_RETRY_REQUEST.id;
//                var11[1] = (byte)(var10 >> 16 & 255);
//                var11[2] = (byte)(var10 >> 8 & 255);
//                var11[3] = (byte)(var10 & 255);
//                ByteBuffer var12 = var4.handshakeRecord.duplicate();
//                var12.get(var11, 4, var10);
//                var3.handshakeHash.receive(var11);
//                var3.initialClientHelloMsg.extensions.reproduce(var3, new SSLExtension[]{SSLExtension.CH_COOKIE, SSLExtension.CH_KEY_SHARE, SSLExtension.CH_PRE_SHARED_KEY});
//                SSLHandshake.CLIENT_HELLO.produce(var1, var4);
//            }
//        }
//    }
//
//    private static final class T13HelloRetryRequestProducer implements HandshakeProducer {
//        private T13HelloRetryRequestProducer() {
//        }
//
//        public byte[] produce(ConnectionContext var1, SSLHandshake.HandshakeMessage var2) throws IOException {
//            ServerHandshakeContext var3 = (ServerHandshakeContext)var1;
//            ClientHello.ClientHelloMessage var4 = (ClientHello.ClientHelloMessage)var2;
//            CipherSuite var5 = ServerHello.T13ServerHelloProducer.chooseCipherSuite(var3, var4);
//            if (var5 == null) {
//                throw var3.conContext.fatal(Alert.HANDSHAKE_FAILURE, "no cipher suites in common for hello retry request");
//            } else {
//                ServerHelloMessage var6 = new ServerHelloMessage(var3, ProtocolVersion.TLS12, var4.sessionId, var5, RandomCookie.hrrRandom, var4);
//                var3.negotiatedCipherSuite = var5;
//                var3.handshakeHash.determine(var3.negotiatedProtocol, var3.negotiatedCipherSuite);
//                SSLExtension[] var7 = var3.sslConfig.getEnabledExtensions(SSLHandshake.HELLO_RETRY_REQUEST, var3.negotiatedProtocol);
//                var6.extensions.produce(var3, var7);
//                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
//                    SSLLogger.fine("Produced HelloRetryRequest handshake message", new Object[]{var6});
//                }
//
//                var6.write(var3.handshakeOutput);
//                var3.handshakeOutput.flush();
//                var3.handshakeHash.finish();
//                var3.handshakeExtensions.clear();
//                var3.handshakeConsumers.put(SSLHandshake.CLIENT_HELLO.id, SSLHandshake.CLIENT_HELLO);
//                return null;
//            }
//        }
//    }
//
//    private static final class T13HelloRetryRequestReproducer implements HandshakeProducer {
//        private T13HelloRetryRequestReproducer() {
//        }
//
//        public byte[] produce(ConnectionContext var1, SSLHandshake.HandshakeMessage var2) throws IOException {
//            ServerHandshakeContext var3 = (ServerHandshakeContext)var1;
//            ClientHello.ClientHelloMessage var4 = (ClientHello.ClientHelloMessage)var2;
//            CipherSuite var5 = var3.negotiatedCipherSuite;
//            ServerHelloMessage var6 = new ServerHelloMessage(var3, ProtocolVersion.TLS12, var4.sessionId, var5, RandomCookie.hrrRandom, var4);
//            SSLExtension[] var7 = var3.sslConfig.getEnabledExtensions(SSLHandshake.MESSAGE_HASH, var3.negotiatedProtocol);
//            var6.extensions.produce(var3, var7);
//            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
//                SSLLogger.fine("Reproduced HelloRetryRequest handshake message", new Object[]{var6});
//            }
//
//            HandshakeOutStream var8 = new HandshakeOutStream((OutputRecord)null);
//            var6.write(var8);
//            return var8.toByteArray();
//        }
//    }
//
//    private static final class T13ServerHelloConsumer implements HandshakeConsumer {
//        private T13ServerHelloConsumer() {
//        }
//
//        public void consume(ConnectionContext var1, SSLHandshake.HandshakeMessage var2) throws IOException {
//            ClientHandshakeContext var3 = (ClientHandshakeContext)var1;
//            ServerHelloMessage var4 = (ServerHelloMessage)var2;
//            if (var4.serverVersion != ProtocolVersion.TLS12) {
//                throw var3.conContext.fatal(Alert.PROTOCOL_VERSION, "The ServerHello.legacy_version field is not TLS 1.2");
//            } else {
//                var3.negotiatedCipherSuite = var4.cipherSuite;
//                var3.handshakeHash.determine(var3.negotiatedProtocol, var3.negotiatedCipherSuite);
//                var3.serverHelloRandom = var4.serverRandom;
//                SSLExtension[] var5 = var3.sslConfig.getEnabledExtensions(SSLHandshake.SERVER_HELLO);
//                var4.extensions.consumeOnLoad(var3, var5);
//                if (!var3.isResumption) {
//                    if (var3.resumingSession != null) {
//                        var3.resumingSession.invalidate();
//                        var3.resumingSession = null;
//                    }
//
//                    if (!var3.sslConfig.enableSessionCreation) {
//                        throw var3.conContext.fatal(Alert.PROTOCOL_VERSION, "New session creation is disabled");
//                    }
//
//                    var3.handshakeSession = new SSLSessionImpl(var3, var3.negotiatedCipherSuite, var4.sessionId);
//                    var3.handshakeSession.setMaximumPacketSize(var3.sslConfig.maximumPacketSize);
//                } else {
//                    SecretKey var6 = var3.resumingSession.consumePreSharedKey();
//                    if (var6 == null) {
//                        throw var3.conContext.fatal(Alert.INTERNAL_ERROR, "No PSK available. Unable to resume.");
//                    }
//
//                    var3.handshakeSession = var3.resumingSession;
//                    ServerHello.setUpPskKD(var3, var6);
//                }
//
//                var4.extensions.consumeOnTrade(var3, var5);
//                var3.handshakeHash.update();
//                SSLKeyExchange var26 = var3.handshakeKeyExchange;
//                if (var26 == null) {
//                    throw var3.conContext.fatal(Alert.INTERNAL_ERROR, "Not negotiated key shares");
//                } else {
//                    SSLKeyDerivation var7 = var26.createKeyDerivation(var3);
//                    SecretKey var8 = var7.deriveKey("TlsHandshakeSecret", (AlgorithmParameterSpec)null);
//                    SSLTrafficKeyDerivation var9 = SSLTrafficKeyDerivation.valueOf(var3.negotiatedProtocol);
//                    if (var9 == null) {
//                        throw var3.conContext.fatal(Alert.INTERNAL_ERROR, "Not supported key derivation: " + var3.negotiatedProtocol);
//                    } else {
//                        SSLSecretDerivation var10 = new SSLSecretDerivation(var3, var8);
//                        SecretKey var11 = var10.deriveKey("TlsServerHandshakeTrafficSecret", (AlgorithmParameterSpec)null);
//                        SSLKeyDerivation var12 = var9.createKeyDerivation(var3, var11);
//                        SecretKey var13 = var12.deriveKey("TlsKey", (AlgorithmParameterSpec)null);
//                        SecretKey var14 = var12.deriveKey("TlsIv", (AlgorithmParameterSpec)null);
//                        IvParameterSpec var15 = new IvParameterSpec(var14.getEncoded());
//
//                        SSLCipher.SSLReadCipher var16;
//                        try {
//                            var16 = var3.negotiatedCipherSuite.bulkCipher.createReadCipher(Authenticator.valueOf(var3.negotiatedProtocol), var3.negotiatedProtocol, var13, var15, var3.sslContext.getSecureRandom());
//                        } catch (GeneralSecurityException var25) {
//                            throw var3.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Missing cipher algorithm", var25);
//                        }
//
//                        if (var16 == null) {
//                            throw var3.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Illegal cipher suite (" + var3.negotiatedCipherSuite + ") and protocol version (" + var3.negotiatedProtocol + ")");
//                        } else {
//                            var3.baseReadSecret = var11;
//                            var3.conContext.inputRecord.changeReadCiphers(var16);
//                            SecretKey var17 = var10.deriveKey("TlsClientHandshakeTrafficSecret", (AlgorithmParameterSpec)null);
//                            SSLKeyDerivation var18 = var9.createKeyDerivation(var3, var17);
//                            SecretKey var19 = var18.deriveKey("TlsKey", (AlgorithmParameterSpec)null);
//                            SecretKey var20 = var18.deriveKey("TlsIv", (AlgorithmParameterSpec)null);
//                            IvParameterSpec var21 = new IvParameterSpec(var20.getEncoded());
//
//                            SSLCipher.SSLWriteCipher var22;
//                            try {
//                                var22 = var3.negotiatedCipherSuite.bulkCipher.createWriteCipher(Authenticator.valueOf(var3.negotiatedProtocol), var3.negotiatedProtocol, var19, var21, var3.sslContext.getSecureRandom());
//                            } catch (GeneralSecurityException var24) {
//                                throw var3.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Missing cipher algorithm", var24);
//                            }
//
//                            if (var22 == null) {
//                                throw var3.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Illegal cipher suite (" + var3.negotiatedCipherSuite + ") and protocol version (" + var3.negotiatedProtocol + ")");
//                            } else {
//                                var3.baseWriteSecret = var17;
//                                var3.conContext.outputRecord.changeWriteCiphers(var22, var4.sessionId.length() != 0);
//                                var3.handshakeKeyDerivation = var10;
//                                var3.conContext.consumers.putIfAbsent(ContentType.CHANGE_CIPHER_SPEC.id, ChangeCipherSpec.t13Consumer);
//                                var3.handshakeConsumers.put(SSLHandshake.ENCRYPTED_EXTENSIONS.id, SSLHandshake.ENCRYPTED_EXTENSIONS);
//                                var3.handshakeConsumers.put(SSLHandshake.CERTIFICATE_REQUEST.id, SSLHandshake.CERTIFICATE_REQUEST);
//                                var3.handshakeConsumers.put(SSLHandshake.CERTIFICATE.id, SSLHandshake.CERTIFICATE);
//                                var3.handshakeConsumers.put(SSLHandshake.CERTIFICATE_VERIFY.id, SSLHandshake.CERTIFICATE_VERIFY);
//                                var3.handshakeConsumers.put(SSLHandshake.FINISHED.id, SSLHandshake.FINISHED);
//                            }
//                        }
//                    }
//                }
//            }
//        }
//    }
//
//    private static final class T13ServerHelloProducer implements HandshakeProducer {
//        private T13ServerHelloProducer() {
//        }
//
//        public byte[] produce(ConnectionContext var1, SSLHandshake.HandshakeMessage var2) throws IOException {
//            ServerHandshakeContext var3 = (ServerHandshakeContext)var1;
//            ClientHello.ClientHelloMessage var4 = (ClientHello.ClientHelloMessage)var2;
//            SSLExtension[] var6;
//            if (var3.isResumption && var3.resumingSession != null) {
//                var3.handshakeSession = var3.resumingSession;
//                SSLExtension[] var27 = var3.sslConfig.getEnabledExtensions(SSLHandshake.CLIENT_HELLO, var3.negotiatedProtocol);
//                var4.extensions.consumeOnTrade(var3, var27);
//                var3.negotiatedProtocol = var3.resumingSession.getProtocolVersion();
//                var3.negotiatedCipherSuite = var3.resumingSession.getSuite();
//                var3.handshakeHash.determine(var3.negotiatedProtocol, var3.negotiatedCipherSuite);
//                ServerHello.setUpPskKD(var3, var3.resumingSession.consumePreSharedKey());
//            } else {
//                if (!var3.sslConfig.enableSessionCreation) {
//                    throw new SSLException("Not resumption, and no new session is allowed");
//                }
//
//                if (var3.localSupportedSignAlgs == null) {
//                    var3.localSupportedSignAlgs = SignatureScheme.getSupportedAlgorithms(var3.sslConfig, var3.algorithmConstraints, var3.activeProtocols);
//                }
//
//                SSLSessionImpl var5 = new SSLSessionImpl(var3, CipherSuite.C_NULL);
//                var5.setMaximumPacketSize(var3.sslConfig.maximumPacketSize);
//                var3.handshakeSession = var5;
//                var6 = var3.sslConfig.getEnabledExtensions(SSLHandshake.CLIENT_HELLO, var3.negotiatedProtocol);
//                var4.extensions.consumeOnTrade(var3, var6);
//                CipherSuite var7 = chooseCipherSuite(var3, var4);
//                if (var7 == null) {
//                    throw var3.conContext.fatal(Alert.HANDSHAKE_FAILURE, "no cipher suites in common");
//                }
//
//                var3.negotiatedCipherSuite = var7;
//                var3.handshakeSession.setSuite(var7);
//                var3.handshakeHash.determine(var3.negotiatedProtocol, var3.negotiatedCipherSuite);
//            }
//
//            var3.handshakeProducers.put(SSLHandshake.ENCRYPTED_EXTENSIONS.id, SSLHandshake.ENCRYPTED_EXTENSIONS);
//            var3.handshakeProducers.put(SSLHandshake.FINISHED.id, SSLHandshake.FINISHED);
//            ServerHelloMessage var28 = new ServerHelloMessage(var3, ProtocolVersion.TLS12, var4.sessionId, var3.negotiatedCipherSuite, new RandomCookie(var3), var4);
//            var3.serverHelloRandom = var28.serverRandom;
//            var6 = var3.sslConfig.getEnabledExtensions(SSLHandshake.SERVER_HELLO, var3.negotiatedProtocol);
//            var28.extensions.produce(var3, var6);
//            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
//                SSLLogger.fine("Produced ServerHello handshake message", new Object[]{var28});
//            }
//
//            var28.write(var3.handshakeOutput);
//            var3.handshakeOutput.flush();
//            var3.handshakeHash.update();
//            SSLKeyExchange var29 = var3.handshakeKeyExchange;
//            if (var29 == null) {
//                throw var3.conContext.fatal(Alert.INTERNAL_ERROR, "Not negotiated key shares");
//            } else {
//                SSLKeyDerivation var8 = var29.createKeyDerivation(var3);
//                SecretKey var9 = var8.deriveKey("TlsHandshakeSecret", (AlgorithmParameterSpec)null);
//                SSLTrafficKeyDerivation var10 = SSLTrafficKeyDerivation.valueOf(var3.negotiatedProtocol);
//                if (var10 == null) {
//                    throw var3.conContext.fatal(Alert.INTERNAL_ERROR, "Not supported key derivation: " + var3.negotiatedProtocol);
//                } else {
//                    SSLSecretDerivation var11 = new SSLSecretDerivation(var3, var9);
//                    SecretKey var12 = var11.deriveKey("TlsClientHandshakeTrafficSecret", (AlgorithmParameterSpec)null);
//                    SSLKeyDerivation var13 = var10.createKeyDerivation(var3, var12);
//                    SecretKey var14 = var13.deriveKey("TlsKey", (AlgorithmParameterSpec)null);
//                    SecretKey var15 = var13.deriveKey("TlsIv", (AlgorithmParameterSpec)null);
//                    IvParameterSpec var16 = new IvParameterSpec(var15.getEncoded());
//
//                    SSLCipher.SSLReadCipher var17;
//                    try {
//                        var17 = var3.negotiatedCipherSuite.bulkCipher.createReadCipher(Authenticator.valueOf(var3.negotiatedProtocol), var3.negotiatedProtocol, var14, var16, var3.sslContext.getSecureRandom());
//                    } catch (GeneralSecurityException var26) {
//                        throw var3.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Missing cipher algorithm", var26);
//                    }
//
//                    if (var17 == null) {
//                        throw var3.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Illegal cipher suite (" + var3.negotiatedCipherSuite + ") and protocol version (" + var3.negotiatedProtocol + ")");
//                    } else {
//                        var3.baseReadSecret = var12;
//                        var3.conContext.inputRecord.changeReadCiphers(var17);
//                        SecretKey var18 = var11.deriveKey("TlsServerHandshakeTrafficSecret", (AlgorithmParameterSpec)null);
//                        SSLKeyDerivation var19 = var10.createKeyDerivation(var3, var18);
//                        SecretKey var20 = var19.deriveKey("TlsKey", (AlgorithmParameterSpec)null);
//                        SecretKey var21 = var19.deriveKey("TlsIv", (AlgorithmParameterSpec)null);
//                        IvParameterSpec var22 = new IvParameterSpec(var21.getEncoded());
//
//                        SSLCipher.SSLWriteCipher var23;
//                        try {
//                            var23 = var3.negotiatedCipherSuite.bulkCipher.createWriteCipher(Authenticator.valueOf(var3.negotiatedProtocol), var3.negotiatedProtocol, var20, var22, var3.sslContext.getSecureRandom());
//                        } catch (GeneralSecurityException var25) {
//                            throw var3.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Missing cipher algorithm", var25);
//                        }
//
//                        if (var23 == null) {
//                            throw var3.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Illegal cipher suite (" + var3.negotiatedCipherSuite + ") and protocol version (" + var3.negotiatedProtocol + ")");
//                        } else {
//                            var3.baseWriteSecret = var18;
//                            var3.conContext.outputRecord.changeWriteCiphers(var23, var4.sessionId.length() != 0);
//                            var3.handshakeKeyDerivation = var11;
//                            return null;
//                        }
//                    }
//                }
//            }
//        }
//
//        private static CipherSuite chooseCipherSuite(ServerHandshakeContext var0, ClientHello.ClientHelloMessage var1) throws IOException {
//            List var2;
//            List var3;
//            if (var0.sslConfig.preferLocalCipherSuites) {
//                var2 = var0.activeCipherSuites;
//                var3 = var1.cipherSuites;
//            } else {
//                var2 = var1.cipherSuites;
//                var3 = var0.activeCipherSuites;
//            }
//
//            CipherSuite var4 = null;
//            AlgorithmConstraints var5 = ServerHandshakeContext.legacyAlgorithmConstraints;
//            Iterator var6 = var2.iterator();
//
//            while(true) {
//                CipherSuite var7;
//                do {
//                    if (!var6.hasNext()) {
//                        if (var4 != null) {
//                            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
//                                SSLLogger.warning("use legacy cipher suite " + var4.name, new Object[0]);
//                            }
//
//                            return var4;
//                        }
//
//                        return null;
//                    }
//
//                    var7 = (CipherSuite)var6.next();
//                } while(!HandshakeContext.isNegotiable(var3, var0.negotiatedProtocol, var7));
//
//                if (var4 != null || var5.permits((Set)null, var7.name, (AlgorithmParameters)null)) {
//                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
//                        SSLLogger.fine("use cipher suite " + var7.name, new Object[0]);
//                    }
//
//                    return var7;
//                }
//
//                var4 = var7;
//            }
//        }
//    }
//}
