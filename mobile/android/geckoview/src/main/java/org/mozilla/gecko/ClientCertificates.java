package org.mozilla.gecko;

import static android.content.Intent.FLAG_ACTIVITY_NEW_TASK;
import android.content.Intent;
import android.security.KeyChain;
import android.security.KeyChainException;
import android.util.Log;
import android.util.Pair;
import androidx.annotation.MainThread;
import androidx.annotation.Nullable;
import androidx.annotation.WorkerThread;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.mozilla.gecko.annotation.WrapForJNI;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

public class ClientCertificates {
    private static final String LOG_TAG = "ClientCertificates";
    private static final Object lock = new Object();

    private static String alias = "";

    @WrapForJNI
    private static Pair<X509Certificate[], PrivateKey[]> getCertificatesWithPrivateKeys() throws InterruptedException {
        synchronized (lock) {
            alias = "";
            Intent intent = new Intent(GeckoAppShell.getApplicationContext(), GeckoCertificateAliasPickerActivity.class);
            intent.addFlags(FLAG_ACTIVITY_NEW_TASK);
            GeckoAppShell.getApplicationContext().startActivity(intent);
            lock.wait();
        }
        return getCertificatesWithPrivateKeysByAlias(alias);
    }

    private static Pair<X509Certificate[], PrivateKey[]> getCertificatesWithPrivateKeysByAlias(String alias) {
        ArrayList<X509Certificate> x509CertificateArrayList = new ArrayList<>();
        ArrayList<PrivateKey> privateKeyArrayList = new ArrayList<>();

        if (alias == null) {
            X509Certificate[] emptyCertsArray = {};
            PrivateKey[] emptyKeysArray = {};
            return new Pair<>(emptyCertsArray, emptyKeysArray);
        }
        try {
            X509Certificate[] chain = KeyChain.getCertificateChain(GeckoAppShell.getApplicationContext(), alias);
            x509CertificateArrayList.addAll(Arrays.asList(chain));
            PrivateKey pk = KeyChain.getPrivateKey(GeckoAppShell.getApplicationContext(), alias);
            privateKeyArrayList.add(pk);
        } catch (KeyChainException | InterruptedException e) {
            Log.e(LOG_TAG, "Could not retrieve certificate chain: " + e);
        }
        X509Certificate[] certificates = new X509Certificate[x509CertificateArrayList.size()];
        PrivateKey[] keys = new PrivateKey[privateKeyArrayList.size()];

        certificates = x509CertificateArrayList.toArray(certificates);
        keys = privateKeyArrayList.toArray(keys);
        return new Pair<>(certificates, keys);
    }

    @WorkerThread
    /* package-private */
    static void onAliasSelected(@Nullable String alias) {
        synchronized (lock) {
            ClientCertificates.alias = alias;
            lock.notify();
        }
    }

    @MainThread
    private static native void nativeInitialize(ClassLoader classLoader);

    @MainThread
    public static void initialize() {
        // A ClassLoader obtained from Android's main thread is required
        // for non-system Java classes resolution in native threads
        ClassLoader loader = ClientCertificates.class.getClassLoader();
        nativeInitialize(loader);
    }

    @WorkerThread
    private static byte[] sign(byte[] bytes, PrivateKey privateKey, String algorithm) {
        return encryptWithPrivateKey(bytes, privateKey, algorithm);
    }
    
    // Used to encrypt data using RSA algorithm
    private static byte[] encryptWithPrivateKey(
            byte[] bytes,
            PrivateKey privateKey, String algorithm) {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            Log.e(LOG_TAG, "Cipher " + algorithm + " not supported: " + e);
            return null;
        }
        try {
            DigestAlgorithmIdentifierFinder hashAlgorithmFinder = new DefaultDigestAlgorithmIdentifierFinder();
            // Find the algorithm provided by the SignParams in the native library
            AlgorithmIdentifier hashingAlgorithmIdentifier = hashAlgorithmFinder.find(algorithm);
            // Decode the DigestInfo from byte array
            DigestInfo digestInfo = new DigestInfo(hashingAlgorithmIdentifier, bytes);
            // Get the digest from DigestInfo
            byte[] hashToEncrypt = digestInfo.getDigest();

            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            return cipher.doFinal(hashToEncrypt);
        } catch (Exception e) {
            Log.e(LOG_TAG,
                    "Exception while encrypting input with " + algorithm + " and "
                            + privateKey.getAlgorithm() + " private key ("
                            + privateKey.getClass().getName() + "): " + e);
            return null;
        }
    }

    // Used to sign data using RSA-PSS algorithm
    private static byte[] signWithPrivateKey(byte[] bytes,
                                             PrivateKey privateKey, String algorithm) {
        Signature signature;
        try {
            signature = Signature.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            Log.e(LOG_TAG, "Signature algorithm " + algorithm + " not supported: " + e);
            return null;
        }
        try {
            signature.initSign(privateKey);
            signature.update(bytes);
            return signature.sign();
        } catch (Exception e) {
            Log.e(LOG_TAG,
                    "Exception while signing message with " + algorithm + " and "
                            + privateKey.getAlgorithm() + " private key ("
                            + privateKey.getClass().getName() + "): " + e);
            return null;
        }
    }
}
