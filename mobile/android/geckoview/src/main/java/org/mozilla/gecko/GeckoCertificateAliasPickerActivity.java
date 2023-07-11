package org.mozilla.gecko;

import android.app.Activity;
import android.os.Bundle;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * This activity exists solely to support calling {@link KeyChain#choosePrivateKeyAlias} method.
 * It doesn't have own UI, and {@link #finish()} is called after user has completed
 * picking (or denied to choose) a certificate from the dialog menu.
 */
public class GeckoCertificateAliasPickerActivity extends Activity {
    private final KeyChainAliasCallback callback = this::onKeychainAliasSelected;

    private final AtomicBoolean hasRequestedKeyAlias = new AtomicBoolean(false);

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (savedInstanceState != null) {
            boolean hasRequestedPrivateKeyAlias = savedInstanceState.getBoolean(HAS_REQUESTED_PRIVATE_KEY_ALIAS);
            hasRequestedKeyAlias.set(hasRequestedPrivateKeyAlias);
        }

        if (!hasRequestedKeyAlias.get()) {
            hasRequestedKeyAlias.set(true);
            KeyChain.choosePrivateKeyAlias(this, callback, null, null, null, -1, null);
        }
    }

    @Override
    protected void onSaveInstanceState(@NonNull Bundle outState) {
        super.onSaveInstanceState(outState);
        outState.putBoolean(HAS_REQUESTED_PRIVATE_KEY_ALIAS, hasRequestedKeyAlias.get());
    }


    private void onKeychainAliasSelected(@Nullable String alias) {
        ClientCertificates.onAliasSelected(alias);
        finish();
    }

    private static final String HAS_REQUESTED_PRIVATE_KEY_ALIAS = "hasRequestedPrivateKeyAlias";
}
