/* -*- Mode: indent-tabs-mode: nil; js-indent-level: 2 -*- */
/* vim: set sts=2 sw=2 et tw=80: */
"use strict";

const { AddonManager } = ChromeUtils.importESModule(
  "resource://gre/modules/AddonManager.sys.mjs"
);
const { Preferences } = ChromeUtils.importESModule(
  "resource://gre/modules/Preferences.sys.mjs"
);

const {
  createAppInfo,
  createTempWebExtensionFile,
  promiseAddonEvent,
  promiseCompleteAllInstalls,
  promiseFindAddonUpdates,
  promiseRestartManager,
  promiseShutdownManager,
  promiseStartupManager,
} = AddonTestUtils;

AddonTestUtils.init(this);

// Allow for unsigned addons.
AddonTestUtils.overrideCertDB();

createAppInfo("xpcshell@tests.mozilla.org", "XPCShell", "42", "42");

function background() {
  let onInstalledDetails = null;
  let onStartupFired = false;
  let eventPage = browser.runtime.getManifest().background.persistent === false;

  browser.runtime.onInstalled.addListener(details => {
    onInstalledDetails = details;
  });

  browser.runtime.onStartup.addListener(() => {
    onStartupFired = true;
  });

  browser.test.onMessage.addListener(message => {
    if (message === "get-on-installed-details") {
      onInstalledDetails = onInstalledDetails || { fired: false };
      browser.test.sendMessage("on-installed-details", onInstalledDetails);
    } else if (message === "did-on-startup-fire") {
      browser.test.sendMessage("on-startup-fired", onStartupFired);
    } else if (message === "reload-extension") {
      browser.runtime.reload();
    }
  });

  browser.runtime.onUpdateAvailable.addListener(() => {
    browser.test.sendMessage("reloading");
    browser.runtime.reload();
  });

  if (eventPage) {
    browser.runtime.onSuspend.addListener(() => {
      browser.test.sendMessage("suspended");
    });
    // an event we use to restart the background
    browser.browserSettings.homepageOverride.onChange.addListener(() => {
      browser.test.sendMessage("homepageOverride");
    });
  }
}

async function expectEvents(
  extension,
  {
    onStartupFired,
    onInstalledFired,
    onInstalledReason,
    onInstalledTemporary,
    onInstalledPrevious,
  }
) {
  extension.sendMessage("get-on-installed-details");
  let details = await extension.awaitMessage("on-installed-details");
  if (onInstalledFired) {
    equal(
      details.reason,
      onInstalledReason,
      "runtime.onInstalled fired with the correct reason"
    );
    equal(
      details.temporary,
      onInstalledTemporary,
      "runtime.onInstalled fired with the correct temporary flag"
    );
    if (onInstalledPrevious) {
      equal(
        details.previousVersion,
        onInstalledPrevious,
        "runtime.onInstalled after update with correct previousVersion"
      );
    }
  } else {
    equal(
      details.fired,
      onInstalledFired,
      "runtime.onInstalled should not have fired"
    );
  }

  extension.sendMessage("did-on-startup-fire");
  let fired = await extension.awaitMessage("on-startup-fired");
  equal(
    fired,
    onStartupFired,
    `Expected runtime.onStartup to ${onStartupFired ? "" : "not "} fire`
  );
}

add_task(async function test_should_fire_on_addon_update() {
  Preferences.set("extensions.logging.enabled", false);

  await promiseStartupManager();

  const EXTENSION_ID =
    "test_runtime_on_installed_addon_update@tests.mozilla.org";

  const PREF_EM_CHECK_UPDATE_SECURITY = "extensions.checkUpdateSecurity";

  // The test extension uses an insecure update url.
  Services.prefs.setBoolPref(PREF_EM_CHECK_UPDATE_SECURITY, false);

  const testServer = createHttpServer();
  const port = testServer.identity.primaryPort;

  let extension = ExtensionTestUtils.loadExtension({
    useAddonManager: "permanent",
    manifest: {
      version: "1.0",
      browser_specific_settings: {
        gecko: {
          id: EXTENSION_ID,
          update_url: `http://localhost:${port}/test_update.json`,
        },
      },
    },
    background,
  });

  testServer.registerPathHandler("/test_update.json", (request, response) => {
    response.write(`{
      "addons": {
        "${EXTENSION_ID}": {
          "updates": [
            {
              "version": "2.0",
              "update_link": "http://localhost:${port}/addons/test_runtime_on_installed-2.0.xpi"
            }
          ]
        }
      }
    }`);
  });

  let webExtensionFile = createTempWebExtensionFile({
    manifest: {
      version: "2.0",
      browser_specific_settings: {
        gecko: {
          id: EXTENSION_ID,
        },
      },
    },
    background,
  });

  testServer.registerFile(
    "/addons/test_runtime_on_installed-2.0.xpi",
    webExtensionFile
  );

  await extension.startup();

  await expectEvents(extension, {
    onStartupFired: false,
    onInstalledFired: true,
    onInstalledTemporary: false,
    onInstalledReason: "install",
  });

  let addon = await AddonManager.getAddonByID(EXTENSION_ID);
  equal(addon.version, "1.0", "The installed addon has the correct version");

  let update = await promiseFindAddonUpdates(addon);
  let install = update.updateAvailable;

  let promiseInstalled = promiseAddonEvent("onInstalled");
  await promiseCompleteAllInstalls([install]);

  await extension.awaitMessage("reloading");

  let [updated_addon] = await promiseInstalled;
  equal(
    updated_addon.version,
    "2.0",
    "The updated addon has the correct version"
  );

  await extension.awaitStartup();

  await expectEvents(extension, {
    onStartupFired: false,
    onInstalledFired: true,
    onInstalledTemporary: false,
    onInstalledReason: "update",
    onInstalledPrevious: "1.0",
  });

  await extension.unload();

  await promiseShutdownManager();
});

add_task(async function test_should_fire_on_browser_update() {
  const EXTENSION_ID =
    "test_runtime_on_installed_browser_update@tests.mozilla.org";

  await promiseStartupManager("1");

  let extension = ExtensionTestUtils.loadExtension({
    useAddonManager: "permanent",
    manifest: {
      version: "1.0",
      browser_specific_settings: {
        gecko: {
          id: EXTENSION_ID,
        },
      },
    },
    background,
  });

  await extension.startup();

  await expectEvents(extension, {
    onStartupFired: false,
    onInstalledFired: true,
    onInstalledTemporary: false,
    onInstalledReason: "install",
  });

  // Restart the browser.
  await promiseRestartManager("1");
  await extension.awaitBackgroundStarted();

  await expectEvents(extension, {
    onStartupFired: true,
    onInstalledFired: false,
  });

  // Update the browser.
  await promiseRestartManager("2");
  await extension.awaitBackgroundStarted();

  await expectEvents(extension, {
    onStartupFired: true,
    onInstalledFired: true,
    onInstalledTemporary: false,
    onInstalledReason: "browser_update",
  });

  // Restart the browser.
  await promiseRestartManager("2");
  await extension.awaitBackgroundStarted();

  await expectEvents(extension, {
    onStartupFired: true,
    onInstalledFired: false,
  });

  // Update the browser again.
  await promiseRestartManager("3");
  await extension.awaitBackgroundStarted();

  await expectEvents(extension, {
    onStartupFired: true,
    onInstalledFired: true,
    onInstalledTemporary: false,
    onInstalledReason: "browser_update",
  });

  await extension.unload();

  await promiseShutdownManager();
});

add_task(async function test_should_not_fire_on_reload() {
  const EXTENSION_ID = "test_runtime_on_installed_reload@tests.mozilla.org";

  await promiseStartupManager();

  let extension = ExtensionTestUtils.loadExtension({
    useAddonManager: "permanent",
    manifest: {
      version: "1.0",
      browser_specific_settings: {
        gecko: {
          id: EXTENSION_ID,
        },
      },
    },
    background,
  });

  await extension.startup();

  await expectEvents(extension, {
    onStartupFired: false,
    onInstalledFired: true,
    onInstalledTemporary: false,
    onInstalledReason: "install",
  });

  extension.sendMessage("reload-extension");
  extension.setRestarting();
  await extension.awaitStartup();

  await expectEvents(extension, {
    onStartupFired: false,
    onInstalledFired: false,
  });

  await extension.unload();
  await promiseShutdownManager();
});

add_task(async function test_should_not_fire_on_restart() {
  const EXTENSION_ID = "test_runtime_on_installed_restart@tests.mozilla.org";

  await promiseStartupManager();

  let extension = ExtensionTestUtils.loadExtension({
    useAddonManager: "permanent",
    manifest: {
      version: "1.0",
      browser_specific_settings: {
        gecko: {
          id: EXTENSION_ID,
        },
      },
    },
    background,
  });

  await extension.startup();

  await expectEvents(extension, {
    onStartupFired: false,
    onInstalledFired: true,
    onInstalledTemporary: false,
    onInstalledReason: "install",
  });

  let addon = await AddonManager.getAddonByID(EXTENSION_ID);
  await addon.disable();
  await addon.enable();
  await extension.awaitStartup();

  await expectEvents(extension, {
    onStartupFired: false,
    onInstalledFired: false,
  });

  await extension.unload();
  await promiseShutdownManager();
});

add_task(async function test_temporary_installation() {
  const EXTENSION_ID =
    "test_runtime_on_installed_addon_temporary@tests.mozilla.org";

  await promiseStartupManager();

  let extension = ExtensionTestUtils.loadExtension({
    useAddonManager: "temporary",
    manifest: {
      version: "1.0",
      browser_specific_settings: {
        gecko: {
          id: EXTENSION_ID,
        },
      },
    },
    background,
  });

  await extension.startup();

  await expectEvents(extension, {
    onStartupFired: false,
    onInstalledFired: true,
    onInstalledReason: "install",
    onInstalledTemporary: true,
  });

  await extension.unload();
  await promiseShutdownManager();
});

add_task(
  {
    pref_set: [["extensions.eventPages.enabled", true]],
  },
  async function test_runtime_eventpage() {
    const EXTENSION_ID = "test_runtime_eventpage@tests.mozilla.org";

    await promiseStartupManager("1");

    let extension = ExtensionTestUtils.loadExtension({
      useAddonManager: "permanent",
      manifest: {
        version: "1.0",
        browser_specific_settings: {
          gecko: {
            id: EXTENSION_ID,
          },
        },
        permissions: ["browserSettings"],
        background: {
          persistent: false,
        },
      },
      background,
    });

    await extension.startup();

    await expectEvents(extension, {
      onStartupFired: false,
      onInstalledFired: true,
      onInstalledReason: "install",
      onInstalledTemporary: false,
    });

    info(`test onInstall does not fire after suspend`);
    // we do enough here that idle timeout causes intermittent failure.
    // using terminateBackground results in the same code path tested.
    extension.terminateBackground();
    await extension.awaitMessage("suspended");
    await promiseExtensionEvent(extension, "shutdown-background-script");

    Services.prefs.setStringPref(
      "browser.startup.homepage",
      "http://test.example.com"
    );
    await extension.awaitMessage("homepageOverride");
    // onStartup remains persisted, but not primed
    assertPersistentListeners(extension, "runtime", "onStartup", {
      primed: false,
      persisted: true,
    });

    await expectEvents(extension, {
      onStartupFired: false,
      onInstalledFired: false,
    });

    info("test onStartup is not primed but background starts automatically");
    await promiseRestartManager();
    // onStartup is a bit special.  During APP_STARTUP we do not
    // prime this, we just start since it needs to.
    assertPersistentListeners(extension, "runtime", "onStartup", {
      primed: false,
      persisted: true,
    });
    await extension.awaitBackgroundStarted();

    info("test expectEvents");
    await expectEvents(extension, {
      onStartupFired: true,
      onInstalledFired: false,
    });

    info("test onInstalled fired during browser update");
    await promiseRestartManager("2");
    assertPersistentListeners(extension, "runtime", "onStartup", {
      primed: false,
      persisted: true,
    });
    await extension.awaitBackgroundStarted();

    await expectEvents(extension, {
      onStartupFired: true,
      onInstalledFired: true,
      onInstalledReason: "browser_update",
      onInstalledTemporary: false,
    });

    info(`test onStarted does not fire after suspend`);
    extension.terminateBackground();
    await extension.awaitMessage("suspended");
    await promiseExtensionEvent(extension, "shutdown-background-script");

    Services.prefs.setStringPref(
      "browser.startup.homepage",
      "http://homepage.example.com"
    );
    await extension.awaitMessage("homepageOverride");
    // onStartup remains persisted, but not primed
    assertPersistentListeners(extension, "runtime", "onStartup", {
      primed: false,
      persisted: true,
    });

    await expectEvents(extension, {
      onStartupFired: false,
      onInstalledFired: false,
    });

    await extension.unload();
    await promiseShutdownManager();
  }
);

// Verify we don't regress the issue related to runtime.onStartup persistent
// listener being cleared from the startup data as part of priming all listeners
// while terminating the event page on idle timeout (Bug 1796586).
add_task(
  {
    pref_set: [["extensions.eventPages.enabled", true]],
  },
  async function test_runtime_onStartup_eventpage() {
    const EXTENSION_ID = "test_eventpage_onStartup@tests.mozilla.org";

    await promiseStartupManager();

    let extension = ExtensionTestUtils.loadExtension({
      useAddonManager: "permanent",
      manifest: {
        version: "1.0",
        browser_specific_settings: {
          gecko: {
            id: EXTENSION_ID,
          },
        },
        permissions: ["browserSettings"],
        background: {
          persistent: false,
        },
      },
      background,
    });

    await extension.startup();

    await expectEvents(extension, {
      onStartupFired: false,
      onInstalledFired: true,
      onInstalledReason: "install",
      onInstalledTemporary: false,
    });

    info("Simulated idle timeout");
    extension.terminateBackground();
    await extension.awaitMessage("suspended");
    await promiseExtensionEvent(extension, "shutdown-background-script");

    // onStartup remains persisted, but not primed
    assertPersistentListeners(extension, "runtime", "onStartup", {
      primed: false,
      persisted: true,
    });

    info(`test onStartup after restart`);
    await promiseRestartManager();

    // onStartup is a bit special.  During APP_STARTUP we do not
    // prime this, we just start since it needs to.
    assertPersistentListeners(extension, "runtime", "onStartup", {
      primed: false,
      persisted: true,
    });
    await extension.awaitBackgroundStarted();

    info("test expectEvents");
    await expectEvents(extension, {
      onStartupFired: true,
      onInstalledFired: false,
    });

    extension.terminateBackground();
    await extension.awaitMessage("suspended");
    await promiseExtensionEvent(extension, "shutdown-background-script");
    assertPersistentListeners(extension, "runtime", "onStartup", {
      primed: false,
      persisted: true,
    });

    await extension.unload();
    await promiseShutdownManager();
  }
);
