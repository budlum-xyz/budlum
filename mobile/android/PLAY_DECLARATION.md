# Google Play `specialUse` declaration (WP-36, directive 7.9.3, risk R-06)

**Draft only. Do not submit this declaration with the current scaffold.**
The mobile-core binding and network duties do not exist in this app yet. The
text below describes the intended implementation, not current behavior. Update
and verify it against the completed app before a Play Console submission.

## Declaration subtype property

The manifest carries:

```xml
<property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE"
          android:value="budlum_storage_validator: keeps peer-to-peer connections open to serve stored data shares and to answer storage audits of the Budlum network"/>
```

and the service is declared with `android:foregroundServiceType="specialUse"`.

## Declaration text for Play Console

> Budlum Validator runs a `specialUse` foreground service so that this phone
> can act as a Budlum storage validator. While the service runs, the app
> keeps peer-to-peer connections open to serve the data shares it stores and
> to answer storage audits issued by the Budlum network, and it shows a
> persistent notification with stored bytes, last audit result and connection
> state. The service is started only from the foreground (the app open). After
> a device reboot the app does not force-restart the service from the
> background; it shows a notification and a 15-minute unmetered WorkManager
> job keeps answering audits in the background. The app requests no battery
> optimization exemption (`REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` is not
> used) and bundles no analytics or tracking SDK.

## Why not `dataSync` / `mediaProcessing`

On Android 15+ those foreground-service types are limited to 6 hours per 24
hours and the system then calls `Service.onTimeout`, which would stop a
long-lived validator service (BLG-265). `specialUse` has no such timeout.

## Review notes

- Distribution: signed, reproducible APK on GitHub Releases; Google Play
  internal testing track first, then open testing (directive 7.9.10).
- If Play review rejects the declaration (R-06), distribution continues via
  the signed APK and F-Droid (WP-58); the declaration text is rewritten and
  resubmitted.
