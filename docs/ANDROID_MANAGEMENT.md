# Community+ Android management

Fleet Community+ can connect directly to Google's Android Management API instead of relying on Fleet's hosted proxy.

## Required server configuration

Set `FLEET_MDM_ANDROID_GOOGLE_SERVICE_CREDENTIALS` to the complete Google service-account credentials JSON used for Android management.

The Google Cloud project behind those credentials must be able to use the Android Management API and create/manage the Pub/Sub resources used for Android Enterprise notifications, including the topic IAM policy and push subscription.

Fleet also requires:

- a non-empty Fleet server private key;
- a publicly reachable non-localhost Fleet server URL;
- HTTPS for production deployment.

When `FLEET_MDM_ANDROID_GOOGLE_SERVICE_CREDENTIALS` is present, Community+ selects the direct Google client. If it is absent, the existing proxy client remains the fallback for compatibility.

## Enrollment flow

The existing Android service then handles the normal fully managed enrollment flow:

1. Create an Android Enterprise signup URL.
2. Complete the Google enterprise signup callback.
3. Create the enterprise and Pub/Sub notification channel.
4. Create/update the default Android management policy.
5. Generate one-time Android enrollment tokens bound to that policy.
6. Process enrollment/status/command/usage notifications through the Fleet Android endpoints.

The direct-client path uses the same service and datastore flow as the existing Android management implementation; only the Android Management API transport selection changes.
