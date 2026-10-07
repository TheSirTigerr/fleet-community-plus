# Community+ agent controls

Community+ uses Fleet's existing `agent_options` configuration surface for fleetd component updates. The implementation is license-independent and works at global and Fleet scope.

## Update channels

Set `update_channels` to control the TUF channel used by the fleetd components:

```json
{
  "config": {},
  "update_channels": {
    "orbit": "stable",
    "osqueryd": "stable",
    "desktop": "stable"
  }
}
```

Channels are passed to Orbit through `OrbitConfig.UpdateChannels`. Omitting `update_channels` leaves the endpoint's current channels unchanged.

## Controlled rollout

Add `update_rollout` to expose the configured channels to only a deterministic percentage of hosts:

```json
{
  "config": {},
  "update_channels": {
    "orbit": "edge",
    "osqueryd": "stable",
    "desktop": "stable"
  },
  "update_rollout": {
    "percentage": 10,
    "rollout_id": "fleetd-2026-10"
  }
}
```

`percentage` accepts values from 0 through 100. `rollout_id` identifies one rollout wave and must be non-empty. Host assignment is derived from a stable hash of the rollout ID and host ID, so increasing the percentage produces a stable superset instead of reshuffling the Fleet.

Hosts outside the wave receive no update-channel override and keep their current channels. Setting 0 percent pauses a rollout; setting 100 percent exposes the configured channels to the entire scope.

## Script orchestration and retry

Community+ policy automation queues saved scripts through Fleet's normal fleetd script queue. It preserves Fleet scoping, platform checks, pending-execution de-duplication, maintenance-window deferral and the normal result ingestion path.

Failed policy-automation scripts are retried only while the policy is still failing and only up to Fleet's retry cap. These paths are covered by the Community+ CI regression gate.
