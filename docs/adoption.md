# Adopting new devices

A device that asks the client for an address and is not in `lan_devices` waits to be adopted. Adopting binds its
MAC address to a tunnel address (fixed, or the next free one) and starts serving it without a restart.

## Policy

Network Scanner tab, "New devices", or Settings, Network access:

| Policy | What happens to a new device |
| --- | --- |
| Admin approval (`ask`) | It waits in the panel until you Adopt or Block it. |
| Automatic (`auto`) | It is adopted at once with the next free address. |
| Closed (`closed`) | It is listed but never adopted. |

Blocked devices are always refused, whatever the policy. Adopt can take a fixed address
(10.77.0.3 to 10.77.0.254, not the client's, not held by another device).

## The server has to learn the address

The server forwards a device's traffic only if its tunnel address is in the server's `lan_tunnel_ips`; it drops
anything else (counted as `WrongSource`). Adopting a device therefore also means adding its address to the server.

Set it up once under "Server sync" (or from the panel): the portal address, the admin password and the SHA-256
fingerprint of the portal certificate. The login is tried before anything is saved. The password is kept in
`server-admin.secret` next to the client config (private file, never returned by the API); the config only holds
`server_admin: { url, secret_file, tls_sha256 }`.

From then on the panel shows which adopted addresses the server is missing and offers:

- **Add to server and restart**: writes the list through the portal, which validates it with the server's own config
  check, and restarts the server so it applies. **Every device loses connectivity for a few seconds.**
- **Add to server, restart later**: writes the list only. It applies at the next server restart.

Automatic policy adopts devices on the client but never restarts the server by itself, because a restart interrupts
everyone; the panel shows the addresses waiting for the next sync. The portal certificate is pinned, plain HTTP is
refused, and `server-sync` is rate-limited.

Limits: the client serves at most the devices its adapters can hold, and the server accepts at most 32 addresses.
