# The Cloudflare API token

CertKeeper proves to Let's Encrypt that you control a name with a DNS-01 challenge: it adds a TXT record
named `_acme-challenge.<name>` in Cloudflare, waits until public DNS shows it, lets Let's Encrypt check it,
and deletes it again. For that it needs a Cloudflare API token.

## What the token needs

| Permission | Why |
|---|---|
| **Zone › Zone › Read** | To list your zones and find the one each name belongs to. **Verify** also uses it to find the account of an account-owned token. |
| **Zone › DNS › Edit** | To create and delete the `_acme-challenge` TXT records. CertKeeper changes no other records. |

Under **Zone Resources**, include the zones you'll issue certificates in: either specific zones, or all
zones in the account. Every name on a certificate must be in a zone the token can edit; for a name in a
zone it can't see, issuing fails with "No Cloudflare zone accessible to this token contains …".

A global API key isn't supported: use a scoped token.

## Creating it

1. In the Cloudflare dashboard, open **My Profile › API Tokens** (for a token owned by you), or
   **Manage Account › Account API Tokens** (for one owned by the account; it keeps working if your user
   leaves the account, which suits a server). Both kinds work.
2. **Create Token**, then **Create Custom Token**.
3. Give it a name, such as `CertKeeper`, and add the two permissions above.
4. Choose the **Zone Resources**.
5. Optional hardening:
   * **Client IP Address Filtering**: allow only the public IP address CertKeeper reaches the internet
     from (for a NAS, your home's public IP). If that address changes, the token stops working.
   * **TTL**: an end date. Once it passes, issuing and renewing fail until you save a new token, and
     the activity log and **Verify** say so.
6. **Continue to summary**, **Create Token**, and copy the token. Cloudflare shows it only once.

## Saving and checking it

In CertKeeper, open **Settings › Cloudflare**, paste the token, choose **Save token**, then **Verify**.
Verify reports whether the token is active and lists the zones it can see. A zone missing from that
list can't be used for certificates.

The token is stored encrypted (in `secrets.enc`; see [the server guide](server.md#secrets)). It's
included in a configuration export only when you give the export a password, and then encrypted with it.

## Network access

Besides `api.cloudflare.com`, CertKeeper needs outbound HTTPS to Let's Encrypt
(`acme-v02.api.letsencrypt.org`, or `acme-staging-v02.api.letsencrypt.org` for staging) and to the public
DNS-over-HTTPS resolvers it checks for the challenge record (`cloudflare-dns.com` and `dns.google`).
Your hosts never need any of these, nor the token.

## Not supported

* Names whose `_acme-challenge` record is delegated to another zone or provider with a CNAME. CertKeeper
  writes the record in the Cloudflare zone of the name itself.
* DNS providers other than Cloudflare.
