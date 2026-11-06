# Private names for a small group

Free names like `alice.internal` that work only for people in your group.
No registrar, no fees, no payment. They do NOT work on the public internet.

## How it works
- This server is a DNS-over-HTTPS resolver. Names ending in `.internal` are answered from your own list.
- Every other website name is passed to a normal public resolver (Cloudflare by default), so normal browsing keeps working.
- Each person sets their browser to use your resolver link once. Then their browser can open the private names.
- Members claim a name with an invite code you give out, and point it at an IP address (A or AAAA record) or save a text note (TXT).
- Why `.internal`: ICANN reserved it for private use, so it will never become a real public extension. You can change it with `PRIVATE_TLD`.

## Set up (free)
1. **Upstash:** free Redis database. Copy `UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN`.
2. **GitHub:** new repository (private is fine), upload `server.js`, `ui.html`, `package.json`.
3. **Render:** New > Web Service > that repository. Node, build `npm install`, start `npm start`.
4. Environment settings:
   - `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN`
   - `ADMIN_KEY`: a long password you make up
   - `DOH_SECRET`: a long random string. It becomes part of the resolver link, so only your group can use your server.
   - `KEEP_AWAKE`: set to `1` so the free server never sleeps (see limits below)
   - Optional: `PRIVATE_TLD` (default `internal`), `UPSTREAM_DOH` (default Cloudflare)
5. Make invite codes: `https://YOURAPP.onrender.com/api/admin/invite?code=FRIENDS&uses=10&key=YOUR_ADMIN_KEY`
   Each use lets one person claim one name.
6. Other admin links: `/api/admin/names?key=...` lists names. `/api/admin/delete?name=alice&key=...` removes one.

## For each person in the group
1. Open your page, claim a name with an invite code, and save the key.
2. Copy the resolver link (shown after claiming or adding a name).
3. Firefox: Settings > Privacy & Security > DNS over HTTPS > Increased Protection > Custom > paste the link.
   Chrome or Edge: Settings > Privacy and security > Security > Use secure DNS > Custom > paste the link.
4. Visit `http://yourname.internal` (type the `http://`).

## Honest limits
- It only works in browsers set up with your link. Phones' system-wide settings, other apps, and anyone outside the group will not see these names.
- Pages open over plain `http`, with no padlock. Nobody issues certificates for private names.
- The name points to an IP address. The server at that address must be set up to answer for `yourname.internal`. It works for things like a Raspberry Pi or computer at home, a LAN device, or a VPS you control. It does not point to Netlify, GitHub Pages or Vercel sites, because those serve by their own domain names.
- Everyone's DNS lookups go through your server while they use it. Only invite people you trust. Use `DOH_SECRET` and keep the link private. Anyone with the link can use your resolver.
- Render's free servers sleep when idle, and a sleeping server can't answer DNS for about a minute, which makes browsing feel broken. Set `KEEP_AWAKE` to `1` in Render's settings and the server visits itself every 10 minutes, so you don't have to do anything. It then stays awake all month, which uses nearly all of Render's free monthly hours (check Render's current number). Those hours are shared by every free service in the same Render workspace, so don't run other free services there, or it may run out and shut down for the rest of the month. A paid always-on instance avoids that.
- Keys are random secrets. Anyone with a key can change that name's records. There is no key recovery.
- Tested locally with real DNS packets (A, AAAA, TXT, unknown names, pass-through to a stand-in upstream). I haven't tested on Render or in a real browser, so try one name end to end before inviting people.
