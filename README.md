### twitter-guest-account: Get guest accounts for nitter
#### Yawning Angel <yawning at schwanenlied dot me>

WARNING:
- This currently requires using a nitter feature-branch.
- No, I will not answer questions about how to get this to work.

The most recent way to unbreak nitter is to use guest accounts a la the
the Android app onboarding workflow.  There is a node.js script buried
in the issue tracker to accomplish this, but I wanted something standalone.

This could have proxy support but, everyone rushing to do this has resulted
in all the public proxies being rate limited.  As far as I can tell, it
is possible to get at least one account per day per IP, but a VPS that
should never have been used for this before was already rate-limited,
so your milage may vary.

See:
- https://github.com/zedeus/nitter/issues/983
- https://github.com/zedeus/nitter/pull/985