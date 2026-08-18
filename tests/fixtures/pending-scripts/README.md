# pending-scripts

An npm project whose lockfile declares packages with `hasInstallScript: true`,
with **no `node_modules/` on disk**.

That combination is the point of the fixture: `scripts` must list the packages
that will execute code at install time from the lockfile alone, and must say
that it has not read what those scripts actually do — an unread script is
reported as unread, never as harmless.

These two tests previously ran against a real checkout outside the repository,
which is gitignored: they passed locally and failed on every clean checkout.
