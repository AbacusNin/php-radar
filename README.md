# php-radar

php-radar finds PHP you did not know you were running and tells you which installs are
exposed to PHP2Shell (CVE-2026-109618 and CVE-2026-109619), two remote code execution bugs
in the PHP runtime. It reads versions and configuration to work out each build, then checks
the build against the releases that carry the fix. It never sends anything meant to trigger
the bug, so it cannot crash a target.

Point it at a repository, a GitHub organization, an AWS account, a range of addresses, or a
single machine. Every find gets a verdict and a confidence, and the exit code tells a script
whether anything is exposed.

## Install

Python 3.9 or later. The core uses only the standard library.

```
pip install git+https://github.com/AbacusNin/php-radar.git
```

For the AWS source, add the aws extra:

```
pip install "php-radar[aws] @ git+https://github.com/AbacusNin/php-radar.git"
```

From a clone, `pip install .` (or `pip install ".[aws]"`) does the same, and
`python -m php_radar` runs it without installing.

## Usage

```
php-radar repo PATH                 # a checkout on disk
php-radar repo --github-org NAME    # every repo in a GitHub org
php-radar host                      # this machine
php-radar host --ssh USER@HOST      # a machine over ssh
php-radar cloud --provider aws      # an AWS account
php-radar network --scope FILE      # addresses you are cleared to probe
```

Add `--format json` or `--format sarif` for machine-readable output (the default is a
console table), and `--output FILE` to write the report to a file.

## Verdicts and exit codes

Each asset grades EXPOSED, LIKELY_PATCHED, INDETERMINATE (PHP is there but the build cannot
be placed), or NOT_PHP, with a confidence that follows how directly the read saw the build. A
host read is the firmest. A network read is only ever a lead.

The run exits 0 when nothing is exposed and the scan was complete, 1 when an asset is
EXPOSED, 2 on a usage or scope error, and 3 when nothing is exposed but a read was skipped.

## Worth knowing

- **It detects, it does not exploit.** The repo, host, and cloud reads look at files, command
  output, and API answers. A network scan sends one plain GET per target and reads the reply.
  No code path triggers the bug.
- **A version can lie.** A distribution can patch PHP and keep the old version number, so
  packaged builds are checked against a small data file of known-fixed builds. A build that
  is not listed grades INDETERMINATE instead of a guess.
- **Outside reads are leads.** A banner can be hidden or forged, so a network read always
  grades low and wants a host read to confirm it.
- **The scope is the authorization boundary.** php-radar reads what you name and nothing else.
  A network sweep refuses public ranges unless you pass `--allow-public`, rate-limits itself,
  and prints an authorization notice before it runs. Whether you may scan is on you.
- **A patched build still carries application risk.** The fix closes the runtime bug. An
  application's own flaws, such as a file-inclusion sink, are a separate question.

## License

Apache-2.0. See LICENSE and NOTICE.
