# php-radar

php-radar finds PHP you did not know you were running and tells you which installs are
exposed to PHP2Shell, the name for CVE-2026-109618 and CVE-2026-109619. Those are two
remote code execution bugs in the PHP runtime itself, so updating WordPress or Laravel does
nothing for them. Finding the PHP is the hard part. It hides in container base images,
hosting panels, appliances, and vendor software.

Point it at a repository, a GitHub organization, an AWS account, a range of addresses, or a
single machine. It reads what that place says about its PHP, works out the build, and checks
the build against the releases that carry the fix. Every find gets a verdict (EXPOSED,
INDETERMINATE, LIKELY_PATCHED, or NOT_PHP) and a confidence, and the exit code says whether
anything is exposed.

Upstream fixed both bugs on 2026-10-21 in PHP 8.5.12, 8.4.27, 8.3.36, and 8.2.35. PHP 8.1
and older are end of life with no fixed release, so a build on those branches grades
EXPOSED. A distribution package gets different treatment. A distribution can patch PHP and
keep the old version number, so php-radar checks packaged builds against its data file, a
JSON list of patched builds that the section on the PHP2Shell data describes.

## What it looks at

A run has one scope: a repository (a checkout on disk or a GitHub organization), a cloud
account (AWS for now), or a network perimeter. A network scope is a file listing the
addresses, ranges, and hostnames to probe. A fourth command reads one machine directly,
either this one or one you reach over ssh. That read is the firmest php-radar can give,
because it sees the installed packages.

The scope is also the authorization boundary. php-radar reads what you named and nothing
else. It adds no targets of its own, follows no link to a new one, and does not widen a
range. Whether you may scan the scope is your responsibility. The section on network sweeps
says what I expect you to have settled first.

## What it sends

php-radar detects. It identifies the PHP build and compares it with the fixed releases.
Nothing it sends is meant to trigger the bug. An exploit check has to trigger a memory bug in
the target's PHP, and that can crash the process. Such a check is a denial-of-service tool,
and php-radar has no code path for one.

The repo, host, and cloud commands read files, command output, and API answers. The network
command sends one plain GET for / to each target, with four headers: `Host`, which HTTP
requires, plus `Accept-Encoding: identity`, `Accept: */*`, and `User-Agent: php-radar`. The
User-Agent lets whoever reads the logs on the other side tell a scan from an attack. The
request has no body, query string, cookie, or credential. php-radar reads the headers of the
reply and, over HTTPS, the names in the certificate. It never follows a redirect.

## Install

php-radar needs Python 3.9 or later, and the core uses only the standard library.

```
pip install php-radar
```

The AWS source needs boto3, which the aws extra installs.

```
pip install "php-radar[aws]"
```

To install from a checkout instead, run pip in the repository root.

```
pip install .
pip install ".[aws]"
```

The second line includes the AWS source. You can also skip the install and run
`python -m php_radar` from the repository root.

## Usage

```
php-radar repo PATH
php-radar repo --github-org NAME
php-radar network --scope FILE
php-radar host
php-radar host --ssh [USER@]HOST
php-radar cloud --provider aws
```

Every command takes `--format`, which is `console` (the default), `json`, or `sarif`. It
also takes `--output FILE` to write the report to a file instead of stdout. The file is UTF-8
with Unix line endings on every platform. With json or sarif, stdout carries one document,
and the notes about how far the run reached go to stderr. php-radar checks that it can write
the `--output` file before it scans, because a long sweep is a bad time to find a typo or a
locked file.

`repo` reads the files that pin or declare a PHP version: Dockerfiles, Compose files, the
setup-php step in GitHub Actions workflows, .php-version and .tool-versions files,
composer.json, and devcontainer.json. It reads them as text and runs nothing from the tree.
It skips .git, node_modules, and vendor, and it follows no symbolic links. An image tag with
a full version, such as `php:8.3.35-fpm`, is a firm pin. A floating tag such as
`php:8.3-apache` pins no patch release. A composer.json requirement only sets a minimum.
Neither says which build runs, so both grade INDETERMINATE: PHP is there, but the build
cannot be placed.

With `--github-org`, `repo` runs the same reading against the default branch of every
repository in the organization, through the GitHub API. Set `GITHUB_TOKEN` to include private
repositories. Without it the scan is anonymous, sees public repositories only, and gets
GitHub's 60 requests an hour. The token goes to api.github.com and nowhere else.

`host` with no flag reads the machine it runs on. With `--ssh` it reads the machine you name
through your system ssh client, in batch mode. Agent, X11, and port forwarding stay off,
because the machine at the other end may be the one you are worried about. Your ssh config
still supplies the keys, ports, and host key checking. Either way it runs `php -v` and
`php -i`, reads /etc/os-release, and asks the package manager (`dpkg-query` or `rpm`) which
PHP packages are installed.

php-radar finds the installed package that matches the running version and grades its build
string. From `php -i` it keeps the version, the server API, and a few settings shown for
context, and drops the rest. The Environment section alone prints the process environment,
which can hold credentials.

`cloud --provider aws` lists the Elastic Beanstalk environments, Lambda functions, and ECR
image tags that name PHP, with four read-only calls. The IAM actions for them are
`elasticbeanstalk:DescribeEnvironments`, `lambda:ListFunctions`,
`ecr:DescribeRepositories`, and `ecr:ListImages`, and php-radar needs no other permission.
Credentials come from the standard AWS chain. No flag takes one. It reads one region by
default, the session's own. `--region` picks others when you repeat it, and the report ends
with a note naming the regions it read, because a clean result covers only those.

`network` takes a scope file and sends one request per target. It has its own section below.

## Reading the results

Here is the console report for a checkout with three pins. The root Dockerfile uses
`php:8.3.35-fpm`, api/Dockerfile uses `php:8.3.36-apache`, and worker/docker-compose.yml
floats on `php:8.3-apache`.

```
php-radar: 1 asset (EXPOSED 1, INDETERMINATE 0, LIKELY_PATCHED 0, NOT_PHP 0)

EXPOSED (1)
  shop~20c3d9ad (repo): HIGH confidence, PHP 8.3.35, FPM
    REPO     EXPOSED         HIGH    Dockerfile  PHP 8.3.35
    REPO     LIKELY_PATCHED  HIGH    api/Dockerfile  PHP 8.3.36
    REPO     INDETERMINATE   LOW     worker/docker-compose.yml  (8.3-apache pins no patch release)
```

An asset is one repository, host, or cloud resource, and it takes the worst verdict among its
reads. Each read keeps its own line underneath, so you can see which pin or banner decided
it. The checkout is named for its folder plus a short hash of its path, which keeps two
checkouts with the same folder name distinct. FPM is the server API, the way PHP is wired
into the web server, read here from the image tag. Groups print worst first.

- `EXPOSED`: the build is older than the first fixed release of its branch, or it sits on an
  end-of-life branch with no fixed release.
- `INDETERMINATE`: PHP is present, or may be, and php-radar cannot place the build. The usual
  causes are a floating tag, a banner that names PHP and hides the version, a distribution
  build missing from the data file, or a read that failed.
- `LIKELY_PATCHED`: the build is at or past the fix, or it matches a distribution build that
  the data file lists as patched. The word likely is there because only a read on the host
  itself is firm.
- `NOT_PHP`: a host read found no PHP. No other source can say this.

Confidence says how directly the read saw the build. A host read or a cloud record that
places the build grades HIGH. A repository pin grades by how exact it is, from HIGH for an
image tag with a full version down to LOW for a floating tag. A network read always grades
LOW, for the reasons under Limits.

The json format is a summary plus one entry per asset, with every read and its own grade.
The sarif format is SARIF 2.1.0 with one result per asset: EXPOSED is an error,
INDETERMINATE a warning, and the other two are results marked as a pass or as not
applicable. A repository result points at the file, and the others name the resource.

## Exit codes

- 0: no asset graded EXPOSED and no read was skipped.
- 1: at least one asset graded EXPOSED. This wins over every other outcome.
- 2: a usage or scope error, such as an unknown flag, a scope file that will not parse, or a
  public address without `--allow-public`.
- 3: no asset graded EXPOSED, but a read was skipped, so the scan is incomplete. That covers
  a file it could not read, a failed GitHub or AWS call, and a host it could not inspect or
  reach. The notes at the end of the report give the reasons.
- 4: an unexpected error inside php-radar, with the traceback on stderr. Python exits 1 for an
  uncaught error, which a CI job would read as an exposed asset, so php-radar catches it and
  exits 4.
- 130: the run was stopped with Ctrl-C.

Exit 3 keeps a scan that never ran from passing as clean in a CI job that reads only the exit
code. Exit 0 says a complete scan found nothing exposed. Assets that grade INDETERMINATE,
such as a floating image tag, exit 0 too, so when they matter, read the INDETERMINATE group
or the per-verdict counts in the JSON summary. A job that must not miss a blind spot can fail
on any nonzero status. One that only cares about exposure can fail on 1, though a 2 or a 4
means the scan did not run.

A network sweep exits 0 or 1, or 2 when it refuses to start. It never exits 3, because a
target that does not answer is a finished check. Most addresses in a range have no listener,
and counting each as a skipped read would make nearly every sweep exit 3. So an exit 0 can
mean the sweep reached nothing. Read the count that ends the report:

```
php-radar network: probed 508 targets, reported 497 of them, left out 11 that answered with no sign of PHP.
```

Of the 508 targets probed, 497 are in the report, each because it showed PHP or gave no
usable answer, and its row says which. The other 11 answered with no sign of PHP. A sweep
that reached nothing reports every target and leaves none out.

## Scanning a network

Run a sweep only against systems you own or have written permission to assess, and list them
in a scope file. php-radar looks for PHP in the Server and X-Powered-By headers, a PHPSESSID
cookie, a PHP content type, or a redirect to a .php file.

A host that answers with no sign of PHP is left out of the report. A server that hides its
banner looks the same as one that runs no PHP, so a clean sweep shows only that nothing
announced itself. A host that gives no answer keeps a row that says so. So does one that
answers with a server error, or with a 401, 403, or 429 and no sign of PHP. Those answers say
nothing about the site behind them.

A scope file has one entry per line: an IPv4 address, an IPv4 range in CIDR form, or a
hostname, each with an optional port. A # starts a comment.

```
# the office network
10.20.0.0/24
10.20.5.17:8080
# a hostname needs --allow-public
intranet.corp.example
```

A line with no port is probed on 80 and 443. Ports 443 and 8443 speak TLS. Every other port
gets plain HTTP. A range must be written on its network address. 10.0.0.5/24 is an error,
because php-radar will not widen it to hosts you did not list. One bad line stops the run and
names the line. An empty file is an error too, because an empty scan would read as a clean
result.

Without `--allow-public`, php-radar probes only addresses that are not globally routable:
the private ranges, loopback, link-local, and similar reserved space. A public address
anywhere in the file refuses the whole run before anything is sent. A hostname counts as
public, because telling a name from public space takes a DNS lookup, so a scope file with
one needs `--allow-public` as well. The exception is localhost.

`--max-hosts` caps the number of targets, counting a host on two ports twice, and defaults to
1024. A scope that expands past the cap is refused, so you never get a partial sweep by
accident. I fixed the pace at 10 probes a second to keep a sweep gentle on the network under
test, which puts a /24 on the default ports at about a minute. `--workers` sets how many
probes can wait on a slow host at once, 16 by default and 64 at most.

Before the first probe, php-radar prints the target count and an acknowledgment to stderr:

```
php-radar network: authorization acknowledgment. By continuing you confirm that you own these systems or hold written permission to test them.
```

It does not stop and ask. In automation, review changes to the scope file and to the
`--allow-public` flag like any other change to access.

## Limits

A network read is a lead. The probe sees only what a host chooses to say. A banner can be
hidden, rewritten, or sent by a proxy in front of the real server, and a patched
distribution build can still show the old number. That is why a network read grades LOW
whether it claims a fix or an exposure.

I turned certificate checking off for the probe on purpose. The probe sends no credentials
and reads only what the host presents. Checking the certificate would skip the self-signed
and legacy hosts that are most worth looking at. The GitHub and AWS calls verify
certificates as usual.

IPv6 is not scanned in 0.1.0, and a scope file with an IPv6 address is refused. A hostname
is probed at whatever address your resolver gives it.

NOT_PHP is a narrow claim. It means a host read found no php command on the PATH and no
installed package with php in its name. A PHP build outside the PATH, such as a source build
in an odd directory or a bundled stack like XAMPP or Bitnami, can still read NOT_PHP on a
Linux machine. Over ssh the PATH is the one a non-interactive session gets, which can be
shorter than the one you see after logging in. On Windows, macOS, and Alpine php-radar has
no dpkg or rpm listing to check, so a machine with no php command reads INDETERMINATE and
the run exits 3.

A host read reports the PHP that the php command runs. On a machine with several versions
installed, that is one of them. The command line version can differ from the one the web
server loads, and a server that has not restarted since an upgrade may still run the old
build.

A host read also records four php.ini settings as context: memory_limit, post_max_size,
session.upload_progress.enabled, and fatal_error_backtraces. These are triage notes and never
move a verdict. Read them with care. No setting fixes CVE-2026-109618, whose memory-corruption
path a large multipart request reaches on its own, so turning session.upload_progress.enabled
off does nothing for it, and that setting bears only on CVE-2026-109619. memory_limit reads
backwards: a finite limit is the condition the trigger needs, and memory_limit=-1 removes it and
is protective.

A patched build still carries application risk. The fix closes the memory-corruption and
stale-state paths, but it does not sanitize the filenames that session.upload_progress writes,
so a build at or past the fix can still be reached through an application's own file-inclusion
flaw. php-radar grades the PHP build, and an application's own vulnerabilities are a separate
question.

A distribution package is graded only against the patched builds in the data file. A build
the file does not list reads INDETERMINATE and is never guessed from its upstream number.

The cloud source finds PHP by name, because AWS reports no PHP build number. An Elastic
Beanstalk platform that names PHP gives a branch such as 8.3, and a Lambda layer named like
php-83 gives no version at all. Both grade INDETERMINATE. An ECR finding needs a version in
the tag, such as 8.3.35-fpm in a repository called php, or php-8.3.35 elsewhere. A tag with
only a branch, such as 8.3-fpm, grades INDETERMINATE. A tag with no version, such as
php:latest, produces no row, so that image goes unreported. A tag is a label someone typed.
The image behind it may never run, and the tag can be pushed again to point at another
build. PHP that never says so by name goes unseen: a Docker-platform Beanstalk environment,
a Lambda container image, PHP inside a zip, an image whose tags never mention php.

A repository pin tells you what the repository declares. What runs may differ, and php-radar
does not link a repository to the machines that deploy from it.

php-radar reports one asset per repository, host, or cloud resource. It does not correlate
assets across sources or across separate runs, so a host read and a network read of the same
machine are two reports.

Secret redaction in the report is best effort. php-radar masks values shaped like tokens,
keys, passwords, and credentials in URLs, and it drops any signal whose name suggests a
secret. A secret with no recognizable shape would pass through.

The location of a find and its resource signal name a thing, so two of the checks skip them:
the one for a bare run of 40 base64 characters, and the one for a Bearer or Basic word followed
by a long run. An ARN can hold either by chance. A credential in a URL, in a name=value pair,
or in a known token format is still masked there.

## The PHP2Shell data

`php_radar/data/php2shell.json` holds the fixed releases, the end-of-life cutoff, and the
distribution builds known to carry the fix. A new fix or build is a row there and no code
change. Because JSON has no comments, each entry carries a notes field that says where it
came from. php-radar checks the file's shape on every run, so a bad edit stops the run with
exit 2 before anything is probed.

I edit the file by hand. The first version came from the 2026-10-21 advisories, and the
exposure picture was still moving when I wrote it. It lists patched builds from Ubuntu,
Debian, Alpine, and SUSE. RHEL and Amazon Linux are not in it yet.

## Development

Run the tests with `python -m pytest`. They need only pytest, and a few skip themselves when
a tool is missing: boto3 for the checks against botocore's own service models, setuptools 77
or later for the wheel tests, and the openssl command line for the TLS tests. Nothing in the
suite needs the internet, an AWS account, or GitHub.

## License

Apache License 2.0. The text is in LICENSE and the attribution in NOTICE.
