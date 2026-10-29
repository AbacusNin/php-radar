# php-radar

php-radar finds PHP you did not know you were running and tells you which installs are
exposed to PHP2Shell (CVE-2026-109618 and CVE-2026-109619), two remote code execution bugs
in the PHP runtime. It reads versions and configuration to work out each build, then checks
the build against the releases that carry the fix. It never sends anything meant to trigger
the bug, so it cannot crash a target.

Point it at a repository, a GitHub organization, a range of addresses, or a single machine. It
also reads AWS accounts, Google Cloud projects, and Azure subscriptions. Every find gets a
verdict and a confidence, and the exit code tells a script whether anything is exposed.

## Install

Python 3.10 or later. The core uses only the standard library.

```
pip install php-radar
```

For a cloud source, add the extra for its provider:

```
pip install "php-radar[aws]"
pip install "php-radar[gcp]"
pip install "php-radar[azure]"
```

Or install from a clone with `pip install .` (or `pip install ".[aws]"`), and
`python -m php_radar` runs it without installing.

## Usage

```
php-radar repo PATH                                   # a checkout on disk
php-radar repo --github-org NAME                      # every repo in a GitHub org
php-radar host                                        # this machine
php-radar host --ssh USER@HOST                        # a machine over ssh
php-radar cloud --provider aws                        # an AWS account
php-radar cloud --provider gcp --project ID           # a Google Cloud project
php-radar cloud --provider azure --subscription GUID  # an Azure subscription
php-radar network --scope FILE                        # addresses you are cleared to probe
```

Add `--format json` or `--format sarif` for machine-readable output (the default is a
console table), and `--output FILE` to write the report to a file.

## Cloud accounts

The cloud command lists what an account runs and reports the PHP in it. It makes read calls
only. Credentials come from each provider's standard chain: the AWS default chain,
Application Default Credentials for Google Cloud, and DefaultAzureCredential for Azure. No
flag takes a credential.

| Provider | Reads | Scope flag | Without the flag |
|---|---|---|---|
| `aws` | Elastic Beanstalk environments, Lambda functions, ECR images | `--region` | the session's own region |
| `gcp` | App Engine versions, Cloud Functions, Artifact Registry images | `--project` | the project of the credentials |
| `azure` | App Service apps, Container Apps, Container Registry images | `--subscription` | `AZURE_SUBSCRIPTION_ID` when it is set, otherwise every subscription the credential can list |

Repeat a flag to read more than one region, project, or subscription. `--project` takes a
project id. `--subscription` takes a subscription id, which is a GUID.

`AZURE_SUBSCRIPTION_ID` sets the default Azure subscription for a run that passes no
`--subscription`. Its value has to be a subscription id (a GUID). A blank value, or any other
value that is not a subscription id, stops the run with exit status 2. That holds even when
you also pass `--subscription`. A CI job that fills the variable from a secret it does not
have sends it blank. Reading that as unset would widen the run to every subscription the
credential can list.

Google Cloud reads use the quota project of the Application Default Credentials. Without
one, an App Engine Admin API that is turned off can answer not found, the same as a project
with no application. The run cannot tell the two apart, so it marks that read skipped
instead of guessing. The result is incomplete, and the run exits 3 when nothing is exposed.
That holds even for a project that has no App Engine application. To avoid the skip, set a
quota project with `gcloud auth application-default set-quota-project PROJECT_ID`, or set
the `GOOGLE_CLOUD_QUOTA_PROJECT` variable.

Both the GCP and Azure sources have now been run read-only against live accounts. Each
authenticated through its standard chain and read the services above. Where an API was
turned off, the run marked that read skipped and called the whole result incomplete.
Neither account held PHP, so grading a real find still rests on the tests and the
stand-ins they build from the SDKs' published definitions.

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
  The exception is Azure. With neither `--subscription` nor `AZURE_SUBSCRIPTION_ID`, a run
  reads every subscription the credential can list. A network sweep refuses public ranges
  unless you pass `--allow-public`, rate-limits itself, and prints an authorization notice
  before it runs. Whether you may scan is on you.
- **A patched build still carries application risk.** The fix closes the runtime bug. An
  application's own flaws, such as a file-inclusion sink, are a separate question.

## License

Apache License 2.0 with the Commons Clause. Anyone, including a company or a government
agency, may use, change, and share php-radar free of charge, for example to check its own
systems. Nobody may sell it, host it for a fee, or sell a product or service, including
consulting or support, whose value comes entirely or substantially from it. This makes it
source-available rather than OSI open source. See LICENSE and NOTICE.

I'm not accepting outside contributions.
