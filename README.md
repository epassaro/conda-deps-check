# conda-deps-check
A GitHub Actions workflow that scans your Conda environment files for common vulnerabilities and exposures (CVE)

## Usage
This is a [reusable workflow](https://docs.github.com/en/actions/using-workflows/reusing-workflows), so you have to call this workflow from another workflow in your repository, passing the path to your Conda environment file as a parameter.

For example, this workflow will scan your dependencies [once a week](https://crontab.guru/#0_0_*_*_0).

```yaml
name: example

on:
  schedule:
    - cron: '0 0 * * 0'

jobs:
  check-env:
    permissions:
        issues: write

    uses: epassaro/conda-deps-check/.github/workflows/check.yml@main
    with:
      environment-file: environment.yml
```

<br>

If vulnerabilities are detected, it will open a new issue like this:

![image](https://github.com/epassaro/conda-deps-check/assets/22769314/96793f4c-4b42-4092-9792-932936dc0d49)

### Optional parameters

- In case you want to always update an existing issue rather than creating a new one, you can use the `issue-number` parameter
- Also, you can ignore CVEs by listing them on a text file, and passing it to the workflow with the `ignore-file` parameter

## Demo
See the [example repository](https://github.com/epassaro/my-conda-repo) to see this workflow in action.
