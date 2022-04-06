# Contributing

## I don't want to read this whole thing, I just have a question

Please **don't file an issue** to ask a question. You'll get faster results by using our [Slack workspace](https://developers.rsk.co/slack/) instead.

## How to contribute to PowHSM

These are mostly guidelines, not rules. Use your best judgment, and feel free to propose changes to this document in a pull request.

### Code Reviews

Continued code reviews and audits are required for security. As such, we encourage interested security researchers to:

* Review our code, even if no contributions are planned.
* Publish their findings whichever way they choose, even if no particular bug or vulnerability was found. We can all learn from new sets of eyes and benefit from increased scrutiny.

### Code contributions

A code contribution process starts with someone identifying a need for writing code. If you're thinking about making your first contribution, we suggest you take a moment to get in touch and see how your idea fits in the development plan:

* Is it a bug in our [issue tracker](https://github.com/rsksmart/rsk-powhsm/issues)?
* Is it a novel idea that should be proposed and discussed first?

#### Review process

Once you know what to do, it is important that you provide a full description of the proposed changes. You can also send a draft pull request if you already have code to show.

We make use of GitHub Checks to ensure all changes meet a certain criteria:

1. The `master` branch is protected and only changeable through pull requests
1. All tests (unit and integration) must pass
1. The C linter must pass
1. The python linter must pass
1. The SonarQube quality gate must be met
1. A project maintainer must approve the pull request
1. An authorized merger must merge the pull request

Since this is a security-sensitive project, we encourage everyone to be proactive and participate in the review process. To help collaboration we propose adhering to these conventions:

* **Request changes** only for correctness and security issues.
* **Comment** when leaving feedback without explicit approval or rejection. This is useful for design, implementation and style-related discussions.
* **Approve** when changes look good from a correctness and security standpoint.

All unit and integration tests pass without loss of coverage (e.g can't remove tests without writing equivalent or better ones).

All code paths on new code must be tested, including sensible edge cases and expected errors. Exceptions to this rule must be justified (i.e. highly similar paths already tested) in written form in the PR description. 

New dependencies are discouraged in order to minimize the attack surface.

In order to ease review, it is expected that the code diff is maintained to a minimum. This includes things like not changing unrelated files, not changing names or reordering code when there isn't an evident benefit.

#### Branching

Under normal circumstances, the PowHSM repository has a sole main branch, `master`, which is protected. This contains the latest nonreleased version, and is constantly updated with changes (e.g., features, bugfixes). There can occasionally exist protected _version_ branches in case there is ongoing patch work on top of an old version. Aside from this, we manage version releases using tags and GitHub releases for some of these.

When creating a pull request for a given set of changes, make sure to create a new branch with a _meaningful_ name off the `master` branch. If your change happens to be an improvement or fix over an old tagged version, then please make sure to contact the team first so that they can assess the situation and create a branch from the corresponding tag so that you can target your pull request to.

## Style

### Pull request etiquette

* Separate your changes into multiple (meaningful) commits when appropiate from a functionality standpoint. 
* If your pull request gets too big, try to split it
* Merge commits are forbidden. Always rebase your changes on top of the target branch
* Make sure your code adheres to the project's established C and Python code style (see below)

### Code style

This repository hosts both C and Python code. Any changes introduced must pass both the existing Python and C automatic linting processes.

For C, we use [clang-format](https://releases.llvm.org/10.0.0/tools/clang/docs/ClangFormat.html) for both linting and formatting. See the [linting/formatting](./lint-c) script for details and specifics.

For Python, we use [flake8](https://flake8.pycqa.org/en/latest/) for linting [yapf](https://github.com/google/yapf) for automatic formatting. See the [linting](./lint-python) and [formatting](./format-python) scripts for details and specifics.

In general terms we prefer manual formatting for new code, so please adhere to the rules from the start where possible.
