============
Contributing
============

.. image:: https://jazzband.co/static/img/jazzband.svg
   :target: https://jazzband.co/
   :alt: Jazzband

This is a `Jazzband <https://jazzband.co>`_ project. By contributing you agree to abide by the `Contributor Code of Conduct <https://jazzband.co/about/conduct>`_ and follow the `guidelines <https://jazzband.co/about/guidelines>`_.


Setup
=====

Fork `django-oauth-toolkit` repository on `GitHub <https://github.com/jazzband/django-oauth-toolkit>`_ and follow these steps:

 * Create a virtualenv and activate it
 * Clone your repository locally

Issues
======

You can find the list of bugs, enhancements and feature requests on the
`issue tracker <https://github.com/jazzband/django-oauth-toolkit/issues>`_. If you want to fix an issue, pick up one and
add a comment stating you're working on it.

Code Style
==========

The project uses `flake8 <https://flake8.pycqa.org/en/latest/>`_ for linting,
`black <https://black.readthedocs.io/en/stable/>`_ for formatting the code,
`isort <https://pycqa.github.io/isort/>`_ for formatting and sorting imports,
and `pre-commit <https://pre-commit.com/>`_ for checking/fixing commits for
correctness before they are made.

You will need to install ``pre-commit`` yourself, and then ``pre-commit`` will
take care of installing ``flake8``, ``black`` and ``isort``.

After cloning your repository, go into it and run::

    pre-commit install

to install the hooks. On the next commit that you make, ``pre-commit`` will
download and install the necessary hooks (a one off task). If anything in the
commit would fail the hooks, the commit will be abandoned. For ``black`` and
``isort``, any necessary changes will be made automatically, but not staged.
Review the changes, and then re-stage and commit again.

Using ``pre-commit`` ensures that code that would fail in QA does not make it
into a commit in the first place, and will save you time in the long run. You
can also (largely) stop worrying about code style, although you should always
check how the code looks after ``black`` has formatted it, and think if there
is a better way to structure the code so that it is more readable.

Pull requests
=============

Please avoid providing a pull request from your `master` and use **topic branches** instead; you can add as many commits
as you want but please keep them in one branch which aims to solve one single issue. Then submit your pull request. To
create a topic branch, simply do::

    git checkout -b fix-that-issue
    Switched to a new branch 'fix-that-issue'

When you're ready to submit your pull request, first push the topic branch to your GitHub repo::

    git push origin fix-that-issue

Now you can go to your repository dashboard on GitHub and open a pull request starting from your topic branch. You can
apply your pull request to the `master` branch of django-oauth-toolkit (this should be the default behaviour of GitHub
user interface).

When you begin your PR, you'll be asked to provide the following:

* Identify the issue number that this PR fixes (if any).
  That issue will automatically be closed when your PR is accepted and merged.

* Provide a high-level description of the change. A reviewer should be able to tell what your PR does without having
  to read the commit(s).

* Make sure the PR only contains one change. Try to keep the PR as small and focused as you can. You can always
  submit additional PRs.

* Any new or changed code requires that a unit test be added or updated. Make sure your tests check for
  correct error behavior as well as normal expected behavior. Strive for 100% code coverage of any new
  code you contribute! Improving unit tests is always a welcome contribution.
  If your change reduces coverage, you'll be warned by `Codecov <https://codecov.io/>`_.

* Update the documentation (in `docs/`) to describe the new or changed functionality.

* Update `CHANGELOG.md` (only for user relevant changes). We use `Keep A Changelog <https://keepachangelog.com/en/1.0.0/>`_
  format which categorizes the changes as:

  * `Added` for new features.

  * `Changed` for changes in existing functionality.

  * `Deprecated` for soon-to-be removed features.

  * `Removed` for now removed features.

  * `Fixed` for any bug fixes.

  * `Security` in case of vulnerabilities. (Please report any security issues to the
     JazzBand security team `<security@jazzband.co>`. Do not file an issue on the tracker
     or submit a PR until directed to do so.)

* Make sure your name is in `AUTHORS`. We want to give credit to all contrbutors!

If your PR is not yet ready to be merged mark it as a Work-in-Progress
By prepending `WIP:` to the PR title so that it doesn't get inadvertently approved and merged.

The repo managers will be notified of your pull request and it will be reviewed, in the meantime you can continue to add
commits to your topic branch (and push them up to GitHub) either if you see something that needs changing, or in
response to a reviewer's comments.  If a reviewer asks for changes, you do not need to close the pull and reissue it
after making changes. Just make the changes locally, push them to GitHub, then add a comment to the discussion section
of the pull request.

Pull upstream changes into your fork regularly
==============================================

It's a good practice to pull upstream changes from master into your fork on a regular basis, in fact if you work on
outdated code and your changes diverge too far from master, the pull request has to be rejected.

To pull in upstream changes::

    git remote add upstream https://github.com/jazzband/django-oauth-toolkit.git
    git fetch upstream

Then merge the changes that you fetched::

    git merge upstream/master

For more info, see http://help.github.com/fork-a-repo/

.. note:: Please be sure to rebase your commits on the master when possible, so your commits can be fast-forwarded: we
    try to avoid *merge commits* when they are not necessary.

How to get your pull request accepted
=====================================

We really want your code, so please follow these simple guidelines to make the process as smooth as possible.

The Checklist
-------------

A checklist template is automatically added to your PR when you create it. Make sure you've done all the
applicable steps and check them off to indicate you have done so. This is
what you'll see when creating your PR:

  Fixes #

  ## Description of the Change

  ## Checklist

  - [ ] PR only contains one change (considered splitting up PR)
  - [ ] unit-test added
  - [ ] documentation updated
  - [ ] `CHANGELOG.md` updated (only for user relevant changes)
  - [ ] author name in `AUTHORS`

Any PRs that are missing checklist items will not be merged and may be reverted if they are merged by
mistake.


Run the tests!
--------------

Django OAuth Toolkit aims to support different Python and Django versions, so we use **tox** to run tests on multiple
configurations. At any time during the development and at least before submitting the pull request, please run the
testsuite via::

    tox

The first thing the core committers will do is run this command. Any pull request that fails this test suite will be
**immediately rejected**.

Add the tests!
--------------

Whenever you add code, you have to add tests as well. We cannot accept untested code, so unless it is a peculiar
situation you previously discussed with the core committers, if your pull request reduces the test coverage it will be
**immediately rejected**.

You can check your coverage locally with the `coverage <https://pypi.org/project/coverage/>`_ package after running tox::

  pip install coverage
  coverage html -d mycoverage

Open mycoverage/index.html in your browser and you can see a coverage summary and coverage details for each file.

There's no need to wait for Codecov to complain after you submit your PR.

Code conventions matter
-----------------------

There are no good nor bad conventions, just follow PEP8 (run some lint tool for this) and nobody will argue.
Try reading our code and grasp the overall philosophy regarding method and variable names, avoid *black magics* for
the sake of readability, keep in mind that *simple is better than complex*. If you feel the code is not straightforward,
add a comment. If you think a function is not trivial, add a docstrings.

To see if your code formatting will pass muster use: `tox -e py37-flake8`


The contents of this page are heavily based on the docs from `django-admin2 <https://github.com/twoscoops/django-admin2>`_

Maintainer Checklist
====================
The following notes are to remind the project maintainers and leads of the steps required to
review and merge PRs and to publish a new release.

Reviewing and Merging PRs
------------------------

- Make sure the PR description includes the `pull request template
  <https://github.com/jazzband/django-oauth-toolkit/blob/master/.github/pull_request_template.md>`_
- Confirm that all required checklist items from the PR template are both indicated as done in the
  PR description and are actually done.
- Perform a careful review and ask for any needed changes.
- Make sure any PRs only ever improve code coverage percentage.
- All PRs should be be reviewed by one individual (not the submitter) and merged by another.

PRs that are incorrectly merged may (reluctantly) be reverted by the Project Leads.


Publishing a Release
--------------------

Only Project Leads can publish a release to pypi.org and rtfd.io. This checklist is a reminder
of steps.

- When planning a new release, create a `milestone
  <https://github.com/jazzband/django-oauth-toolkit/milestones>`_
  and assign issues, PRs, etc. to that milestone.
- Review all commits since the last release and confirm that they are properly
  documented in the CHANGELOG. (Unfortunately, this has not always been the case
  so you may be stuck documenting things that should have been documented as part of their PRs.)
- Make a final PR for the release that updates:

  - CHANGELOG to show the release date.
  - setup.cfg to set `version = ...`

- Once the final PR is committed push the new release to pypi and rtfd.io.
