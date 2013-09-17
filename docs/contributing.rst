============
Contributing
============

Setup
=====

Fork `django-oauth-toolkit` repository on `GitHub <https://github.com/evonove/django-oauth-toolkit>`_ and follow these steps:

 * Create a virtualenv and activate it
 * Clone your repository locally
 * cd into the repository and type `pip install -r requirements/optional.txt` (this will install both optional and base requirements, useful during development)

Issues
======

You can find the list of bugs, enhancements and feature requests on the
`issue tracker <https://github.com/evonove/django-oauth-toolkit/issues>`_. If you want to fix an issue, pick up one and
add a comment stating you're working on it. If the resolution implies a discussion or if you realize the comments on the
issue are growing pretty fast, move the discussion to the `Google Group <http://groups.google.com/group/django-oauth-toolkit>`_.

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

Next you should add a comment about your branch, and if the pull request refers to a certain issue, insert a link to it.
The repo managers will be notified of your pull request and it will be reviewed, in the meantime you can continue to add
commits to your topic branch (and push them up to GitHub) either if you see something that needs changing, or in
response to a reviewer's comments.  If a reviewer asks for changes, you do not need to close the pull and reissue it
after making changes. Just make the changes locally, push them to GitHub, then add a comment to the discussion section
of the pull request.

Pull upstream changes into your fork regularly
==============================================

It's a good practice to pull upstream changes from master into your fork on a regular basis, infact if you work on
outdated code and your changes diverge too far from master, the pull request has to be rejected.

To pull in upstream changes::

    git remote add upstream https://github.com/evonove/django-oauth-toolkit.git
    git fetch upstream

Then merge the changes that you fetched::

    git merge upstream/master

For more info, see http://help.github.com/fork-a-repo/

.. note:: Please be sure to rebase your commits on the master when possible, so your commits can be fast-forwarded: we
    try to avoid *merge commits* when they are not necessary.

How to get your pull request accepted
=====================================

We really want your code, so please follow these simple guidelines to make the process as smooth as possible.

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
situation you previously discussed with the core commiters, if your pull request reduces the test coverage it will be
**immediately rejected**.

Code conventions matter
-----------------------

There are no good nor bad conventions, just follow PEP8 (run some lint tool for this) and nobody will argue.
Try reading our code and grasp the overall philosophy regarding method and variable names, avoid *black magics* for
the sake of readability, keep in mind that *simple is better than complex*. If you feel the code is not straightforward,
add a comment. If you think a function is not trivial, add a docstrings.

The contents of this page are heavily based on the docs from `django-admin2 <https://github.com/twoscoops/django-admin2>`_
