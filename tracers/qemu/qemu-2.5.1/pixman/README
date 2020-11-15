Pixman is a library that provides low-level pixel manipulation
features such as image compositing and trapezoid rasterization.

Questions, bug reports and patches should be directed to the pixman
mailing list:

        http://lists.freedesktop.org/mailman/listinfo/pixman

You can also file bugs at

        https://bugs.freedesktop.org/enter_bug.cgi?product=pixman

For real time discussions about pixman, feel free to join the IRC
channels #cairo and #xorg-devel on the FreeNode IRC network.


Contributing
------------

In order to contribute to pixman, you will need a working knowledge of
the git version control system. For a quick getting started guide,
there is the "Everyday Git With 20 Commands Or So guide"

        http://www.kernel.org/pub/software/scm/git/docs/everyday.html

from the Git homepage. For more in depth git documentation, see the
resources on the Git community documentation page:

        http://git-scm.com/documentation

Pixman uses the infrastructure from the freedesktop.org umbrella
project. For instructions about how to use the git service on
freedesktop.org, see:

        http://www.freedesktop.org/wiki/Infrastructure/git/Developers

The Pixman master repository can be found at:

	git://anongit.freedesktop.org/git/pixman

and browsed on the web here:

	http://cgit.freedesktop.org/pixman/


Sending patches
---------------

The general workflow for sending patches is to first make sure that
git can send mail on your system. Then, 

 - create a branch off of master in your local git repository

 - make your changes as one or more commits

 - use the 

        git send-email

   command to send the patch series to pixman@lists.freedesktop.org.

In order for your patches to be accepted, please consider the
following guidelines:

 - This link:

        http://www.kernel.org/pub/software/scm/git/docs/user-manual.html#patch-series

   describes how what a good patch series is, and to create one with
   git.

 - At each point in the series, pixman should compile and the test
   suite should pass.

   The exception here is if you are changing the test suite to
   demonstrate a bug. In this case, make one commit that makes the
   test suite fail due to the bug, and then another commit that fixes
   the bug.

   You can run the test suite with 

        make check

   It will take around two minutes to run on a modern PC.

 - Follow the coding style described in the CODING_STYLE file

 - For bug fixes, include an update to the test suite to make sure
   the bug doesn't reappear.

 - For new features, add tests of the feature to the test
   suite. Also, add a program demonstrating the new feature to the
   demos/ directory.

 - Write descriptive commit messages. Useful information to include:
        - Benchmark results, before and after
	- Description of the bug that was fixed
	- Detailed rationale for any new API
	- Alternative approaches that were rejected (and why they
          don't work)
	- If review comments were incorporated, a brief version
          history describing what those changes were.

 - For big patch series, send an introductory email with an overall
   description of the patch series, including benchmarks and
   motivation. Each commit message should still be descriptive and
   include enough information to understand why this particular commit
   was necessary.

Pixman has high standards for code quality and so almost everybody
should expect to have the first versions of their patches rejected.

If you think that the reviewers are wrong about something, or that the
guidelines above are wrong, feel free to discuss the issue on the
list. The purpose of the guidelines and code review is to ensure high
code quality; it is not an exercise in compliance.
