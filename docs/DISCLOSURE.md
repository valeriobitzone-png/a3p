# Disclosure policy

This checkout is not a published project. There is no security@ alias, no bounty, and no public advisory channel here.

## How to report

Report a vulnerability to the maintainer of the checkout you are running. Include the items in `SECURITY.md`. Give the maintainer time to reproduce it before any public write-up.

Do not file an exploit as a public issue first. Do not include live credentials, customer content, or a private signing key in the report.

## What you can expect

The maintainer will say whether they can reproduce the behavior against this tree, and whether it changes Method v1.0, the sandbox, or the badge check. A confirmed bug in the method is documented as a method change when the criteria move. A confirmed bug that does not move the criteria can ship as a package fix on the same method version.

There is no payment. There is no promise of a timeline.

## Out of scope

- A model saying something harmful inside a probe you were authorized to run. That is a finding for the model operator, scored by the batteries, not a vulnerability in the probe.
- Results from a configuration that set `A3P_ISOLATION=inprocess` on purpose. The report says so.
- Claims that a passing sample should have been a guarantee. The method does not say that.
