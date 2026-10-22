# Onboarding plan

Goal: every new person knows exactly how to get started, based on role. Guidance is derived from real data (like `js/milestones.js`), never blocks, and is dismissible.

## Phase 1 — frontend only (no schema, no worker deploy)
| Slice | Delivers | Status |
|---|---|---|
| 1a | Learner welcome card (`#l-welcome`) | Built |
| 1b | Manager "Get your team started" checklist (invite, assign, watch progress) and an empty-state action; Demo gets "As a new manager" | Built |
| 1c | Admin "Set up your academy" checklist (brand, team, course, invite a manager, assign) | Planned |
| 1d | Invite page polish: org logo and name, clearer "what happens next" | Planned |

Not in 1a: a pre-course expectations line. The player has no intro screen and courses have no duration field, so the welcome card carries the pass mark, auto-save and retake notes instead.

## Phase 2 — email and nudges
Welcome email on invite signup, assignment email, due-soon reminder (needs a Cloudflare cron trigger), "I'm ready" nudge to the manager. Reuses `worker/email.js`.

## Phase 3 — needs approval (schema)
Invite-attached courses that auto-assign on join, inviter name and personal note on the invite (`invite_codes` has no creator column), a sample course, and funnel metrics (invite redeemed → first start → first pass).

Note on 1b: assignments are per learner, so assigning stays locked until a first learner has joined. The "See a finished example" link was dropped: launching the Demo from inside a real session would overwrite the signed-in manager state. The Demo picker's new-manager option covers it from the landing page.
