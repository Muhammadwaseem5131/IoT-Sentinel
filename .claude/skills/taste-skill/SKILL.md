---
name: taste-skill
description: Taste-Skill-inspired anti-slop rules (github.com/Leonxlnx/taste-skill) adapted for the IoT-Sentinel dashboard — dial-driven design (variance/motion/density), the em-dash ban, color/contrast/button hard rules, and a pre-flight checklist. Use alongside emil-design and impeccable-design whenever designing, building, reviewing, or writing copy for the UI.
---

# Taste-Skill-inspired rules, adapted for a security dashboard

Adapted from [Leonxlnx/taste-skill](https://github.com/Leonxlnx/taste-skill), which targets
marketing/landing pages. IoT-Sentinel is a **data-dense security console**, not a landing page,
so this skill keeps what transfers (dials, hard rules, motion discipline, pre-flight checklist)
and drops what doesn't (hero copy, bento grids, marquees, logo walls — no marketing surface
exists in this app). Pairs with [[emil-design]] (motion/craft) and [[impeccable-design]]
(anti-slop tells) — this skill owns the **dial calibration, the em-dash ban, and hard
pass/fail checks**.

## The three dials, calibrated for IoT-Sentinel

State the dial reading before designing any new screen — it's the project's fixed baseline,
not re-inferred per component:

- **DESIGN_VARIANCE: 3** — *Predictable.* A security tool is scanned under stress (an admin
  triaging a critical finding). Symmetrical grids, consistent card layout, left-aligned data.
  No asymmetric/masonry layouts — variance here reads as instability, not style.
- **MOTION_INTENSITY: 5** — *Fluid CSS.* Matches [[emil-design]]: `transition` with a custom
  ease-out curve, staggered list/card entrances, hover lifts. No scroll-hijacking, parallax, or
  cinematic choreography — this is a tool, not a story.
- **VISUAL_DENSITY: 7** — *Cockpit.* This is explicitly a data-dense operator tool (device
  tables, risk scores, port lists, findings). Tight-but-legible padding, monospace/tabular
  numbers for IPs and risk scores (already the convention — keep it), compact card metadata.
  Not art-gallery whitespace; not so dense it stops being scannable.

Don't renegotiate these per-component. If a specific screen (e.g. the empty/onboarding state)
genuinely wants more air, say so explicitly and treat it as a deliberate exception.

## The em-dash ban (non-negotiable, applies to all UI copy)

**No em-dash (`—`) or en-dash (`–`) in any UI-facing string**: card labels, empty states, button
text, tooltips, modal copy, toast messages, error text, the README's UI-adjacent docs. This is
the clearest AI-writing tell there is, and IoT-Sentinel's copy should read like a human security
engineer wrote it.

- Replace with a period, comma, colon, or two sentences.
- The only permitted dash is a regular hyphen `-` (compound words, ranges like `192.168.1.0-254`).
- Before shipping any new copy: search the changed files for `—` and `–` and rewrite every hit.

(This applies to strings *in the product* — code comments and this conversation's prose are out
of scope, but product copy is not.)

## Hard rules that transfer to a dashboard

- **Color Consistency Lock**: one accent color (`--accent`), used identically everywhere. Risk
  severity colors (critical/high/medium/low) are the only sanctioned second palette, and they
  stay fixed in meaning across every screen, modal, chip, and chart.
- **The Lila Rule**: no purple-to-blue AI-glow gradients, no decorative neon. (Reinforces
  [[impeccable-design]].)
- **Button Contrast Check**: every button/pill text passes WCAG AA (4.5:1 body, 3:1 large) against
  its background — check this explicitly for the severity-colored pills and score badges.
- **CTA Button Wrap Ban**: primary action labels stay on one line at normal widths ("Start Scan",
  "Enable monitor", "Explain & fix with AI") — 1-3 words, never wrapping to two lines.
- **No Duplicate CTA Intent**: one label per action across the app. Don't mix "View details",
  "Open", and "See more" for the same click target — this app already standardized on
  "View details →"; keep it that way everywhere new.
- **Form Contrast Check**: inputs, placeholders, focus rings, and helper/error text all pass AA
  against the panel background, in both themes once light mode exists.
- **Label Restraint**: don't put an eyebrow/kicker label above every card or section by default —
  only where it adds real scanability (e.g. "Discovered Devices (5)" already earns its heading;
  a redundant label above it would not).
- **Copy Self-Audit** before shipping any new string: re-read every visible label/message for
  grammar, unclear referents, or AI-hallucinated phrasing (no filler verbs like "elevate" /
  "seamless" / "unleash" — say what the button does).

## Motion discipline (adds to emil-design)

- **Motion must be motivated**: before adding any transition/animation, state in one clause what
  it communicates (state change, hierarchy, feedback) — "looked cool" is not a reason.
- **No `window.addEventListener('scroll')`** and no `requestAnimationFrame` loop touching React
  state for anything in this app (nothing here needs scroll-driven effects; if that ever changes,
  use CSS scroll-driven animations or an IntersectionObserver, not a manual listener).
- Animate only `transform` and `opacity` (already the [[emil-design]] rule — restated because
  it's the single highest-impact performance rule).
- **Reduced motion**: every non-trivial transition respects
  `@media (prefers-reduced-motion: reduce)`.

## Performance & accessibility guardrails

- **Dark mode is mandatory, light mode when added is not a re-skin**: both need independently
  checked AA contrast, not just inverted values.
- **Viewport stability**: never `height: 100vh` for a scrolling app shell; the layout must not
  jump on mobile browser chrome show/hide.
- Icons: one family, used consistently (this app currently uses emoji as device/status icons —
  that's a deliberate, valid choice per [[impeccable-design]]'s "earn your icon" rule; don't mix
  in an SVG icon library halfway through).
- `useEffect`-driven animations/timers clean up on unmount (polling loops, modal listeners).

## Pre-flight checklist (dashboard-adapted)

Run before shipping any new screen or component:

- [ ] Dial reading matches the project baseline (variance 3 / motion 5 / density 7), or the
      exception is stated explicitly
- [ ] Zero em-dashes/en-dashes in any new UI string
- [ ] One accent color; severity colors used only for severity
- [ ] Every button/pill passes AA contrast; primary labels don't wrap
- [ ] No duplicate CTA intent; label matches existing conventions elsewhere in the app
- [ ] Every animation is motivated in one clause; transform/opacity only; reduced-motion respected
- [ ] No scroll listeners or RAF loops touching React state
- [ ] Copy self-audit done: no filler verbs, no unclear referents
- [ ] Effects/timers/listeners clean up on unmount
