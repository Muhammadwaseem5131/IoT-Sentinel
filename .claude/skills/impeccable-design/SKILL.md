---
name: impeccable-design
description: Impeccable-inspired anti-slop design guidance (github.com/pbakaus/impeccable) for the IoT-Sentinel dashboard. Use alongside emil-design whenever designing, building, reviewing, or auditing UI — catches generic "AI-template" tells (Inter everywhere, purple-blue gradients, nested cards, gray-on-color text) and pushes toward a distinctive, intentional interface.
---

# Impeccable-inspired anti-slop design guidance

Adapted from [pbakaus/impeccable](https://github.com/pbakaus/impeccable): a shared design
vocabulary that stops AI-generated UI from converging on the same generic "SaaS template"
look. Pairs with [[emil-design]] (motion/craft/restraint) and [[taste-skill]] (dial
calibration, em-dash ban, hard checks) — this one is the **anti-pattern checklist and
distinctiveness pass**.

## Why this exists

Every model trained on the same SaaS templates reaches for the same tells. If nothing pushes
back, an AI-built dashboard drifts toward generic "AI slop" regardless of the actual product.
IoT-Sentinel should look like a considered security tool, not a template.

## The tells to actively avoid

- **Typography**: don't default to Inter / Arial / system-ui for everything. Pick a deliberate
  type choice (or pair) and use it with intent — not just "whatever the framework shipped with."
- **Purple-to-blue gradients**: the single most obvious AI-slop signature. Avoid decorative
  gradients entirely unless they encode real meaning (e.g. a risk heat scale).
- **Gray text on colored backgrounds**: low-contrast text on a colored chip/button is both an
  a11y failure and a slop tell. Colored surfaces get high-contrast text, always checked against
  AA.
- **Pure black / pure gray**: neutrals should be tinted (a whisper of the brand hue), not `#000`
  / `#888`. IoT-Sentinel's dark navy (`--bg`) is the right instinct — keep extending that tint
  through the whole neutral ramp instead of dropping to flat gray anywhere.
- **Cards nested in cards**: a card inside a card inside a card is a tell that layout wasn't
  actually designed, just stacked. One level of surface elevation per region; use spacing and
  typographic hierarchy instead of another border to separate sub-content.
- **The rounded-square icon tile above every heading**: don't reach for a generic icon-in-a-box
  above section titles by default — earn it, or skip it.
- **Bounce / elastic easing**: reads as dated and toy-like on a security console. (Matches
  [[emil-design]]'s motion rule — ease-out/ease-in only.)
- **Side-tab borders and dark glows on everything**: another generic-template tell; a component
  needs a real reason for a glow/border treatment, not decoration by default.

## Quality checks (deterministic, apply while reviewing any screen)

- Line length: body text isn't stretched edge-to-edge in a wide card — cap measure for
  readability.
- Padding isn't cramped: touch/click targets meet a comfortable minimum (44px-ish), especially
  on the device/wireless cards and modal buttons.
- Heading levels aren't skipped (h2 straight to h4) — keep a real outline.
- Spacing is consistent and rhythmic, not ad hoc per component (ties to [[emil-design]]'s 4px
  rhythm).

## Workflow concepts worth keeping

- **Shape before you build**: for a new screen, decide the layout/hierarchy/tone in one pass
  before writing component code — don't discover the design by iterating on markup.
- **Know the anti-references**: it helps to name what the product should *not* look like
  (generic AI SaaS dashboard, crypto-startup gradient hero) as much as what it should.
- **A running design record**: this project's `DESIGN.md`-equivalent is the palette and rules
  already established in `frontend/src/index.css` (dark security-console theme, risk color
  system, card/modal patterns) — extend that vocabulary rather than introducing a competing one
  per new component.
- **Passes, not one shot**: distinct passes for shape → build → critique (hierarchy/clarity) →
  audit (a11y/contrast/responsive) → polish, rather than trying to nail everything in the first
  draft.

## Checklist before shipping a screen

- [ ] No purple-blue gradient, no decorative gradient without meaning
- [ ] No gray-on-color text; colored chips/buttons pass AA contrast
- [ ] Neutrals are tinted, not pure black/gray
- [ ] No card-in-a-card; one elevation level per region
- [ ] No default icon-tile-above-heading unless it earns its place
- [ ] Typography choice is deliberate, not the untouched default
- [ ] Heading hierarchy isn't skipped; line length is capped for readability
- [ ] Touch targets are comfortable; spacing follows the existing rhythm
