---
name: emil-design
description: Emil Kowalski-inspired UI design principles — motion, craft, and minimalism for the IoT-Sentinel dashboard. Use whenever designing, building, or reviewing UI (layout, components, animation, transitions, hover/focus states, theming). Prioritizes purposeful motion, restraint, and native-feeling detail.
---

# Emil-inspired design principles

Design language for IoT-Sentinel's UI, inspired by Emil Kowalski's work (Sonner, Vaul,
animations.dev): motion with intent, ruthless restraint, and obsessive craft. Apply these
to every screen and component. Pairs with [[impeccable-design]] (anti-slop/distinctiveness
checklist) and [[taste-skill]] (dial calibration, em-dash ban, hard pass/fail checks) — this
skill owns motion, restraint, and craft detail.

## 1. Motion (the signature)

Motion is the most visible layer of craft. Get the easing and timing right; skip decoration.

- **Never use `linear` easing** for UI (only for continuous spinners/progress). Entrances use
  **ease-out**, exits use **ease-in**. Prefer custom curves: `cubic-bezier(0.32, 0.72, 0, 1)`
  (Emil's signature smooth ease-out) for panels/modals.
- **Timing**: 150–200ms for small state changes (hover, color, small moves), 250–350ms for
  larger transforms (modals, drawers). Faster than you think feels snappier.
- **Animate only `transform` and `opacity`** (GPU-friendly). Never animate `width`, `top`,
  `box-shadow`, or `background` in hot paths — they cause layout/paint jank.
- **Origin-aware**: elements animate *from where they belong* — a modal scales up slightly
  (`scale(0.97)→1`) + fades; a card lifts on hover (`translateY(-2px)`).
- **Interruptible & reversible**: transitions on the base element (CSS `transition`), so a
  reversed hover/close feels immediate, not queued.
- **Always** honor `@media (prefers-reduced-motion: reduce)` — drop transforms, keep opacity.

## 2. Restraint (minimalism)

- Content first. Chrome disappears. Remove borders, boxes, and labels that don't earn their place.
- One accent color, used sparingly for the primary action and focus. Everything else is
  neutral greys with a clear hierarchy (text / muted / faint).
- Generous, consistent spacing on a rhythm (4px base: 4/8/12/16/24/32). Whitespace is a feature.
- Prefer a single strong number/visual over a dense table. Show the signal, hide the noise
  behind a click (progressive disclosure — cards → modal).
- Subtle depth: 1px hairline borders, soft low-opacity shadows, blurred backdrops for overlays.
  No hard drop shadows, no gradients-for-decoration.

## 3. Craft (the details that separate good from great)

- **Every interactive element has 4 states**: rest, hover, active (`:active` nudges 1px),
  focus-visible (a clear ring — never remove outlines without replacing them).
- **Optical alignment** over mathematical: icons and text centered by eye; consistent baseline.
- **Typography**: a real type scale, tight line-height on headings, comfortable on body
  (~1.5). One or two weights. Numbers can use tabular/mono for alignment (risk scores, IPs).
- **Instant feedback**: interactions respond within one frame (hover/press), and async actions
  show optimistic/loading state immediately — never a dead click.
- **Native-feeling overlays**: modals/drawers fade the backdrop with a slight blur, trap focus,
  close on Esc and backdrop click, and animate in from a natural origin.
- **Toasts over inline errors** for transient feedback (Sonner-style): stack bottom-right,
  auto-dismiss, swipe/close, spring in. Reserve inline text for persistent/validation errors.

## 4. Dark + light done well

- Don't just invert. In dark mode, elevate surfaces with *lighter* panels (not pure black),
  reduce pure-white text to ~90% for comfort, and keep accent saturation slightly lower.
- Semantic risk colors (critical/high/medium/low) stay legible and distinct in both themes;
  verify contrast (WCAG AA) for text on colored chips.

## 5. Checklist before shipping a screen

- [ ] Motion uses ease-out/in with a custom curve, transform+opacity only, reduced-motion handled
- [ ] One accent; neutral hierarchy is clear; spacing on the 4px rhythm
- [ ] Every control has hover / active / focus-visible states
- [ ] Progressive disclosure: overview first, detail on demand
- [ ] Overlays: blur backdrop, focus trap, Esc + click-out, natural origin animation
- [ ] Contrast passes AA in both themes; numbers are aligned (tabular/mono)
