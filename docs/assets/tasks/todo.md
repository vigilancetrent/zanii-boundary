# README asset redesign

## Investigation
- Existing patterns: `banner.svg`, `architecture.svg`, and their image embeds in `../../README.md`.
- Stack: standalone accessible SVG assets; surrounding project is Node.js ESM. No asset dependencies or build step.
- Conventions: 1200px view boxes, Inter with local fallbacks, explicit image titles and descriptions.
- History: repository has no commits. Both assets are currently untracked.
- Scope: two static SVGs; no runtime, configuration, fixtures, exports, or README changes needed.
- Risk: low; preserve filenames, dimensions, independent authorization, and deployment qualification text.

## Direction and decisions
Primary reference: Linear Changelog, https://linear.app/changelog (Refero style 11d3e58a-87d7-4a9a-bbf5-720f4fd3ffc6).
Secondary references: Tailscale, https://tailscale.com (5d884659-1d6b-4b82-8ccd-dbb0434667a8), and Oxide, https://oxide.computer (57399d2f-b94d-48df-a573-2c423077b16c).

| Decision | Source and role | Reason |
| --- | --- | --- |
| Charcoal banner, medium-weight display type, thin dividers | Linear: canvas, typography, separation | Establish hierarchy with minimal ornament |
| White technical diagram with lightly outlined service groups | Tailscale: technical clarity on light surfaces | Keep the detailed request flow readable in the README |
| Monospace transport and stage labels | Oxide: technical notation only | Distinguish protocols and execution stages from descriptions |
| Mint boundary and authority emphasis | Existing Zanii identity | Retain brand continuity and give the accent a precise meaning |
| Vertical banner flow and numbered architecture stages | Existing request sequence | Make the graphics specific to Boundary's enforcement model |

Reference lock: flat technical surfaces, restrained mint accent, clear type hierarchy, no decorative grid, gradients, glow, stock art, or generic shield illustration. SVG geometry supplies the product diagram. Preserve independent resource authorization and deployment acceptance qualifications.

## Plan
- [x] Inspect assets, embeds, dependencies, history, and design references.
- [x] Redesign `banner.svg` and `architecture.svg` in place.
- [x] Review SVG structure, accessibility, text contrast, and preserved content.
- [x] Render both assets at README size and inspect for overflow or alignment problems.

## Review
Passed: XML parsing, preserved dimensions and README embeds, accessible labels, no script or external image dependencies, and preservation of security qualifications. Headless Chromium reported no clipped or overlapping text and produced previews at 960px and 600px. All 12 text color pairs pass the WCAG AA 4.5:1 threshold. Both assets were visually reviewed. Whitespace checks passed.

No backend tests run: these changes affect static images only. GitHub's hosted rendering was not checked. Fonts retain the existing local fallback approach, so glyphs can vary across systems. Small screens scale the diagrams rather than rearranging their content.

## Original generated concept: The Aperture
User steering: create an original idea and generate it. Deliver a new banner concept using the built-in image generation tool.

Asset lock: wide marketing banner; charcoal, near-white, and the existing mint accent. A precision-machined architectural opening expresses task-scoped execution. Preserve the product name and current description. Use a studio-rendered physical metaphor, not interface boxes or security clip art.

References retain bounded roles: Linear supplies typography and negative space; Oxide supplies infrastructure materiality. The aperture composition is an original product-specific concept. This is conceptual brand artwork, not an engineering topology or evidence of a deployed control.

- [x] Generate original banner concept.
- [x] Inspect image and save the project deliverable.

Deliverable: `../banner-aperture.png`, generated with the built-in image tool. Prompt: `aperture-prompt.txt`. Visually inspected the generated result: the exact product name and supporting copy are legible, the aperture motif is present, and the palette matches the asset lock. PNG decoding and wide-format dimensions verified. Delivered as a new concept asset; existing README embeds still use the SVG designs.
