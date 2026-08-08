# Granger Browser UI design references

The Granger Browser component system is implemented in the project's own Qt Widgets,
HTML, CSS, and JavaScript. No source code, package, runtime dependency, icon,
font, trademarked artwork, or remote asset was copied from the projects below.
They were reviewed only for public interaction and accessibility patterns.

## Reviewed references

| Reference | Patterns reviewed | Upstream license |
| --- | --- | --- |
| shadcn/ui | Dialog, select, checkbox, menu spacing and visual hierarchy | MIT |
| Radix Primitives | Focus management, keyboard navigation, typeahead, dismissal, and popup collision behavior | MIT |
| HyperUI | Compact settings forms and empty-state structure | MIT |
| Flowbite | Form grouping and modal hierarchy | MIT for open-source code; documentation is CC BY 3.0 |

Upstream sources:

- https://ui.shadcn.com/docs
- https://github.com/shadcn-ui/ui/blob/main/LICENSE.md
- https://www.radix-ui.com/primitives/docs/overview/accessibility
- https://github.com/radix-ui/primitives/blob/main/LICENSE
- https://hyperui.dev/components/application/
- https://github.com/markmead/hyperui/blob/main/LICENSE
- https://flowbite.com/docs/getting-started/license/

## Granger Browser implementation

The following pieces are original Granger Browser implementations:

- native Qt Create menu and container editor dialog;
- local color palette and local icon picker;
- Settings custom select behavior and keyboard model;
- container row action popovers;
- design tokens, native QSS, internal-page CSS, and reduced-motion rules;
- viewport clamping, focus restoration, and dialog validation logic.

Because no upstream component source was copied, no upstream attribution is
required by the MIT licenses. This document is included in the packaged
`licenses` directory as a transparent engineering record.
