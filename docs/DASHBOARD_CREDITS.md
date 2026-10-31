# Dashboard credits

The local dashboard is server-rendered HTML from `src/a3p/dashboard.py`. The sentences, the G3 badge geometry, and the Ed25519 checks elsewhere in A3P are original. The page adapts free, open-source visual patterns. It does not vendor those React libraries, and it does not use paid or closed components.

This page is a sample view of local `results.json` files. It is not a certification, and it does not mean an agent is safe.

## Inter

Body text is Inter, the Latin subset already used by the public site (Fontsource Inter, SIL Open Font License 1.1). The files are self-hosted under `src/a3p/static/fonts/` and embedded in the page so a bearer-token request does not need a second fetch.

## Source Serif Pro

The badge level and the agent name use Source Serif Pro, Latin subset, from Fontsource (`source-serif-pro` 5.2.5), which distributes Adobe’s design. Source Serif Pro is licensed under the SIL Open Font License 1.1. The files are `source-serif-pro-400.woff2` and `source-serif-pro-600.woff2` in the same font directory.

## daisyUI

The top bar, text links, and the bordered history table follow the spacing of daisyUI 5 navbar and table patterns (MIT). Copyright Pouya Saadeghi. <https://github.com/saadeghi/daisyui>

The dashboard does not ship the daisyUI stylesheet. The markup is plain HTML.

## HyperUI

Battery scores use a bordered card: a short uppercase label and a large figure, in the spirit of the free HyperUI marketing blocks (MIT). Copyright (c) Mark Mead. <https://github.com/markmead/hyperui>

## Magic UI

Section entrance is a short upward move, the idea of Magic UI Blur Fade (MIT) without the fade or the blur. Copyright Magic UI. <https://github.com/magicuidesign/magicui>

The text starts fully opaque. A browser that skips the animation, including Safari, still shows the page. `prefers-reduced-motion: reduce` turns the move off. Numbers are plain text. There is no count-up.

## Aceternity UI

The page background is a very light radial wash in the site colours (`#1c4e6e` and the plum used on L3). It is not the Aceternity Pro Background Gradient component, and the Aceternity Pro licence was not purchased. The public registry component is credited as the reference for a soft gradient behind content: <https://ui.aceternity.com/registry/background-gradient.json>. Author: Manu Arora.

## 21st.dev and Hirael

The regression page is two columns, earlier run then later run, following Comparison 03 by Mohammad Shehadeh, MIT, Copyright (c) 2026 Mohammad Shehadeh.

- Upstream: <https://github.com/MohammadShehadeh/hirael>
- Registry: <https://hirael.com/r/comparison-03.json>
- 21st.dev lists the same block as `hirael/comparison-03` under the MIT licence

## Badge colour

G3 is a solid band in the level colour: an equilateral triangle with inward-curved sides and slightly rounded corners. A thin white line sits in the band. The centre is a white triangle of the same shape, with a thin level-colour line just inside it. Words in the band follow the three curves. L1 is slate `#5f6f7f`, L2 is blue `#1c4e6e`, L3 is plum `#5a3d6b`. L0 is not in that palette; the dashboard uses ink `#12141a` and says so on the badge page. The badge does not use green.
