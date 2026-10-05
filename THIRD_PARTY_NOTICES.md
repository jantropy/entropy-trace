# Third-party notices

Entropy Trace is released under the MIT licence (see `LICENSE`). It includes the
following material from others, each under its own terms.

## Fonts

The reports and the web app use two fonts, both under the SIL Open Font License,
Version 1.1. The full licence text is in `entropytrace/emit/fonts/`.

| Font | Copyright | Licence text |
|---|---|---|
| Bricolage Grotesque | 2022 The Bricolage Grotesque Project Authors (https://github.com/ateliertriay/bricolage) | `entropytrace/emit/fonts/OFL-BricolageGrotesque.txt` |
| Space Mono | 2016 The Space Mono Project Authors (https://github.com/googlefonts/spacemono) | `entropytrace/emit/fonts/OFL-SpaceMono.txt` |

The font files in `entropytrace/emit/fonts/` are embedded into each static report so
it opens with no network. The web app loads the same fonts from the `@fontsource`
npm packages, which carry the same licences.

## SARIF schema

`fixtures/schemas/sarif-schema-2.1.0.json` is the SARIF 2.1.0 JSON schema published
by OASIS (https://github.com/oasis-tcs/sarif-spec). The tests use it to check that the
SARIF the tool writes is valid. It is not modified.

## Dependencies

Libraries installed from `requirements.txt`, `web/api/requirements.txt` and
`web/ui/package.json` are not part of this repository and keep their own licences.
