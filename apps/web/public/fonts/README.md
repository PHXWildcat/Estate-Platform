# Instrument Sans (self-hosted)

Variable font, weight axis 400–700, split into the standard latin / latin-ext
unicode-range subsets. Licensed under the SIL Open Font License 1.1 (`OFL.txt`);
copyright The Instrument Sans Project Authors
(https://github.com/Instrument/instrument-sans).

Files are the v4 woff2 subsets as served by Google Fonts
(`fonts.googleapis.com/css2?family=Instrument+Sans:wght@400..700`), vendored so
builds and page loads make no third-party font requests — same posture as every
other external dependency here: pinned, reviewable, no runtime CDN.

`@font-face` declarations (including the matching `unicode-range` values) live
in `src/app/globals.css`. To update: re-fetch the css2 response, replace these
files, and keep the ranges in sync.
