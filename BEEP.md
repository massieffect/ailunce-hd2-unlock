# Ailunce HD2 — remove the power-on tone (startup chime)

**Verified on Ailunce HD2 V3, firmware V3 3.1.9.008.** Removes the boot "message sound"
while keeping normal key/talk-permit beeps. Reversible (reflash stock).

## What the tone actually is

The power-on chime is a **3-note sequence — ~782 Hz → ~660 Hz → ~2078 Hz, ~195 ms each**
(measured by FFT from a phone recording of the radio; the Hz values are **not** in the
binary — the firmware stores phase/timer ticks).

A harmonic analysis of that recording was the key: the notes are **pure sine** (no odd
harmonics), which proves it comes from the **sine‑table tone engine**, not the PWM
(square‑wave) engine. The HD2 has both:

- `FUN_03014140` — **PWM** square‑wave generator (buzzy). Drives key beeps, talk‑permit, etc.
- `FUN_03015224` — **sine‑table mixer** (pure tone; the only reader of the sine table at
  `0x30997cc`). `FUN_03014f58` is its sibling player. **This is what plays the chime.**

Patches aimed at the PWM engine never silenced the chime — wrong circuit.

## The patch (App.bin file offsets; firmware V3 3.1.9.008)

Make both sine tone‑players return immediately. Their prologue is `push {r4-r11}` **without
`r15`**, so an `rts` at the entry is stack‑safe (returns via the untouched link register):

| File offset | Function | Stock bytes | Patched bytes |
|---|---|---|---|
| `0x7F58` | `FUN_03014f58` | `c8 14` (`push {r4-r11}`) | `3c 78` (`rts`) |
| `0x8224` | `FUN_03015224` | `c8 14` (`push {r4-r11}`) | `3c 78` (`rts`) |

Result: **all sine tones are silenced (including the chime); PWM key/talk‑permit beeps keep
working.** If you later miss a sine‑only alert (e.g. roger/low‑battery), restore it per
beep‑type instead of muting the whole engine.

## Boot splash image (bonus)

The boot logo is a raw **RGB565 160×128** image at App.bin file offset **`0xA275E`**
(40,960 bytes). Replace those bytes with any 160×128 RGB565 encode and reflash to get a
custom boot screen. No in‑file checksum rejects the change.

## Flashing

Retevis CPS → Operation → Firmware → "Download Application to the Flash". Enter DFU first:
hold **PTT + PF1** while powering on. **Recoverable** — reflash the stock App.bin to undo,
so keep a stock copy.
