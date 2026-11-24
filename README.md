# Ailunce HD2 — Unlock & Firmware Reverse Engineering

Independent reverse-engineering notes for the **Ailunce HD2 (V3)** DMR handheld, with two
practical, verified fixes. **No vendor firmware, CPS binaries, or decryption keys are
included** — this is original analysis only. For interoperability / repair / research.

Verified on firmware **V3 3.1.9.008**.

---

## 🔧 Start here

### 1. [UNLOCK.md](UNLOCK.md) — open the TX frequency range
The HD2 ships transmit-locked to the ham sub-bands (VHF 144–146, UHF 430–440) and throws
**"TX error"** on GMRS / MURS / business / out-of-band frequencies. There's a hidden keypad
menu to open it:

> Power **OFF** → hold **PTT + 8** and power **ON** → password **`777888`** → choose
> **Extend** → set TX **136–174 / 400–520** → **Menu** to save.

(The old "Menu+8/Menu+6" community guide is wrong for the HD2 — it's **PTT+8 / PTT+6**.
Note: a CPS write re-locks it; see UNLOCK.md.)

### 2. [BEEP.md](BEEP.md) — remove the power-on tone
The startup chime is a **pure-sine** 3-note tone (~782 / 660 / 2078 Hz). It comes from the
sine-table engine, not the PWM beep engine — so a tiny 4-byte patch silences it while
keeping normal key/talk-permit beeps.

---

## The one fact that unlocks everything

**The HD2 CPU is a C-SKY CK803S core, not ARM.** It lives in a Hongruan HR_C7000 /
Dahua DH4570 SoC (firmware ELF name `dh4570_ucos.elf`, µC/OS). The stock app image reads as
garbage under ARM and cleanly as C-SKY. Same SoC family as the Baofeng DM-32UV, which
RadioFoundry has reversed in depth.

| Thing | Value |
|---|---|
| CPU core | **C-SKY CK803S**, little-endian, mixed 16/32-bit ISA (CSKYv2) |
| SoC | Hongruan HR_C7000 / Dahua DH4570, µC/OS |
| DMR baseband | integrated; RF = RDA1846S; FM = RDA5807 |
| **HD2 V3 App.bin image base** | **`0x0300D000`** |
| Sine table | `0x30997CC` (only reader = the sine tone engine) |
| Boot splash | RGB565 160×128 at App.bin offset **`0xA275E`** |

## Tooling (macOS Apple Silicon)

C-SKY disassembler in Ghidra:
- Module: [`github.com/awkaplan/ghidra_csky`](https://github.com/awkaplan/ghidra_csky)
  (CK803S-tuned fork of `leommxj/ghidra_csky`). Language ID `CSKY_V2:LE:32:default`.
- Drop `CSKY/` into `$GHIDRA/Ghidra/Processors/`, run `sleigh` on `csky_v2.slaspec`,
  Ghidra 12.x + JDK 21+. Capstone/LLVM have no C-SKY. Its decompiler is partial — rely on
  the disassembly listing.
- **Load gotcha:** `-loader-baseAddr` does not relocate. Load at default base and call
  `setImageBase(0x0300D000, true)` in a *preScript* before analysis (see
  `ghidra_scripts/SetBase.java`), or the absolute pointer tables dangle and most functions
  are missed. Correct load ≈ 1335 functions.

`ghidra_scripts/` are the headless analysis scripts used along the way (disassembly,
function-ref tracing, beep-subsystem mapping, etc.).

## Method notes (useful if you revisit)

- **Frequencies aren't stored as Hz.** TX band edges and tone pitches are phase/timer ticks
  or parsed from region strings — searching the image for `14400000` (144 MHz in 10 Hz
  units) or for an audio pitch in Hz finds nothing. Trace structurally instead.
- **Identify a tone by measuring it.** The power-on chime was pinned by recording the radio
  and running an FFT + harmonic analysis: *pure sine → sine engine*, which separated it from
  the PWM beeps that earlier patches kept hitting.
- **Region lock breadcrumbs:** firmware strings `SST Password(Extend)` / `(IARUx)`,
  `SaleRegion[0/1]=%x`, `Tx_freq IARU_Region=%d %d, f=%d, ret=%d`, the IARU/Extend region
  string table, and the boot-combo labels `KEY_COM_PTT_8` / `KEY_COM_PTT_6` /
  `KEY_COM_MENU_EXIT`.

## References
- Ghidra C-SKY module: https://github.com/awkaplan/ghidra_csky
- DM-32UV RE corpus (same SoC): https://github.com/awkaplan/dm32uv-re

## Legal / disclaimer

Reverse engineering for interoperability and repair. **No copyrighted firmware is
distributed here.** Modifying TX limits can allow operation outside the bands the radio is
type-accepted for — that may be illegal in your jurisdiction and is your responsibility.
Everything here is provided as-is, with no warranty; flashing firmware can brick a radio.
Not affiliated with Ailunce, Retevis, or the SoC vendors.
