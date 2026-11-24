# Ailunce HD2 — open the TX frequency range (GMRS / MURS / business / full band)

**Plain-English guide. Verified on an Ailunce HD2 V3, firmware V3 3.1.9.008.**

The HD2 **receives** 136–174 / 400–520 MHz but ships **transmit-locked to the ham
sub-bands only**: VHF **144–146**, UHF **430–440** (IARU Region 1). Key up on GMRS
(462–467), MURS (151–154), business, or even a 147 MHz ham repeater and you get
**"TX error."** The channel frequency programs fine in the CPS — the radio just vetoes
the transmit.

This is a **region / band-plan setting**, and there's a hidden menu built into the
firmware to change it.

## The regions

| Region | TX bands |
|---|---|
| IARU1 (factory default) | 144–146, 430–440 |
| IARU2 | 144–148, 420–450 |
| IARU3 | 144–148, 430–440 |
| **Extend** | **user-defined Rx/Tx — the full range** |

Only **Extend** reaches GMRS / MURS / business.

## Unlock steps (keypad — no computer needed)

1. Turn the radio **OFF**.
2. Hold the **PTT** button **and the `8` key** together, and **power ON** while holding both.
   - Tip: hold **PTT + 8 first**, then tap the power button while still holding them.
3. At **`Input Password:`** enter **`777888`**.
4. Choose **Extend**, and set the TX range wide — **VHF 136–174**, **UHF 400–520**.
5. Press **Menu** to accept each field (OK), then **Menu** again to exit.
6. Power-cycle.

The three hidden boot combos on 3.1.9 (from the firmware's own `KEY_COM_*` labels):

- **`PTT + 8`** → frequency / Extend menu (password `777888`)
- **`PTT + 6`** → IARU region select
- **`Menu + Exit`** → **Data Init = FACTORY RESET — do NOT confirm, it wipes your codeplug**

> The old community guide says "Menu+8 / Menu+6" — that's wrong for the HD2. It's
> **PTT+8 / PTT+6**. The password `654321` from older radios is not in 3.1.9; use `777888`.

## Still getting "TX error" after unlocking? Check the channel

GMRS/MURS are **analog**, so on each such channel set:

- **Channel type = Analog FM** (not Digital/DMR — a DMR GMRS channel won't work).
- **TX Admit / Admit Criteria = Always** (if it's "Inhibit" or "Channel Busy", PTT is blocked).

## Persistence

The Extend setting is stored in the radio and **persists through normal CPS writes** —
once you've unlocked, it stays unlocked (tested on 3.1.9.008). A full **Data Init** factory
reset (Menu+Exit → confirm) reverts it to the ham-only default, so just redo PTT+8 if you
ever reset.

## Legal note

The HD2 is **not FCC type-accepted** for GMRS (Part 95E), MURS (95J), or business/Part 90.
Transmitting on those services with this radio is not strictly legal even with a GMRS
license — this is a common ham modification, documented here for interoperability/research.
Know your local rules.

---
*Reverse-engineered from the stock firmware; see `README.md` for the C-SKY tooling and the
firmware breadcrumbs (`SST Password(Extend)`, `SaleRegion`, `Tx_freq IARU_Region`, region
string table). The measured TX band edges are not stored as plain Hz in the image.*
