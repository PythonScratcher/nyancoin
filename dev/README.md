# Source files (for maintainers)

The five programs in the main folder are **generated** from these files, so that every program carries an
identical copy of the shared consensus rules (and its rules-lock fingerprint).

| File | Becomes |
|---|---|
| `nyancore.py` | the locked "SHARED RULES" section copied into every program |
| `node.py`, `miner.py`, `wallet.py` | each program's own code |
| `gui.py`, `gui_miner_src.py` | the windows added on top of `wallet.py` / `miner.py` to make `gui_wallet.py` / `gui_miner.py` |

Edit these, then run:

```bash
python3 dev/build.py
```

It rewrites `node.py`, `miner.py`, `wallet.py`, `gui_wallet.py` and `gui_miner.py` in the main folder and
recomputes the rules-lock fingerprints. Don't edit the generated files by hand: editing their SHARED RULES
section makes them refuse to start. Changing anything in `nyancore.py` changes consensus, so every node,
miner and wallet must update together (bump `CHAIN_ID` for incompatible changes).
