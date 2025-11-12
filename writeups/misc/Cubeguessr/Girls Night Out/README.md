# 🔥 Cubeguessr 🔥
**Author:** null

## Description
```
I heard normal Geoguessr has turned too easy. After all, it is the same old world every time that we all have visited before. I heard that if you get a 5k score there might also be a flag or something.
```
**Category:** 'Misc

**Write-Up Author:** SirAlexiner

**Final Flag:**

```
EPT{5000_p0in7s_y3t_s7il1_n0_di4mond5?_smh}
```

---

## 🧠 Challenge Summary

In **CubeGuessr**, players were spawned in a random Minecraft world and tasked with locating the **exact coordinates** they spawned on. The world spanned the coordinates **±30,000,000**, corresponding to a **radius of 1,875,000 chunks** around (0, 0).

The server website allowed players to select Minecraft versions (ranging from **1.7 through 1.21.8**) and to configure **render distance (1–10)**.
For the exploit, setting **render distance to 1** was important — it made the server only send **one chunk packet per round**, meaning the received chunk was precisely the one that needed to be identified.

Although the server offered modern versions, the relevant **bedrock pattern vulnerability** targeted by classic base-finders applies **mostly** to **Minecraft 1.12–1.17** — these versions share deterministic bedrock-generation behavior at the top Y-level (Y=4), which allows pattern-based coordinate recovery/extraction.

Each game consisted of **five rounds**, and players were scored based on how accurately they pinpointed the correct location:

* A **perfectly correct coordinates guess** (distance **0** from the exact block where you spawned) awarded **5001 points** — this yields an extra point above a "chunk-correct" guess.
* A guess that lands anywhere **inside the correct chunk** (i.e., correct chunk but not exact block) yields **5000 points**.
* Therefore the theoretical maximum (if all five rounds hit the exact coordinates) is **25,005 points**. Practical exploitation usually yielded 25,001 for perfect-chunk + offset method, while targeted bedrock-searching should reach 25,005.

---

## 🔍 Core Exploit Concept

Minecraft’s **bedrock generation pattern at Y=4** (in the affected versions) is deterministic given a seed and chunk coordinates. That means the 16×16 bedrock layout of a chunk can act as a fingerprint: if you can reconstruct that pattern, you can run a pattern search across chunk coordinates to find the chunk location.

Two complementary attack strategies were used:

* **Bedrock pattern search**: reconstruct the chunk’s Y=4 pattern and brute-force-search it across the world generation space — accurate enough to produce **exact chunk coordinate**, using additional `position` data we can match the exact coordinates (5001 points).
* **Offset exploit**: use server-sent position updates that occur *immediately after a submitResponse* to compute the next chunk from the previous correct chunk plus an offset — this method is faster and stable and reliably yields **5000 points** per round.

---

## 🧩 Data Extraction and Parsing

The server sent raw chunk payloads over a websocket. We deliberately **selected Minecraft 1.12** for exploitation, so the chunk payloads were in the 1.12-style format (palette + packed longs).

I wrote a custom parser (`minecraft_chunk_parser.py`) because no readily available tool parsed that exact JSONL/websocket chunk representation sent by the server.

Key points:

* The website’s **render distance** setting (1–10) mattered: setting it to **1** ensured the server sent exactly one `loadChunk` packet per round — the chunk we needed — instead of many chunks that would complicate selection.
* The parser decodes section palettes and the packed `long` block data (custom unpacking logic tuned to the 1.12 format).
* In our captured chunk payloads, **bedrock** was mapped to **palette index 112** (determined experimentally by plotting block IDs with Matplotlib and checking Y layers). Note: palette IDs are local, so the parser accepts a `target_block_id` argument to select the block to treat as bedrock.
* The parser writes a 16×16 pattern file (binary grid) representing `1` for bedrock and `0` otherwise. Example output format (see [example.txt](example.txt)):

  ```
  16 16
  1 0 0 0 ... 0
  ...
  ```

Standalone usage (Copy to new file):

```python
from minecraft_chunk_parser import MinecraftChunkParser

MinecraftChunkParser.generate_pattern_file(
    "chunk_data.jsonl",
    target_block_id=112,
    layer_y=4,
    output_dir="./"
)
```

---

## ⚙️ Bedrock Pattern Searching

I adapted and simplified the bedrock pattern search logic (based on ChromeCrusher / LuxXx work) and implemented two executables:

### `bedrock` (CPU, OpenMP)

* Written in C (`bedrock.c`)
* Parallelized with **OpenMP** and exits on the first match
* Compile:

  ```bash
  gcc bedrock.c -O3 -fopenmp -o bedrock
  ```
* Works on any reasonably modern CPU; still slow for a full 1,875,000 chunk radius (took **>1.5 hours** on an AMD Ryzen 7 5800H in my tests).

### `bedrock_cuda` (GPU, CUDA)

* Ported core search into CUDA (`.cu`) for massive parallelism on Nvidia GPUs
* Highly recommended if you need to search the entire radius: **~10–12 minutes** on an NVIDIA RTX 3060 Laptop GPU versus >1.5 hours on CPU.
* The code was written for my 3060 laptop; other GPUs might require minor tweaks.

The CPU and GPU code reproduces the seed advances and comparisons per chunk cell exactly as in the original code from ChromeCrusher / LuxXx. The output format of both executables is the same and is parsed by the Python bootstrap `CubeGuessr.py`.

---

## 🧭 Offset Exploit — The Fast Path

A smart observation shared by **bludsoe** (Discord) was that immediately after submitting a guess, the websocket sends a **position update containing an offset**. Using that offset:

```
next_chunk_x = previous_correct_chunk_x + offset_x
next_chunk_z = previous_correct_chunk_z + offset_z
```

When the first round’s chunk is correctly identified (via bedrock search), subsequent rounds can be solved using only these offsets — no additional heavy searches required. In short:

* Bedrock search for round 1 to get a base chunk.
* For rounds 2–5, read the first `position` message after `submitResponse` and apply it to the previously known correct chunk coordinates.
* This yields near-perfect predictions: Exact enough to guarantee **5000 points** per offset-exploited round.

The bootstrap `CubeGuessr.py` defaults to the offset method for practical speed and stability. Full bedrock searches are still supported and necessary if aiming for the extra per-round +1 (5001) to reach the maximum of **25,005**.

---

## 🔄 Solver Pipeline (`CubeGuessr.py`)

High-level flow implemented in `CubeGuessr.py`:

* Server must be started and in a game with the version set to **1.12** and render distance set to **1**.

1. **Connect** via Socket.IO to the challenge server.
2. **Listen** for events:

   * `loadChunk` → capture chunk payload to `chunk_data.jsonl`
   * `position` → receive in-chunk coordinates (0–16) and offset messages
   * `submitResponse` → get confirmation/correct coordinates and offsets
3. **Parse chunk** with `MinecraftChunkParser.generate_pattern_file(...)` to produce a `pattern_chunk_X_Z.txt`.
4. **Run bedrock searcher** (CPU or GPU) with the generated pattern file:

   ```bash
   ./bedrock_cuda pattern_chunk_X_Z.txt
   ```

   The solver reads stdout and extracts `(world_x, world_z)` when found.
5. **Combine**: If an in-chunk position (x,z within 0..16) is received, combine it with the base chunk world coordinates to produce the exact block coordinates to submit.
6. **Submit** via Socket.IO (interactive confirmation by default).
7. **Offset method**: On `submitResponse`, record the correct coordinates and on the next `position` event apply the offset to compute the next round’s guess (fast; default mode).

Important implementation notes:

* `CubeGuessr.py` defaults to `use_bedrock_for_all_rounds=False` (offset method) — change to `True` to force bedrock search every round.
* It stores debug artifacts: `chunk_data.jsonl`, `pattern_chunk_<x>_<z>.txt`, and `bedrock_debug_output.json`.
* The parser expects the chunk data JSONL/websocket format observed in the challenge; different server encodings may require minor adjustments.

To fully automate the bootstrap solver pipeline:

Pipe the `yes` command in with the python command to automatically confirm the coordinates found from bedrock search or the offset method to be submitted:
```bash
yes | python3 ./CubeGuessr.py
```

---

## 🧪 Practical Tips & Gotchas

* **Render distance = 1**: set on the website UI to limit the server to sending exactly one chunk per round (makes the loadChunk you receive the correct target chunk).
* **Version selection**: the site allowed a wide range (1.7 → 1.21.8) but the bedrock pattern vulnerability exploited applies to **1.12–1.17** — target those when possible. For this write-up the chunk payloads were intentionally captured in **1.12** format.
* **Palette IDs are local**: the parser is configurable for `target_block_id` because the palette index for bedrock varies with the chunk packet’s palette. Confirm with a quick visual check (Matplotlib) if uncertain.
* **Biome caveats**: some biome generation overrides cause the bedrock fingerprint method to fail for specific biome types (see [TerrainFinder](https://github.com/DaMatrix/TerrainFinder) notes). The bedrock approach is not 100% reliable on all biome variants.
* **GPU portability**: `bedrock_cuda` would require recompilation to match a different compute capability or driver setup.
* **Network reliability**: the socket sometimes disconnected; the solver is resilient (reconnect loop), but slow repeated CPU searches increase the chances of the socket dropping — prefer offset method where possible.

---

## 🧩 Files Overview

| File                          | Description                                                                    |
| ----------------------------- | ------------------------------------------------------------------------------ |
| **CubeGuessr.py**             | Main solver handling server connection, round logic, and exploit orchestration |
| **minecraft_chunk_parser.py** | Chunk parser and pattern generator for Y=4 bedrock extraction                  |
| **bedrock.c**                 | CPU bedrock pattern searcher (OpenMP) — compiles with `-fopenmp`               |
| **bedrock_cuda.cu**              | GPU-accelerated searcher (CUDA) — compile args specific to hardware      |                                             |
| **example.txt**       | Example extracted 16×16 bedrock pattern files                                          |                                     |                                   |

---

## 🏁 Final Result

Using the combined approach of a **first-round bedrock fingerprint** and **subsequent offset exploitation**, I reliably scored the five rounds and recovered the flag:

```
EPT{5000_p0in7s_y3t_s7il1_n0_di4mond5?_smh}
```
---

## 🙏 Acknowledgements:

    ChromeCrusher — Original bedrock pattern search algorithm used for base-finding on 2b2t.

    LuxXx — Simplified and documented the algorithm in a public gist, which formed the foundation for the search implementation.

    DaMatrix — Creator of TerrainFinder, whose notes clarified biome-specific limitations of bedrock pattern matching.

    Bludsoe — Identified the websocket offset exploit behavior that drastically improved round performance and reliability.

    EPT CTF Organizers — For designing a creative and technically rich challenge blending Minecraft internals with reverse engineering, and hosting the CTF.

