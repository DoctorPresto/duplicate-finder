from __future__ import annotations

import os
import sys
import math
import time
import threading
import csv
import hashlib
import importlib.util
import shutil
import subprocess
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

REQUIRED = [("PIL", "Pillow"), ("imagehash", "ImageHash"), ("send2trash", "send2trash"), ("ttkbootstrap", "ttkbootstrap"), ]


def ensure_dependencies():
    missing = [pkg for mod, pkg in REQUIRED if importlib.util.find_spec(mod) is None]
    if not missing:
        return

    # Stdlib-only path so this runs before any third-party import. tkinter ships
    # with CPython on all major platforms; if it is unavailable or no display is
    # attached we degrade to stderr so the user at least gets a hint.
    try:
        import tkinter as _tk
        from tkinter import ttk as _ttk
    except ImportError:
        print(f"Missing dependencies: {', '.join(missing)}", file=sys.stderr)
        print(f"tkinter unavailable; install manually: pip install {' '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    try:
        root = _tk.Tk()
    except _tk.TclError as e:
        print(f"Missing dependencies: {', '.join(missing)}", file=sys.stderr)
        print(f"No display ({e}); install manually: pip install {' '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    root.title("Install dependencies")
    root.resizable(False, False)

    state = {"installed": False, "cancelled": False}

    body = _tk.Frame(root, padx=24, pady=20)
    body.pack()
    _tk.Label(body, text="The following Python packages are required:", anchor="w").pack(fill="x")
    _tk.Label(body, text="\n".join(f"  • {p}" for p in missing),
              anchor="w", justify="left",
              font=("TkDefaultFont", 10, "bold")).pack(fill="x", pady=(8, 12))
    _tk.Label(body, text="Install them now via pip?", anchor="w").pack(fill="x")

    status = _tk.Label(body, text="", anchor="w", justify="left", fg="#666",
                       wraplength=360)
    status.pack(fill="x", pady=(12, 4))
    pbar = _ttk.Progressbar(body, mode="indeterminate", length=360)

    btns = _tk.Frame(root, padx=24)
    btns.pack(fill="x", pady=(0, 20))

    def on_install_failure(msg: str):
        pbar.stop()
        pbar.pack_forget()
        status.config(text=f"Install failed:\n{msg}", fg="#a00")
        cancel_btn.config(text="Close", state="normal", command=root.destroy)
        root.protocol("WM_DELETE_WINDOW", root.destroy)

    def do_install():
        install_btn.config(state="disabled")
        cancel_btn.config(state="disabled")
        # Suppress window-close during install so the worker thread cannot
        # post callbacks to a destroyed root.
        root.protocol("WM_DELETE_WINDOW", lambda: None)
        status.config(text="Installing… this may take a minute.")
        pbar.pack(fill="x", pady=(8, 0))
        pbar.start(12)

        def worker():
            try:
                proc = subprocess.run(
                    [sys.executable, "-m", "pip", "install", *missing],
                    capture_output=True, text=True,
                )
                if proc.returncode == 0:
                    state["installed"] = True
                    root.after(0, root.destroy)
                else:
                    tail = (proc.stderr or proc.stdout or "pip returned non-zero").strip().splitlines()
                    err_text = "\n".join(tail[-6:])[:600]
                    root.after(0, lambda: on_install_failure(err_text))
            except Exception as e:
                root.after(0, lambda: on_install_failure(str(e)))

        threading.Thread(target=worker, daemon=True).start()

    def do_cancel():
        state["cancelled"] = True
        root.destroy()

    install_btn = _tk.Button(btns, text="Install", command=do_install, width=12, default="active")
    install_btn.pack(side="right", padx=(8, 0))
    cancel_btn = _tk.Button(btns, text="Cancel", command=do_cancel, width=12)
    cancel_btn.pack(side="right")

    root.protocol("WM_DELETE_WINDOW", do_cancel)
    root.bind("<Return>", lambda e: do_install())
    root.bind("<Escape>", lambda e: do_cancel())

    root.update_idletasks()
    w, h = root.winfo_width(), root.winfo_height()
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    root.geometry(f"+{max(0, (sw - w) // 2)}+{max(0, (sh - h) // 3)}")
    install_btn.focus_set()

    root.mainloop()

    if not state["installed"]:
        sys.exit(0 if state["cancelled"] else 1)

    # Relaunch via a fresh subprocess so newly-installed modules are picked up
    # by a clean interpreter. Avoids os.execv quirks on Windows (console
    # detachment, argv quoting) and behaves identically across platforms.
    subprocess.Popen([sys.executable, *sys.argv])
    sys.exit(0)


ensure_dependencies()
#  Theme 
try:
    import ttkbootstrap as ttkb
    from ttkbootstrap.constants import *
    from ttkbootstrap.dialogs import Messagebox
    TKMOD = "ttkbootstrap"
except Exception:
    ttkb = None
    TKMOD = "tk"

import tkinter as tk
from tkinter import ttk, filedialog
from tkinter import messagebox as tk_messagebox

#  Imaging / hashing / safe delete 
from PIL import Image, ImageFile, ImageTk, ImageOps
ImageFile.LOAD_TRUNCATED_IMAGES = True

# Explicit cap: legitimate high-res photography decodes,
# but Pillow still raises DecompressionBombError at 2x this for malicious inputs.
Image.MAX_IMAGE_PIXELS = 256_000_000
warnings.simplefilter("ignore", Image.DecompressionBombWarning)

try:
    import pillow_heif
    pillow_heif.register_heif_opener()
except Exception:
    pass

try:
    import imagehash
except Exception as e:
    raise SystemExit("Missing dependency: imagehash. Install with `pip install imagehash pillow`.") from e

try:
    from send2trash import send2trash
except Exception:
    send2trash = None  

# Config 
IMAGE_EXTS = {
    ".jpg", ".jpeg", ".png", ".bmp", ".gif", ".tif", ".tiff",
    ".webp", ".jfif", ".pjpeg", ".pjp", ".avif", ".heic", ".heif"
}
DEFAULT_HASH_ALGO = "phash"   # 'ahash','dhash','phash','whash','colorhash'
DEFAULT_HASH_SIZE = 16
DEFAULT_THRESHOLD = 5
DUPES_DIR_NAME = "dupes"
MAX_DECODE_PIXELS = 256_000_000
DRAFT_FORMATS = {"JPEG", "MPO", "JPEG2000"}
PREVIEW_DRAFT_TARGET = (1280, 1280)
PREVIEW_DEBOUNCE_MS = 80
TREE_INSERT_BUDGET = 200
EXIF_ORIENTATION_TAG = 0x0112


def _draft_decode(im: Image.Image, size: tuple) -> None:
    """Hint the underlying decoder to deliver a pre-downsampled image.

    For the JPEG family this triggers IDCT scaling (1/2, 1/4, 1/8) during decode,
    dramatically faster than full-resolution decode followed by resize. Pillow
    picks the smallest natural scale that still fits the requested size, so it
    is safe to call unconditionally — small sources stay full-resolution. No-op
    on formats that do not implement draft().
    """
    if im.format in DRAFT_FORMATS:
        try:
            im.draft(None, size)
        except Exception:
            pass

# Data 
@dataclass
class ImageRecord:
    path: Path
    size_bytes: int
    mtime: float
    width: int
    height: int
    hash_str: str
    group_id: Optional[int] = None
    marked_for_delete: bool = False

    @property
    def resolution_str(self) -> str:
        return f"{self.width}×{self.height}"

    @property
    def size_mb(self) -> float:
        return self.size_bytes / (1024 * 1024)

# Hashing 
class HashEngine:
    def __init__(self, algo: str = DEFAULT_HASH_ALGO, hash_size: int = DEFAULT_HASH_SIZE):
        self.algo = algo.lower()
        self.hash_size = hash_size

    def compute(self, img: Image.Image) -> str:
        a = self.algo
        if a == "ahash":
            h = imagehash.average_hash(img, hash_size=self.hash_size)
        elif a == "dhash":
            h = imagehash.dhash(img, hash_size=self.hash_size)
        elif a == "phash":
            h = imagehash.phash(img, hash_size=self.hash_size)
        elif a == "whash":
            h = imagehash.whash(img, hash_size=self.hash_size)
        elif a == "colorhash":
            binbits = max(3, min(8, int(round(math.log2(self.hash_size)))))
            h = imagehash.colorhash(img, binbits=binbits)
        else:
            h = imagehash.phash(img, hash_size=self.hash_size)
        return str(h)

    @staticmethod
    def hamming_distance(h1: str, h2: str) -> int:
        return imagehash.hex_to_hash(h1) - imagehash.hex_to_hash(h2)

# Grouping 
class DupeGrouper:
    def __init__(self, threshold: int):
        self.threshold = max(0, threshold)

    def build_groups(self, records: List[ImageRecord]) -> Dict[int, List[int]]:
        """Group records by Hamming distance using multi-index hashing.

        Each hash is partitioned into (threshold + 1) contiguous chunks. By the
        pigeonhole principle, any two hashes within Hamming distance `threshold`
        must agree on at least one chunk, so a pair colliding on any chunk index
        becomes a candidate that we verify with the full Hamming distance. This
        yields 100% recall (no false negatives) while still pruning candidates
        aggressively versus a brute-force O(n^2) scan.

        Equal-size partitions are not required for the pigeonhole argument; any
        partition of the bit positions works. We split hex characters for
        simplicity, distributing any remainder across the leading chunks.
        """
        n = len(records)
        if n < 2:
            return {}

        threshold = self.threshold
        num_chunks = threshold + 1
        hash_len = len(records[0].hash_str)
        base, rem = divmod(hash_len, num_chunks)
        boundaries: List[Tuple[int, int]] = []
        pos = 0
        for k in range(num_chunks):
            length = base + (1 if k < rem else 0)
            boundaries.append((pos, pos + length))
            pos += length

        indexes: List[Dict[str, List[int]]] = [defaultdict(list) for _ in range(num_chunks)]
        for idx, rec in enumerate(records):
            h = rec.hash_str
            for k, (s, e) in enumerate(boundaries):
                indexes[k][h[s:e]].append(idx)

        parent = list(range(n))
        size = [1] * n
        def find(i: int) -> int:
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i
        def union(a: int, b: int):
            ra, rb = find(a), find(b)
            if ra == rb:
                return
            if size[ra] < size[rb]:
                ra, rb = rb, ra
            parent[rb] = ra
            size[ra] += size[rb]

        for idx_map in indexes:
            for bucket in idx_map.values():
                m = len(bucket)
                if m < 2:
                    continue
                for i in range(m - 1):
                    ai = bucket[i]
                    hi = records[ai].hash_str
                    for j in range(i + 1, m):
                        aj = bucket[j]
                        # If already merged via an earlier chunk match, skip the
                        # Hamming computation entirely.
                        if find(ai) == find(aj):
                            continue
                        if HashEngine.hamming_distance(hi, records[aj].hash_str) <= threshold:
                            union(ai, aj)

        groups: Dict[int, List[int]] = {}
        for idx in range(n):
            root = find(idx)
            groups.setdefault(root, []).append(idx)
        return {gid: ms for gid, ms in groups.items() if len(ms) > 1}

# Scanning 
class ImageScanner:
    def __init__(self, engine: HashEngine, stop_event: threading.Event):
        self.engine = engine
        self.stop_event = stop_event

    def scan_folder(self, root: Path, progress_cb=None, exact_only: bool = False) -> List[ImageRecord]:
        files = self._collect_files(root)
        files.sort(key=lambda t: t[1])

        workers = max(4, (os.cpu_count() or 4))

        # Partition by file size. Two files of different sizes cannot be
        # byte-identical, so only size-shared files are candidates for the
        # SHA-256 cluster pass. The size data is already in hand from scandir.
        size_groups: Dict[int, List[Tuple[Path, int, float]]] = defaultdict(list)
        for fi in files:
            size_groups[fi[1]].append(fi)
        unique_size_files: List[Tuple[Path, int, float]] = []
        shared_size_files: List[Tuple[Path, int, float]] = []
        for lst in size_groups.values():
            (unique_size_files if len(lst) == 1 else shared_size_files).extend(lst)

        # Phase 1: SHA-256 on size-shared files only. A content hash is several
        # times cheaper than a full image decode + perceptual hash, so collapsing
        # byte-identical files into one perceptual-hash representative is a net
        # win whenever the duplicate density is above a few percent.
        sha_by_path: Dict[Path, str] = {}
        if shared_size_files:
            total = len(shared_size_files)
            ex = ThreadPoolExecutor(max_workers=workers)
            futures = {ex.submit(self._content_hash_one, fi): fi for fi in shared_size_files}
            try:
                done = 0
                for fut in as_completed(futures):
                    if self.stop_event.is_set():
                        break
                    fi = futures[fut]
                    try:
                        digest = fut.result()
                    except Exception:
                        digest = None
                    if digest is not None:
                        sha_by_path[fi[0]] = digest
                    done += 1
                    if progress_cb:
                        progress_cb(done, total, "content")
            finally:
                ex.shutdown(wait=True, cancel_futures=True)

        if self.stop_event.is_set():
            return []

        # Cluster size-shared files by content. Each (size, sha256) bucket is
        # either a single file (unique content that happens to share size with
        # something else) or a set of byte-identical files. Pick the first
        # member of each bucket as the perceptual-hash representative; the rest
        # will inherit the rep's hash, width, and height.
        clusters: Dict[Tuple[int, str], List[Tuple[Path, int, float]]] = defaultdict(list)
        for fi in shared_size_files:
            sha = sha_by_path.get(fi[0])
            if sha is None:
                continue
            clusters[(fi[1], sha)].append(fi)

        # Exact-only mode: skip perceptual hashing entirely. Only multi-member
        # clusters can yield a duplicate group, so unique-size files and
        # single-member clusters drop out of the result set.
        if exact_only:
            return self._build_exact_records(clusters, sha_by_path, progress_cb, workers)

        cluster_reps = [members[0] for members in clusters.values()]

        # Phase 2: perceptual hash on the much-reduced target set: every
        # unique-size file plus one rep per content cluster.
        phash_targets = unique_size_files + cluster_reps
        rep_records: Dict[Path, ImageRecord] = {}
        if phash_targets:
            total = len(phash_targets)
            ex = ThreadPoolExecutor(max_workers=workers)
            futures = [ex.submit(self._hash_one, fi) for fi in phash_targets]
            try:
                for i, fut in enumerate(as_completed(futures), 1):
                    if self.stop_event.is_set():
                        break
                    rec = fut.result()
                    if rec is not None:
                        rep_records[rec.path] = rec
                    if progress_cb:
                        progress_cb(i, total, "perceptual")
            finally:
                ex.shutdown(wait=True, cancel_futures=True)

        # Materialise final records. Unique-size files take their own record.
        # Cluster members other than the rep clone the rep's hash, width, and
        # height — byte-identical content guarantees identical image metadata.
        records: List[ImageRecord] = []
        for fi in unique_size_files:
            rec = rep_records.get(fi[0])
            if rec is not None:
                records.append(rec)
        for members in clusters.values():
            rep_path = members[0][0]
            rec = rep_records.get(rep_path)
            if rec is None:
                continue
            for fi in members:
                if fi[0] == rep_path:
                    records.append(rec)
                else:
                    records.append(ImageRecord(
                        path=fi[0], size_bytes=fi[1], mtime=fi[2],
                        width=rec.width, height=rec.height, hash_str=rec.hash_str,
                    ))
        return records

    def _build_exact_records(self, clusters, sha_by_path, progress_cb, workers) -> List[ImageRecord]:
        """Materialise records for exact-duplicate clusters without decoding.

        Only clusters with 2+ members can produce a duplicate group. Image
        dimensions are read from the file header for one rep per cluster; the
        siblings share those dimensions because they are byte-identical to
        the rep by construction.
        """
        multi_member = [m for m in clusters.values() if len(m) >= 2]
        if not multi_member:
            return []

        reps = [m[0] for m in multi_member]
        rep_dims: Dict[Path, Optional[Tuple[int, int]]] = {}
        total = len(reps)
        ex = ThreadPoolExecutor(max_workers=workers)
        futures = {ex.submit(self._read_dimensions, fi): fi for fi in reps}
        try:
            done = 0
            for fut in as_completed(futures):
                if self.stop_event.is_set():
                    break
                fi = futures[fut]
                try:
                    rep_dims[fi[0]] = fut.result()
                except Exception:
                    rep_dims[fi[0]] = None
                done += 1
                if progress_cb:
                    progress_cb(done, total, "dimensions")
        finally:
            ex.shutdown(wait=True, cancel_futures=True)

        if self.stop_event.is_set():
            return []

        records: List[ImageRecord] = []
        for members in multi_member:
            rep_path = members[0][0]
            sha = sha_by_path[rep_path]
            dims = rep_dims.get(rep_path) or (0, 0)
            w, h = dims
            for fi in members:
                records.append(ImageRecord(
                    path=fi[0], size_bytes=fi[1], mtime=fi[2],
                    width=w, height=h, hash_str=sha,
                ))
        return records

    def _read_dimensions(self, fileinfo: Tuple[Path, int, float]) -> Optional[Tuple[int, int]]:
        # Image.open is lazy: .size reads the file header without decoding any
        # pixels, so this is roughly an order of magnitude faster than a full
        # perceptual hash even before draft() kicks in.
        path = fileinfo[0]
        try:
            with Image.open(path) as im:
                return im.size
        except Exception:
            return None

    def _content_hash_one(self, fileinfo: Tuple[Path, int, float]) -> Optional[str]:
        path = fileinfo[0]
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    if self.stop_event.is_set():
                        return None
                    h.update(chunk)
        except OSError:
            return None
        return h.hexdigest()

    def _collect_files(self, root: Path) -> List[Tuple[Path, int, float]]:
        """Enumerate image files under root with size and mtime in a single pass.

        Uses an iterative os.scandir walk (avoids os.walk's recursion stack and
        its lack of DirEntry exposure). DirEntry.stat() reuses cached stat data
        from the directory read on POSIX, so we get size and mtime essentially
        for free — eliminating the second stat() that the old two-pass design
        did inside _hash_one.
        """
        out: List[Tuple[Path, int, float]] = []
        # (dir_path, prune_dupes): only prune the dupes quarantine folder at the
        # scan root, not anywhere else in the tree.
        stack: List[Tuple[str, bool]] = [(str(root), True)]
        while stack:
            if self.stop_event.is_set():
                break
            d, prune_dupes = stack.pop()
            try:
                it = os.scandir(d)
            except OSError:
                continue
            with it:
                for entry in it:
                    if self.stop_event.is_set():
                        break
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            if prune_dupes and entry.name == DUPES_DIR_NAME:
                                continue
                            stack.append((entry.path, False))
                        elif entry.is_file(follow_symlinks=False):
                            name = entry.name
                            dot = name.rfind(".")
                            if dot < 0:
                                continue
                            if name[dot:].lower() not in IMAGE_EXTS:
                                continue
                            try:
                                st = entry.stat(follow_symlinks=False)
                            except OSError:
                                continue
                            out.append((Path(entry.path), st.st_size, st.st_mtime))
                    except OSError:
                        continue
        return out

    def _hash_one(self, fileinfo: Tuple[Path, int, float]) -> Optional[ImageRecord]:
        path, size_bytes, mtime = fileinfo
        try:
            with Image.open(path) as im:
                try:
                    im.seek(0)
                except Exception:
                    pass
                width, height = im.size
                if width * height > MAX_DECODE_PIXELS:
                    print(f"Skipped (declared {width}x{height} exceeds pixel cap): {path}",
                          file=sys.stderr)
                    return None
                target = self.engine.hash_size * 8
                _draft_decode(im, (target, target))
                if im.getexif().get(EXIF_ORIENTATION_TAG, 1) != 1:
                    im = ImageOps.exif_transpose(im)
                if im.mode not in ("RGB", "L"):
                    im = im.convert("RGB")
                h = self.engine.compute(im)
            return ImageRecord(
                path=path, size_bytes=size_bytes, mtime=mtime,
                width=width, height=height, hash_str=h
            )
        except Image.DecompressionBombError:
            print(f"Skipped (decompression bomb risk): {path}", file=sys.stderr)
            return None
        except Exception:
            return None

# App 
class DuplicateFinderApp:
    def __init__(self):
        self.stop_event = threading.Event()
        self.engine = HashEngine()
        self.records: List[ImageRecord] = []
        self.groups: Dict[int, List[int]] = {}
        self.current_folder: Optional[Path] = None

        # Preview state/cache
        self._preview_pil: Optional[Image.Image] = None
        self._preview_photo: Optional[ImageTk.PhotoImage] = None
        self._preview_path: Optional[Path] = None
        self._preview_after_id: Optional[str] = None

        # Tree row mapping: iid -> record index
        self._iid_to_index: Dict[str, int] = {}
        self._populate_generation: int = 0

        if ttkb:
            self.root = ttkb.Window(themename="darkly")
            self.StyleMsg = Messagebox
        else:
            self.root = tk.Tk()
            self.StyleMsg = None
            try:
                ttk.Style().theme_use("clam")
            except Exception:
                pass

        self.root.title("Image Duplicate Finder")
        self.root.geometry("1200x720")
        self.root.minsize(960, 600)
        self._build_ui()

    def _build_ui(self):
        top = ttk.Frame(self.root, padding=10)
        top.pack(side=tk.TOP, fill=tk.X)

        self.folder_var = tk.StringVar(value="")
        self.algo_var = tk.StringVar(value=DEFAULT_HASH_ALGO)
        self.hash_size_var = tk.IntVar(value=DEFAULT_HASH_SIZE)
        self.threshold_var = tk.IntVar(value=DEFAULT_THRESHOLD)
        self.exact_only_var = tk.BooleanVar(value=False)
        self.status_var = tk.StringVar(value="Select a folder and click Scan")

        ttk.Button(top, text="📂 Select Folder", command=self.on_pick_folder).pack(side=tk.LEFT)
        ttk.Entry(top, textvariable=self.folder_var, width=60).pack(side=tk.LEFT, padx=8)

        ttk.Label(top, text="Algorithm").pack(side=tk.LEFT, padx=(12, 4))
        self.algo_combo = ttk.Combobox(top, textvariable=self.algo_var, state="readonly",
                                       values=["phash", "dhash", "ahash", "whash", "colorhash"], width=10)
        self.algo_combo.pack(side=tk.LEFT)

        ttk.Label(top, text="Hash size").pack(side=tk.LEFT, padx=(12, 4))
        self.hash_size_spin = ttk.Spinbox(top, from_=8, to=32, textvariable=self.hash_size_var, width=5)
        self.hash_size_spin.pack(side=tk.LEFT)

        ttk.Label(top, text="Threshold").pack(side=tk.LEFT, padx=(12, 4))
        self.thres_scale = ttk.Scale(top, from_=0, to=20, orient=tk.HORIZONTAL,
                                     variable=self.threshold_var, length=160)
        self.thres_scale.pack(side=tk.LEFT)

        self.exact_only_chk = ttk.Checkbutton(
            top, text="Exact only", variable=self.exact_only_var,
            command=self._on_exact_only_toggle
        )
        self.exact_only_chk.pack(side=tk.LEFT, padx=(12, 4))

        self.scan_btn = ttk.Button(top, text="▶ Scan", command=self.on_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=(12, 4))
        self.cancel_btn = ttk.Button(top, text="⏹ Cancel", command=self.on_cancel, state=tk.DISABLED)
        self.cancel_btn.pack(side=tk.LEFT)

        self.pvar = tk.DoubleVar(value=0.0)
        self.pbar = ttk.Progressbar(top, variable=self.pvar, maximum=1.0, length=200, mode="determinate")
        self.pbar.pack(side=tk.RIGHT, padx=4)

        main = ttk.Panedwindow(self.root, orient=tk.HORIZONTAL)
        main.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        left = ttk.Frame(main)
        self.tree = ttk.Treeview(
            left,
            columns=("select", "filename", "resolution", "size", "path"),
            show="tree headings", 
            selectmode="extended"
        )
        # Headings
        self.tree.heading("#0", text="Group")
        self.tree.heading("select", text="Select")
        self.tree.heading("filename", text="Filename")
        self.tree.heading("resolution", text="Resolution")
        self.tree.heading("size", text="Size (MB)")
        self.tree.heading("path", text="Path")

        # Column widths / stretch
        self.tree.column("#0", width=180, stretch=True)
        self.tree.column("select", width=70, stretch=False, anchor="center")
        self.tree.column("filename", width=260, stretch=True)
        self.tree.column("resolution", width=110, stretch=False)
        self.tree.column("size", width=90, stretch=False, anchor="e")
        self.tree.column("path", width=420, stretch=True)

        yscroll = ttk.Scrollbar(left, orient=tk.VERTICAL, command=self.tree.yview)
        xscroll = ttk.Scrollbar(left, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        left.rowconfigure(0, weight=1)
        left.columnconfigure(0, weight=1)

        right = ttk.Frame(main, padding=(10, 0, 0, 0))
        ttk.Label(right, text="Preview").pack(anchor="w")
        self.preview_canvas = tk.Canvas(right, highlightthickness=0, bg="#111", height=320)
        self.preview_canvas.pack(fill=tk.BOTH, expand=True)
        self.preview_canvas.bind("<Configure>", self._on_preview_resize)

        acts = ttk.Frame(right)
        acts.pack(fill=tk.X, pady=(10, 0))
        ttk.Button(acts, text="Select all NON-best per group", command=self.on_select_non_best).pack(fill=tk.X, pady=2)
        ttk.Button(acts, text="Toggle select for chosen rows", command=self.on_toggle_mark_selected).pack(fill=tk.X, pady=2)
        ttk.Button(acts, text="Open containing folder", command=self.on_open_folder).pack(fill=tk.X, pady=2)
        ttk.Button(acts, text="Export CSV report…", command=self.on_export_csv).pack(fill=tk.X, pady=2)

        self.move_btn = ttk.Button(right, text="Move selected to dupes subfolder",
                                   command=self.on_move_to_dupes,
                                   bootstyle="warning" if ttkb else None)
        self.move_btn.pack(fill=tk.X, pady=(12, 2))

        del_text = "Delete selected to Recycle Bin" if send2trash else "Permanently delete selected"
        self.delete_btn = ttk.Button(right, text=del_text, command=self.on_delete_marked,
                                     bootstyle="danger" if ttkb else None)
        self.delete_btn.pack(fill=tk.X, pady=(2, 2))

        status = ttk.Label(self.root, textvariable=self.status_var, anchor="w")
        status.pack(fill=tk.X, pady=(0, 6), padx=10)

        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.tree.bind("<Double-1>", self._on_tree_double_click)

        main.add(left, weight=3)
        main.add(right, weight=2)

    # Events 
    def on_pick_folder(self):
        folder = filedialog.askdirectory(title="Choose image folder")
        if folder:
            self.folder_var.set(folder)
            self.status("Ready. Click Scan.")

    def _on_exact_only_toggle(self):
        # Perceptual-mode controls are meaningless in exact-only mode; grey them
        # out to make the dependency visible rather than just ignored.
        if self.exact_only_var.get():
            self.algo_combo.config(state=tk.DISABLED)
            self.hash_size_spin.config(state=tk.DISABLED)
            self.thres_scale.config(state=tk.DISABLED)
        else:
            self.algo_combo.config(state="readonly")
            self.hash_size_spin.config(state=tk.NORMAL)
            self.thres_scale.config(state=tk.NORMAL)

    def on_scan(self):
        folder = self.folder_var.get().strip()
        if not folder:
            return self.alert("Choose a folder first.")
        p = Path(folder)
        if not p.is_dir():
            return self.alert("Folder does not exist or is not a directory.")

        self.engine = HashEngine(self.algo_var.get(), int(self.hash_size_var.get()))
        self.current_folder = p
        self.stop_event.clear()
        self.scan_btn.config(state=tk.DISABLED)
        self.move_btn.config(state=tk.DISABLED)
        self.delete_btn.config(state=tk.DISABLED)
        self.cancel_btn.config(state=tk.NORMAL)
        self.records.clear()
        self.groups.clear()
        self._clear_tree()
        self._clear_preview()
        self.status("Scanning…")

        last_ui_ts = 0.0

        def progress(i, total, phase=None):
            nonlocal last_ui_ts
            now = time.time()
            if i != total and now - last_ui_ts < 0.1:
                return
            last_ui_ts = now
            ratio = 0.0 if total == 0 else i / total
            if phase == "content":
                label = "Content hashing"
            elif phase == "perceptual":
                label = "Perceptual hashing"
            elif phase == "dimensions":
                label = "Reading dimensions"
            else:
                label = "Scanning"
            msg = f"{label}… {i}/{total} files"

            def apply():
                self.pvar.set(ratio)
                self.status(msg)
            self.root.after(0, apply)

        def worker():
            start = time.time()
            exact_only = self.exact_only_var.get()
            recs = ImageScanner(self.engine, self.stop_event).scan_folder(
                p, progress_cb=progress, exact_only=exact_only
            )
            if self.stop_event.is_set():
                def apply_cancelled():
                    self.status("Scan canceled.")
                    self._after_scan_cleanup()
                self.root.after(0, apply_cancelled)
                return

            # In exact-only mode every cluster member shares a SHA-256, so the
            # grouper must look for bit-identical hashes only.
            threshold = 0 if exact_only else int(self.threshold_var.get())
            groups_raw = DupeGrouper(threshold).build_groups(recs)
            gid = 1
            for _, members in groups_raw.items():
                for idx in members:
                    recs[idx].group_id = gid
                gid += 1

            elapsed = time.time() - start

            def apply_results():
                self.records = recs
                self.groups = {}
                for i, r in enumerate(recs):
                    if r.group_id is not None:
                        self.groups.setdefault(r.group_id, []).append(i)
                self._populate_tree()
                dfiles = sum(len(v) for v in self.groups.values())
                gcount = len(self.groups)
                mode_word = "exact duplicates" if exact_only else "duplicates"
                if gcount:
                    self.status(f"Found {gcount} groups of {mode_word} "
                                f"({dfiles} files) in {elapsed:.1f}s.")
                else:
                    self.status(f"No {mode_word} found in {elapsed:.1f}s.")
                self._after_scan_cleanup()

            self.root.after(0, apply_results)

        threading.Thread(target=worker, daemon=True).start()

    def _after_scan_cleanup(self):
        self.scan_btn.config(state=tk.NORMAL)
        self.move_btn.config(state=tk.NORMAL)
        self.delete_btn.config(state=tk.NORMAL)
        self.cancel_btn.config(state=tk.DISABLED)
        self.pvar.set(0.0)

    def on_cancel(self):
        self.stop_event.set()
        self.status("Canceling…")

    def on_toggle_mark_selected(self):
        changed = 0
        for iid in self.tree.selection():
            if self.tree.get_children(iid):  # parent (group)
                for child in self.tree.get_children(iid):
                    if child in self._iid_to_index:
                        idx = self._iid_to_index[child]
                        rec = self.records[idx]
                        rec.marked_for_delete = not rec.marked_for_delete
                        self._update_row_mark(child, rec)
                        changed += 1
            else:  # leaf
                if iid in self._iid_to_index:
                    idx = self._iid_to_index[iid]
                    rec = self.records[idx]
                    rec.marked_for_delete = not rec.marked_for_delete
                    self._update_row_mark(iid, rec)
                    changed += 1
        if changed:
            self.status(f"Toggled selection on {changed} file(s).")

    def on_select_non_best(self):
        count_marked = 0
        for _, idxs in self.groups.items():
            if not idxs:
                continue
            def score(i):
                r = self.records[i]
                return (r.width * r.height, r.size_bytes)
            best = max(idxs, key=score)
            for i in idxs:
                self.records[i].marked_for_delete = (i != best)
            count_marked += max(0, len(idxs) - 1)
        self._refresh_tree_marks()
        self.status(f"Selected {count_marked} files (kept best in each group).")

    def on_open_folder(self):
        sel = self.tree.selection()
        if not sel:
            return self.alert("Select at least one row.")
        iid = sel[0]
        if iid not in self._iid_to_index:
            children = self.tree.get_children(iid)
            if not children:
                return self.alert("No file rows under this item.")
            iid = children[0]
        idx = self._iid_to_index[iid]
        folder = self.records[idx].path.parent
        try:
            if sys.platform.startswith("win"):
                os.startfile(folder)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(folder)])
            else:
                subprocess.Popen(["xdg-open", str(folder)])
        except Exception as e:
            self.alert(f"Failed to open folder:\n{e}")

    def on_move_to_dupes(self):
        to_move = [r for r in self.records if r.marked_for_delete]
        if not to_move:
            return self.alert("No files are selected for moving.")
        if not self.current_folder:
            return self.alert("Scan a folder first.")

        dupes_dir = self.current_folder / DUPES_DIR_NAME
        if not self.confirm(
            f"Move {len(to_move)} file(s) to:\n{dupes_dir}\n\n"
            "Subfolder structure relative to the scan folder will be preserved.",
            title="Confirm move",
        ):
            return

        self.scan_btn.config(state=tk.DISABLED)
        self.move_btn.config(state=tk.DISABLED)
        self.delete_btn.config(state=tk.DISABLED)
        self.status(f"Moving {len(to_move)} file(s)…")

        def worker():
            moved, errors = self._do_move_batch(to_move, dupes_dir)
            self.root.after(0, lambda: self._post_move(moved, errors))

        threading.Thread(target=worker, daemon=True).start()

    def _do_move_batch(self, records: List[ImageRecord], dupes_dir: Path):
        """Move records into dupes_dir preserving paths relative to the scan root.

        Same-filesystem moves resolve to os.rename via shutil.move — a metadata-only
        operation regardless of file size, which keeps the batch cheap on 4K+ images.
        """
        moved: set = set()
        errors: list = []
        created_dirs: set = set()
        total = len(records)
        root_resolved = self.current_folder.resolve()
        dupes_resolved = dupes_dir.resolve()
        last_status = 0.0

        for i, rec in enumerate(records, 1):
            src = rec.path
            try:
                src_resolved = src.resolve()
                if dupes_resolved == src_resolved or dupes_resolved in src_resolved.parents:
                    errors.append((src, "already inside dupes folder"))
                    continue
                try:
                    rel = src_resolved.relative_to(root_resolved)
                except ValueError:
                    rel = Path(src.name)
                dst = dupes_dir / rel
                parent = dst.parent
                if parent not in created_dirs:
                    parent.mkdir(parents=True, exist_ok=True)
                    created_dirs.add(parent)
                if dst.exists():
                    stem, suffix = dst.stem, dst.suffix
                    k = 1
                    while True:
                        candidate = parent / f"{stem}__{k}{suffix}"
                        if not candidate.exists():
                            dst = candidate
                            break
                        k += 1
                shutil.move(str(src), str(dst))
                moved.add(src)
            except Exception as e:
                errors.append((src, str(e)))

            now = time.time()
            if now - last_status > 0.1 or i == total:
                last_status = now
                self.root.after(0, lambda i=i: self.status(f"Moving… {i}/{total}"))
        return moved, errors

    def _post_move(self, moved_paths: set, errors: list):
        if moved_paths:
            remaining: List[ImageRecord] = []
            for r in self.records:
                if r.path in moved_paths:
                    continue
                remaining.append(r)
            self.records = remaining
            new_groups: Dict[int, List[int]] = defaultdict(list)
            for i, r in enumerate(self.records):
                if r.group_id is not None:
                    new_groups[r.group_id].append(i)
            self.groups = {g: idxs for g, idxs in new_groups.items() if len(idxs) > 1}
            self._populate_tree()

        for path, err in errors:
            print(f"Move failed: {path}: {err}", file=sys.stderr)

        self.scan_btn.config(state=tk.NORMAL)
        self.move_btn.config(state=tk.NORMAL)
        self.delete_btn.config(state=tk.NORMAL)

        if errors:
            self.status(f"Moved {len(moved_paths)} file(s); {len(errors)} failed (see console).")
        else:
            self.status(f"Moved {len(moved_paths)} file(s) to dupes folder.")

    def on_delete_marked(self):
        to_delete = [r for r in self.records if r.marked_for_delete]
        if not to_delete:
            return self.alert("No files are selected for deletion.")

        if send2trash:
            msg = f"Send {len(to_delete)} file(s) to Recycle Bin?"
        else:
            msg = f"PERMANENTLY delete {len(to_delete)} file(s)? (send2trash not installed)"

        if not self.confirm(msg, title="Confirm deletion"):
            return

        errors = 0
        remaining: List[ImageRecord] = []
        for r in self.records:
            if r.marked_for_delete:
                try:
                    if send2trash:
                        send2trash(str(r.path))
                    else:
                        r.path.unlink()
                except Exception:
                    errors += 1
                continue
            remaining.append(r)
        self.records = remaining

        new_groups: Dict[int, List[int]] = {}
        for i, r in enumerate(self.records):
            if r.group_id is not None:
                new_groups.setdefault(r.group_id, []).append(i)
        self.groups = {g: idxs for g, idxs in new_groups.items() if len(idxs) > 1}
        self._populate_tree()
        self.status("Deletion complete." if errors == 0 else f"Done, {errors} file(s) failed to delete.")

    def on_export_csv(self):
        if not self.groups:
            return self.alert("Nothing to export.")
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV", "*.csv")],
                                            title="Export CSV")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Group", "SelectedForDeletion", "Filename", "Resolution", "Size_MB", "Path"])
            for rec in self.records:
                if rec.group_id is None:
                    continue
                w.writerow([rec.group_id, int(rec.marked_for_delete), rec.path.name,
                            rec.resolution_str, f"{rec.size_mb:.2f}", str(rec.path)])
        self.status(f"Exported CSV to {path}")

    # Tree helpers 
    def _clear_tree(self):
        self._iid_to_index.clear()
        for iid in self.tree.get_children():
            self.tree.delete(iid)

    def _populate_tree(self):
        """Rebuild the duplicate-group tree.

        Work is snapshotted upfront and processed in budgeted chunks scheduled
        via root.after(0, ...) so the Tk event loop stays responsive even on
        very large result sets. A generation counter short-circuits stale
        chunk callbacks when a fresh populate starts before the previous one
        has finished — e.g., a move or delete that completes mid-rebuild.
        """
        self._populate_generation += 1
        gen = self._populate_generation
        self._clear_tree()

        if not self.groups:
            self._clear_preview()
            return

        sort_key = lambda k: (self.records[k].width * self.records[k].height,
                              self.records[k].size_bytes)
        snapshot: List[Tuple[int, List[int]]] = [
            (gid, sorted(self.groups[gid], key=sort_key, reverse=True))
            for gid in sorted(self.groups.keys())
        ]
        state = {"group_idx": 0, "member_idx": 0, "parent_iid": None}
        self._populate_chunk(snapshot, state, gen)

    def _populate_chunk(self, snapshot, state, gen):
        if gen != self._populate_generation:
            return

        budget = TREE_INSERT_BUDGET
        while budget > 0 and state["group_idx"] < len(snapshot):
            gid, members = snapshot[state["group_idx"]]
            if state["parent_iid"] is None:
                state["parent_iid"] = self.tree.insert(
                    "", "end", text=f"Group {gid}  ({len(members)} files)"
                )
                budget -= 1
                continue
            while budget > 0 and state["member_idx"] < len(members):
                i = members[state["member_idx"]]
                rec = self.records[i]
                iid = self.tree.insert(
                    state["parent_iid"], "end",
                    values=(
                        "✓" if rec.marked_for_delete else "—",
                        rec.path.name,
                        rec.resolution_str,
                        f"{rec.size_mb:.2f}",
                        str(rec.path),
                    )
                )
                self._iid_to_index[iid] = i
                state["member_idx"] += 1
                budget -= 1
            if state["member_idx"] >= len(members):
                state["group_idx"] += 1
                state["member_idx"] = 0
                state["parent_iid"] = None

        if state["group_idx"] < len(snapshot):
            self.root.after(0, lambda: self._populate_chunk(snapshot, state, gen))
        else:
            # Final chunk: a stale preview (from before the rebuild) no longer
            # corresponds to a live tree row.
            self._clear_preview()

    def _update_row_mark(self, iid: str, rec: ImageRecord):
        self.tree.set(iid, "select", "✓" if rec.marked_for_delete else "—")

    def _refresh_tree_marks(self):
        for iid, idx in self._iid_to_index.items():
            self._update_row_mark(iid, self.records[idx])

    def _on_tree_select(self, _evt=None):
        # Cancel any pending decode so only the latest stable selection actually
        # runs through _show_preview. Rapid keyboard navigation (held arrow key)
        # otherwise fires this handler ~30 times per second and would queue a
        # full decode for each transient selection.
        if self._preview_after_id is not None:
            try:
                self.root.after_cancel(self._preview_after_id)
            except Exception:
                pass
            self._preview_after_id = None
        # Empty selection clears immediately — no decode work, no reason to wait.
        if not self.tree.selection():
            self._clear_preview()
            return
        self._preview_after_id = self.root.after(
            PREVIEW_DEBOUNCE_MS, self._do_preview_update
        )

    def _do_preview_update(self):
        self._preview_after_id = None
        sel = self.tree.selection()
        if not sel:
            self._clear_preview()
            return
        target = None
        for iid in sel:
            if iid in self._iid_to_index:
                target = iid
                break
        if target is None:
            self._clear_preview()
            return
        idx = self._iid_to_index[target]
        self._show_preview(self.records[idx].path)

    def _on_tree_double_click(self, evt):
        region = self.tree.identify("region", evt.x, evt.y)
        if region != "cell":
            return
        col = self.tree.identify_column(evt.x)
        row = self.tree.identify_row(evt.y)
        if not row or row not in self._iid_to_index:
            return 
        if col != "#1": 
            return
        idx = self._iid_to_index[row]
        rec = self.records[idx]
        rec.marked_for_delete = not rec.marked_for_delete
        self._update_row_mark(row, rec)

    # Preview 
    def _clear_preview(self):
        if self._preview_pil is not None:
            self._preview_pil.close()
        self._preview_pil = None
        self._preview_photo = None
        self._preview_path = None
        self.preview_canvas.delete("all")

    def _show_preview(self, path: Path):
        # Release the prior preview before loading a new one. Pillow Image
        # objects reference C-allocated pixel buffers; an explicit close keeps
        # the working set bounded when clicking through high-res files faster
        # than the GC reclaims them.
        if self._preview_pil is not None:
            self._preview_pil.close()
            self._preview_pil = None
        self._preview_path = None
        try:
            with Image.open(path) as im:
                try:
                    im.seek(0)
                except Exception:
                    pass
                width, height = im.size
                if width * height > MAX_DECODE_PIXELS:
                    self._render_preview()
                    self.status(f"Preview skipped: image too large ({width}x{height}).")
                    return
                _draft_decode(im, PREVIEW_DRAFT_TARGET)
                if im.getexif().get(EXIF_ORIENTATION_TAG, 1) != 1:
                    im = ImageOps.exif_transpose(im)
                if im.mode not in ("RGB", "RGBA", "L"):
                    im = im.convert("RGB")
                self._preview_pil = im.copy()
                self._preview_path = path
        except Image.DecompressionBombError:
            self.status(f"Preview skipped: decompression bomb risk ({path.name}).")
        except Exception:
            pass
        self._render_preview()

    def _on_preview_resize(self, _evt):
        self._render_preview()

    def _render_preview(self):
        self.preview_canvas.delete("all")
        if self._preview_pil is None:
            self.preview_canvas.create_text(
                self.preview_canvas.winfo_width() // 2,
                self.preview_canvas.winfo_height() // 2,
                text="(Preview unavailable)",
                fill="#aaa"
            )
            return
        cw = max(1, self.preview_canvas.winfo_width())
        ch = max(1, self.preview_canvas.winfo_height())
        img = self._preview_pil.copy()
        img.thumbnail((cw, ch), Image.LANCZOS)
        self._preview_photo = ImageTk.PhotoImage(img)
        img.close()
        self.preview_canvas.create_image(cw // 2, ch // 2, image=self._preview_photo, anchor="center")
        self.preview_canvas.create_rectangle(2, 2, cw - 2, ch - 2, outline="#333")

    # UX 
    def status(self, text: str):
        self.status_var.set(text)
        if hasattr(self.root, "update_idletasks"):
            self.root.update_idletasks()

    def alert(self, message: str, title: str = "Notice"):
        if self.StyleMsg:
            self.StyleMsg.show_info(message=message, title=title)
        else:
            tk_messagebox.showinfo(title, message)

    def confirm(self, message: str, title: str = "Confirm") -> bool:
        if self.StyleMsg:
            return self.StyleMsg.okcancel(message=message, title=title) == "OK"
        else:
            return tk_messagebox.askokcancel(title, message)

    def run(self):
        self.root.mainloop()

# Main 
if __name__ == "__main__":
    app = DuplicateFinderApp()
    app.run()
