#!/usr/bin/env python3
"""One command from docs/VIDEO-SCRIPT.md + record.spec.ts to the finished review cut (mp4 + srt). See README.md.

Steps: narration.txt -> Kokoro neural voice per scene (videos/tts/narrate.py; durations and per-sentence cues in narration.json) -> rehearsal (natural scene lengths) -> a plan that gives
every scene at least audio + MARGIN seconds -> the real recording -> ffmpeg: H.264/AAC mp4 with the narration placed at the
scene starts, plus an .srt aligned to the audio.  Everything is local; needs a throwaway UTF-8 Postgres (see README.md).
"""
import json, os, re, shutil, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
KIT = HERE.parent.parent
OUT = HERE / "out"
NAME = os.environ.get("VIDEO_NAME", "agentpg-kit")
VOICE, MARGIN = os.environ.get("VIDEO_VOICE", "af_heart"), 0.7
TTS = KIT.parent / "videos" / "tts"                          # shared narrator (Kokoro, local): narrate.py, pronounce.json, .venv, models
NARRATION = HERE / "narration.txt"
PRONOUNCE = HERE / "pronounce.json"
SCENES = list(range(1, 12))
FFMPEG = os.environ.get("FFMPEG", "/opt/homebrew/bin/ffmpeg")
FFPROBE = os.environ.get("FFPROBE", "/opt/homebrew/bin/ffprobe")


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, **kw)


def duration(f):
    return float(subprocess.check_output([FFPROBE, "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", str(f)], text=True))


def flat(body):
    """narration.txt section -> the plain text the script shows (pause markers dropped, paragraphs joined)."""
    paras, cur = [], []
    for line in body.strip().splitlines():
        t = line.strip()
        if t and t != "..." and not re.fullmatch(r"\[pause\s+[\d.]+\]", t):
            cur.append(t)
        elif cur:
            paras.append(" ".join(cur)); cur = []
    if cur:
        paras.append(" ".join(cur))
    return " ".join(paras)


def narration_texts():
    parts = re.split(r"(?m)^##[ \t]+(\S+)(?:[ \t]+(\S+))?[ \t]*$", NARRATION.read_text())     # "## <scene id> [voice]"
    return {int(k): flat(v) for k, v in zip(parts[1::3], parts[3::3])}


SCRIPT = KIT / "docs" / "VIDEO-SCRIPT.md"
SCRIPT_RE = re.compile(r'(### Scene (\d+) .*?\*\*NARRATION:\*\* ")(.*?)("\n\n)', re.S)


def check_script(write=False):
    """VIDEO-SCRIPT.md must carry exactly the narration that is spoken (narration.txt is the source)."""
    want = narration_texts()
    assert sorted(want) == SCENES, f"expected narration for scenes 1-11, got {sorted(want)}"
    text = SCRIPT.read_text()
    bad = []

    def fix(m):
        n = int(m.group(2))
        if re.sub(r"\s+", " ", m.group(3)).strip() != want[n]:
            bad.append(n)
        return m.group(1) + want[n] + m.group(4)
    new = SCRIPT_RE.sub(fix, text)
    if write:
        SCRIPT.write_text(new)
    elif bad:
        sys.exit(f"docs/VIDEO-SCRIPT.md differs from docs/video/narration.txt in scenes {bad}; run: python3 build.py --write-script")
    return want


def speak():
    """Run the shared Kokoro narrator; returns {scene: {duration, cues}} from narration.json."""
    aud = OUT / "audio"
    done = aud / "narration.json"
    if done.exists() and not os.environ.get("FORCE_TTS") and all(done.stat().st_mtime > f.stat().st_mtime for f in (NARRATION, PRONOUNCE)):
        print("narration.json is newer than narration.txt and pronounce.json: reusing the audio (FORCE_TTS=1 to speak again)")
        return {int(k): v for k, v in json.loads(done.read_text()).items()}
    shutil.rmtree(aud, ignore_errors=True)
    run([str(TTS / ".venv/bin/python"), str(TTS / "narrate.py"), "scenes", str(NARRATION), str(aud), "--voice", VOICE, "--pronounce", str(PRONOUNCE)])
    return {int(k): v for k, v in json.loads((aud / "narration.json").read_text()).items()}


def env_for_recorder():
    env = dict(os.environ)
    env.setdefault("APGKIT_REC_PG_PORT", "55432")
    # Playwright's own ffmpeg may be missing (it is a download): point it at a system ffmpeg through a private browsers dir.
    rev = next(b["revision"] for b in json.loads((HERE / "node_modules/playwright-core/browsers.json").read_text())["browsers"] if b["name"] == "ffmpeg")
    cache = Path(os.environ.get("PLAYWRIGHT_BROWSERS_PATH") or Path.home() / "Library/Caches/ms-playwright")
    if not (cache / f"ffmpeg-{rev}").exists():
        priv = OUT / "browsers"
        d = priv / f"ffmpeg-{rev}"
        d.mkdir(parents=True, exist_ok=True)
        link = d / "ffmpeg-mac"
        if not link.exists():
            link.symlink_to(FFMPEG)
        (d / "INSTALLATION_COMPLETE").touch()
        (d / "DEPENDENCIES_VALIDATED").touch()
        env["PLAYWRIGHT_BROWSERS_PATH"] = str(priv)
    return env


def playwright(env, extra):
    e = dict(env, **extra)
    run(["./node_modules/.bin/playwright", "test"], cwd=HERE, env=e)


def srt_time(t):
    ms = round(t * 1000)
    return f"{ms // 3600000:02}:{ms // 60000 % 60:02}:{ms // 1000 % 60:02},{ms % 1000:03}"


def video_lag(webm, event_t):
    """Seconds the recording's clock runs behind the recorder's clock at `event_t` (s): Playwright's video can start late under load.
    Found by locating, in the video, the first lower-third callout (its amber border) that the recorder logged at event_t."""
    lo = max(0.0, event_t - 10)
    out = subprocess.run([FFMPEG, "-v", "error", "-ss", f"{lo}", "-t", "14", "-i", str(webm), "-vf", "crop=24:40:44:975,signalstats,metadata=print:key=lavfi.signalstats.YAVG:file=-",
                          "-an", "-f", "null", "-"], capture_output=True, text=True).stdout
    pts = [float(x) for x in re.findall(r"pts_time:([\d.]+)", out)]
    ys = [float(x) for x in re.findall(r"YAVG=([\d.]+)", out)]
    for p, y in zip(pts, ys):
        if y > ys[0] + 20:
            return event_t - (lo + p)
    raise SystemExit(f"callout at {event_t:.1f}s not found in the video: cannot align the audio")


def main():
    OUT.mkdir(exist_ok=True)
    aud = OUT / "audio"
    if len(sys.argv) > 1 and sys.argv[1] == "--write-script":
        check_script(write=True)
        print("docs/VIDEO-SCRIPT.md narration updated from narration.txt")
        return
    texts = check_script()
    narr = speak()
    durs = {n: narr[n]["duration"] for n in SCENES}
    for n in SCENES:
        print(f"scene {n:2}: {len(texts[n].split()):3} words, audio {durs[n]:5.1f} s")
    need = {str(n): round(d + MARGIN, 2) for n, d in durs.items()}

    env = env_for_recorder()
    if os.environ.get("SKIP_REHEARSAL") != "1" or not (OUT / "natural.json").exists():
        print("rehearsal at human pace (no video) to measure the natural scene lengths ...")
        playwright(env, {"RECORD": "0", "REAL_PACE": "1"})
        shutil.copy(OUT / "timings.json", OUT / "natural.json")
    nat = json.loads((OUT / "natural.json").read_text())
    starts = [nat["starts"][str(n)] for n in range(1, 13)] + [nat["end"]]
    scale = {}
    for i, n in enumerate(range(1, 12)):
        length = (starts[i + 1] - starts[i]) / 1000
        p = nat["paused"].get(str(n), 0) / 1000
        fixed = max(0.0, length - p)                                # typing, output, loading: not stretchable
        # never stretch pauses (a callout must not linger): the sync() waits in the recorder hold each step for its sentence instead
        scale[str(n)] = round(min(1.0, max(0.5, (need[str(n)] + 0.4 - fixed) / p)), 3) if p else 1.0
    plan = OUT / "plan.json"
    plan.write_text(json.dumps({"need": need, "scale": scale, "cues": {str(n): [{"text": c["text"], "start": c["start"]} for c in narr[n]["cues"]] for n in SCENES}}, indent=1))
    print("pause stretch per scene:", scale)

    if os.environ.get("REUSE_VIDEO") == "1" and list((OUT / "video").glob("*.webm")):
        print("REUSE_VIDEO=1: keeping the last recording")
    else:
        shutil.rmtree(OUT / "video", ignore_errors=True)
        print("recording ...")
        playwright(env, {"APGKIT_REC_PLAN": str(plan)})
    webm = sorted((OUT / "video").glob("*.webm"))[-1]
    tim = json.loads((OUT / "timings.json").read_text())
    st = {int(k): v / 1000 for k, v in tim["starts"].items()}
    vdur = duration(webm)
    first = {n: next(e["t"] for e in tim["events"] if e["scene"] == n and e["what"].startswith("callout")) / 1000 for n in (1, 11)}
    lag0, lag1 = video_lag(webm, first[1]), video_lag(webm, first[11])
    lag = lambda t: lag0 + (lag1 - lag0) * (t - first[1]) / (first[11] - first[1])     # linear drift between the two markers
    pad = lag0 if lag0 > 0.05 else 0.0                                                   # the file started late: its first seconds (the title card) are missing
    shift = lambda t: lag(t) - pad                                                       # what is left after putting the card back in front
    print(f"video clock lags the recorder by {lag0:.2f} s at {first[1]:.0f} s and {lag1:.2f} s at {first[11]:.0f} s; title card restored for {pad:.2f} s, residual drift {lag1 - lag0:+.2f} s")
    for n in range(1, 12):
        length = st[n + 1] - st[n]
        assert length >= durs[n] + 0.5, f"scene {n} lasts {length:.1f}s, narration {durs[n]:.1f}s"

    # video offset: the recording starts when the page is created, the scene clock a moment later; the difference is < 0.3 s
    inputs, filt = [], []
    for i, n in enumerate(range(1, 12)):
        inputs += ["-i", str(aud / f"scene-{n}.wav")]
        ms = max(0, int((st[n] - shift(st[n])) * 1000) + 150)
        filt.append(f"[{i + 1}:a]aresample=44100,adelay={ms}|{ms}[a{i}]")
    mix = "".join(f"[a{i}]" for i in range(11)) + "amix=inputs=11:normalize=0,apad[aout]"
    final = OUT / f"{NAME}.mp4"
    vf = "scale=out_range=tv,format=yuv420p"
    head, vin = [], "0:v"
    if pad:                                                      # put the title card back in front of the late-starting file
        head = ["-loop", "1", "-framerate", "25", "-t", f"{pad:.3f}", "-i", str(OUT / "card1.png")]
        filt.append(f"[{len(inputs) // 2 + 1}:v]scale=1920:1080,{vf},setsar=1[card];[0:v]{vf},setsar=1[v0];[card][v0]concat=n=2:v=1:a=0[vcat]")
        vin = "[vcat]"
    else:
        filt.append(f"[0:v]{vf}[vcat]")
        vin = "[vcat]"
    end_t = min(vdur + pad, tim["end"] / 1000 - shift(tim["end"] / 1000) + 0.6)
    run([FFMPEG, "-v", "error", "-y", "-i", str(webm), *inputs, *head, "-filter_complex", ";".join(filt + [mix]), "-map", vin, "-map", "[aout]",
         "-c:v", "libx264", "-preset", "medium", "-crf", "20", "-pix_fmt", "yuv420p", "-r", "25", "-c:a", "aac", "-b:a", "160k",
         "-t", f"{end_t:.2f}", "-movflags", "+faststart", str(final)])

    # captions: the written text of every spoken sentence, timed by the narrator's own cues
    cues, k = [], 1
    for n in SCENES:
        for c in narr[n]["cues"]:
            s_ = c["text"].strip()
            words, lines = s_.split(), []
            if len(s_) > 80:                                    # two lines
                acc = 0
                for i, w in enumerate(words):
                    acc += len(w) + 1
                    if acc >= len(s_) / 2:
                        lines = [" ".join(words[: i + 1]), " ".join(words[i + 1:])]
                        break
            base = st[n] - shift(st[n]) + 0.15
            t0_, t1_ = base + c["start"], base + c["end"]
            cues.append(f"{k}\n{srt_time(t0_)} --> {srt_time(t1_)}\n" + ("\n".join(lines) if lines else s_) + "\n")
            k += 1
    (OUT / f"{NAME}.srt").write_text("\n".join(cues))
    # soft subtitles: the same cues as a selectable track inside the mp4 (the .srt stays next to it for players that want a file)
    withsubs = OUT / f"{NAME}.subs.mp4"
    run([FFMPEG, "-v", "error", "-y", "-i", str(final), "-i", str(OUT / f"{NAME}.srt"), "-map", "0:v", "-map", "0:a", "-map", "1:0", "-c", "copy",
         "-c:s", "mov_text", "-metadata:s:s:0", "language=eng", "-movflags", "+faststart", str(withsubs)])
    withsubs.replace(final)
    print(f"done: {final} ({duration(final):.1f} s), {OUT / (NAME + '.srt')}")


if __name__ == "__main__":
    sys.exit(main())
