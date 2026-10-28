# Tutorial video: recorder and build

`record.spec.ts` plays `docs/VIDEO-SCRIPT.md` in real Chrome (1920x1080) against a local throwaway Postgres.
`build.sh` turns script + recorder into the finished review cut, in one command:

```bash
cd docs/video
APGKIT_REC_PG_PORT=<port> APGKIT_REC_PORT=<free port> ./build.sh      # npm install runs on first use
```

Result (git-ignored): `out/agentpg-kit.mp4` (H.264 yuv420p + AAC, soft subtitles, faststart) and `out/agentpg-kit.srt`.

What it does:

1. Checks that `VIDEO-SCRIPT.md` carries the same NARRATION as `narration.txt` (`python3 build.py --write-script` copies it over), then speaks
   `narration.txt` with the local neural voice Kokoro: `videos/tts/narrate.py scenes narration.txt out/audio --voice af_heart --pronounce pronounce.json`
   (`VIDEO_VOICE` changes the voice). `narration.txt` is written for listening: short sentences, a blank line is a pause, `...` a short beat,
   `[pause 2.5]` a long pause over something happening on screen. `pronounce.json` holds respellings that only change how a word is spoken
   (on top of the shared `videos/tts/pronounce.json`); captions keep the written text. The narrator writes `out/audio/scene-<id>.wav` and
   `narration.json` (scene durations and the start/end of every sentence).
2. Runs a rehearsal at human pace (no video) to measure each scene's natural length, then plans every scene to last at least
   audio + 0.7 s: pauses and callout holds are stretched (or shrunk, down to 0.5x) per scene, and a scene is held at its end if still short
   (`out/plan.json`, passed to the recorder as `APGKIT_REC_PLAN`). Title and end cards keep their own length.
3. Records for real (fresh database each take). The plan also carries the sentence cues: at the main steps the recorder waits for the narrator to
   reach the sentence that describes the step (`sync(...)` in `record.spec.ts`), so a callout or an action starts with its sentence.
   `out/timings.json` lists what appeared on screen and when (`events`). ffmpeg then places each scene's audio at the scene start.
4. Playwright's video file starts about 3 s late on this machine (the title card is missing), so the build finds the first and last lower-third callouts in the video, compares them with `out/timings.json` and puts a still of the title card (`out/card1.png`) in front; audio and captions are placed on that corrected timeline.
5. Writes the `.srt` from the narrator's cues (written text, one cue per sentence) and adds it to the mp4 as a soft subtitle track.

Needs: a UTF-8 Postgres on 127.0.0.1 (see the script's "Prerequisites"; the database `notes_test` is dropped and recreated), `uv`, Google Chrome,
`ffmpeg`/`ffprobe` (Homebrew path, or set `FFMPEG`/`FFPROBE`), and the shared narrator in `../../../videos/tts` (its `.venv` and models; nothing is downloaded by the build). If Playwright's own ffmpeg is not installed, `build.py` points Playwright at the system
ffmpeg through a private browsers folder in `out/browsers` (no download). `SKIP_REHEARSAL=1` reuses `out/natural.json`.
The terminal scenes show the script's ports (8790, 55432) even when the recorder uses others.
