# MN-P01 — micro-notify on Linux: container proof (owned by micro-notify-orch)

BOARD: micro-notify   DEPENDS ON: —   GATED: no   COVERS: GC-14 (alert path in the container) / —

This card is written and dispatched by `micro-notify-orch` on its own board; the card file lives in the
micro-notify repo. What is already merged there: the file secret backend
(`MICRO_NOTIFY_SECRETS=file` + `MICRO_NOTIFY_SECRETS_DIR`, #43 / #45), the Alpine non-root image (#42).
An env secret backend is NOT built and will not be (secret values never travel through the environment).

What is left, and is the whole card: nothing has ever run on Linux. Build the Alpine image on a Linux
runner, run `mnotify doctor` and one alert send as uid 10001 with mounted secret files against a local
stub webhook, and keep that as a repeatable job.

`GC-P16a..c` consume the result: they need the image to build and `mnotify doctor` to pass in it.
