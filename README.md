# aiopyronix

[![PyPI](https://img.shields.io/pypi/v/aiopyronix)](https://pypi.org/project/aiopyronix/)
[![CI](https://github.com/Herbertmt978/aiopyronix/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Herbertmt978/aiopyronix/actions/workflows/ci.yml)
[![Licence: MIT](https://img.shields.io/badge/Licence-MIT-0F766E.svg)](https://github.com/Herbertmt978/aiopyronix/blob/main/LICENSE)

An asynchronous Python client for Pyronix alarm panels reached through
PyronixCloud, the service used by the HomeControl 2.0 app.

It powers the [Pyronix HomeControl integration for Home Assistant](https://github.com/Herbertmt978/HA-Pyronix),
and it can be used on its own. This is independent community software. It is
not an official Pyronix, Hikvision or Home Assistant product.

## Design

The client controls an intruder alarm, so caution takes priority over convenience:

- **Explicit sessions.** Nothing connects when a `PanelClient` is created. A
  session opens only when `connect()` is called. There is no polling or
  automatic reconnection.
- **Idle sessions close.** A session closes after five minutes without a
  `connect()` or `control()` call. Heartbeats keep the socket alive, but they
  do not extend that limit.
- **Commands are sent once.** `control()` arms or disarms exactly one area and
  waits for the panel to confirm it. When the outcome cannot be confirmed, it
  raises `CommandUnconfirmedError`. The command is never repeated, even after
  a lost connection.
- **A narrow command set.** Only single-area arm and disarm are possible. The
  library has no forced omissions, outputs, installer functions or cloud
  account changes.
- **Nothing sensitive is logged.** The library does not log. Its error
  messages are fixed text and never contain credentials, panel data or wire
  payloads.

Status updates and commands share one WebSocket. Each frame is encrypted with
a session key agreed through ECDH (P-256) and checked for integrity and
sequence.

## Installation

```bash
pip install aiopyronix
```

Python 3.14 or later is required.

## Connection details

`PanelClient` needs the connection details that the HomeControl 2.0 app saves
when you sign in:

| Field | Meaning |
| --- | --- |
| `AppUser`, `PushId`, `DeviceId` | The app installation registered with PyronixCloud |
| `PanelId` | The eight-character panel identifier |
| `SystemName` | The panel name shown in the app |
| `PanelPwd` | The app password stored for the panel |
| `UserCode` | The panel user code, four to eight digits |

`AppVersion`, `AppType`, `OSName`, `OSVersion`, `NetworkType` and `AppLang`
are optional. Other keys are discarded. The Home Assistant integration
includes a [setup helper](https://github.com/Herbertmt978/HA-Pyronix#connect-your-own-alarm)
that reads these details from your own signed-in app.

## Usage

```python
import asyncio
import json
from pathlib import Path

import aiohttp

from aiopyronix import CommandUnconfirmedError, PanelClient


async def main() -> None:
    auth = json.loads(Path("pyronix.json").read_text())
    async with aiohttp.ClientSession() as http:
        client = PanelClient(http, auth)
        try:
            snapshot = await client.connect()
            for index, area in snapshot["areas"].items():
                print(index, area["name"], area["status"])

            if 0 in snapshot["can_arm"]:
                try:
                    await client.control("arm", 0)
                except CommandUnconfirmedError:
                    print("Check the panel before trying again")
        finally:
            await client.disconnect()


asyncio.run(main())
```

`connect()` returns once every area the user may control has reported its
state. Calling it on an open session returns the current state and restarts
the idle timer.

### Callbacks

- `on_update(snapshot)` runs whenever the panel reports new state.
- `on_state()` runs when `state`, `detail` or `idle_expires_at` changes.
- `create_task(coroutine)` starts the session's background reader. It defaults
  to `asyncio.create_task`. Home Assistant passes
  `entry.async_create_background_task`.

### State

- `snapshot()` returns an independent copy of the latest `Snapshot`: the
  `areas`, the `can_arm` and `can_disarm` area sets, `permissions_received`,
  `observed_at` and, when reported, `firmware`.
- `state` is `disconnected`, `connecting`, `connected` or `error`. After an
  error, `detail` holds a fixed explanation.
- `idle_expires_at` is the wall-clock time at which an idle session will close.

Area `value` codes are listed in `STATUS`: `0` Unset, `1` Set, `2` Alarmed,
`3` Setting, `4` Cannot Set, `5` Can Override and `6` Set Cancelled. An arm
request counts as confirmed once the area reports Setting. Arming is refused
while an area reports Cannot Set or Can Override.

### Errors

All errors derive from `ProtocolError`:

| Exception | Meaning |
| --- | --- |
| `AuthenticationError` | The cloud or panel rejected the credentials. Ask for new details; do not retry automatically. |
| `PanelBusyError` | Another command on this client is still waiting for its result. |
| `CommandUnconfirmedError` | The command may have reached the panel, but its outcome is unknown. `snapshot` holds the latest state, if the session is still open. |
| `ProtocolError` | Any other connection, validation or panel failure. |

## Development

```bash
python -m pip install -e . --group dev
ruff check .
ruff format --check .
mypy
pytest --cov
```

The tests use a simulated panel and require 100% branch coverage. They never
contact PyronixCloud.

## Licence

[MIT](LICENSE)
