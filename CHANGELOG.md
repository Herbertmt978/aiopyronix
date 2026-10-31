# Changelog

This project follows [Semantic Versioning](https://semver.org/). Until 1.0, a
minor version may change the public API.

## 0.1.1

A malformed panel record now ends the session cleanly. Such records include a
permissions list that is not an object, area details that are not a list of
objects, or a status body that cannot be decoded, including one nested too
deeply to decode. The client reports state `error` with a fixed message
("Invalid panel status" or "Invalid panel permissions"). It no longer stops
the reader with an unhandled exception and reports `disconnected` with no
detail. Nothing is logged or retried, and a pending command still fails with
`CommandUnconfirmedError`.

- A record is checked in full before any of it is kept, so a malformed record
  leaves the snapshot unchanged.
- Confirmation: only a usable area report settles a pending command. A row
  whose area index or value is unusable is ignored, as it already was for the
  snapshot.
- A status body that is not valid JSON is now reported as "Invalid panel
  status" instead of the generic connection message.

## 0.1.0

First release. The PyronixCloud client and panel protocol move out of the
[Pyronix HomeControl integration](https://github.com/Herbertmt978/HA-Pyronix)
0.3.0 unchanged, with a public API, type information and full branch test
coverage.
