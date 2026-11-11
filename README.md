# BTS

GSM/GPRS network 001-01 for the emulator.

## Run

```sh
docker compose up -d
```

Start the emulator with `--gsm-trxmux 127.0.0.1:5750`.
The first emulator uses IMSI `001010000001000`.
Give the others `--sim-imsi 001010000001001`, `001010000001002` and so on.
Up to 4 emulators work at once, set `BTS_CELLS` in `.env` for up to 24.

Stop the network with `docker compose down`.

## Numbers

The phone number is the last 9 IMSI digits without leading zeros, so `001010000001000` gets `1000`.
The SMS center is `+1234`.

## Internet and MMS

Operator settings from the 2000s work without changes, so the phone does not need to be reconfigured.

A phone without settings receives them by SMS after the first registration.
Manual settings:

| Setting | Value |
| --- | --- |
| APN | any, for example `internet` |
| User, password | any |
| Proxy | none |
| MMS center | `http://172.16.32.1:8002/` |
| MMS proxy | none |

## Configuration

Settings are in `.env.default`.
Put changed values in `.env` and run `docker compose up -d --force-recreate`.

Operator proxies and MMS centers come from `operators.csv`.
After editing it, run `tools/generate_operator_config.py` and `docker compose up -d --force-recreate`.
