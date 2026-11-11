# BTS

GSM/GPRS network 001-01 for the emulator.

## Run

```sh
docker compose up -d      # start the network
docker compose down       # stop it
```

Emulators:

```sh
pmb887x-emu --fullflash EL71.bin --gsm-trxmux 127.0.0.1:5750                              # number 1000
pmb887x-emu --fullflash EL71.bin --gsm-trxmux 127.0.0.1:5750 --sim-imsi 001010000001001   # number 1001
```

Every next emulator needs its own `--sim-imsi`.
The number is the last 9 IMSI digits without leading zeros.
By default 4 emulators can run at once, `BTS_CELLS=24` in `.env` allows 24.

SMS center: `+1234`.

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

Operator proxies and MMS centers are taken from `config/operators.csv`.
