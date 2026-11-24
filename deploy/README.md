# Installing the controller on a board

What a board needs besides the program itself. Worked out on the bench board (Variscite
DART-MX8M-PLUS on the SightPAS SP4 carrier, Debian 12) on 2026-11-23.

## Layout

| Path | Holds |
|---|---|
| `/opt/indagate/releases/<name>/indagate-controller` | One folder per release of the program |
| `/opt/indagate/current` | A link to the release in use (relative: `releases/<name>`) |
| `/etc/indagate/` | The server's certificate, when it is not publicly trusted |
| `/var/lib/indagate/` | The controller's data: `device.json` (its identity and secret), `indagate.db`, the journals beside it, `door-overrides.json`. The database also holds the OSDP reader keys. Keep it private and back it up as one folder |
| `/etc/systemd/system/indagate-board-power.service` | From `systemd/` here |
| `/etc/systemd/system/indagate-controller.service` | From `systemd/` here |
| `/etc/systemd/system/indagate-controller.service.d/*.conf` | The server address and certificate for this installation |

A board set up before the rename keeps its data in `/var/lib/highline-nexus`; the program
uses that folder for as long as the identity file is only there (see `src/paths.rs`).

## Why there are two services

`indagate-board-power.service` runs once, early in boot, and switches the board's I/O
power on (line GPIO1_IO06). Two things depend on it:

* **The relay chip.** Until the line is high the I2C bus the chip sits on is dead (the
  kernel logs `i2c i2c-2: SCL is stuck low`) and no relay can be switched.
* **The network.** The same line powers a cellular modem. If it goes high after the wired
  network is already up, the Ethernet PHY stops passing traffic, although the link shows as
  up, until the interface is taken down and up again. Switching it on before the network
  starts avoids that.

The controller also prepares the line itself when it starts (`src/hal/board_setup.rs`),
along with every input line it reads. With the early service in place it finds the line
already on. Without it the relays still work, but the wired network can drop.

Nothing else on the board should prepare these lines. The board maker's application
(`monitor.service`) used to; it must stay disabled, and the controller's unit conflicts
with it so the two can never run together.

## Installing or updating

```bash
install -d -m 700 /opt/indagate/releases/<name>
install -m 755 indagate-controller /opt/indagate/releases/<name>/indagate-controller
systemctl stop indagate-controller.service
cp -a /var/lib/indagate /root/indagate-data-before-<name>     # holds secrets: keep it on the board
cd /opt/indagate && ln -sfn releases/<name> current
systemctl start indagate-controller.service
```

First installation only:

```bash
install -m 644 systemd/indagate-board-power.service systemd/indagate-controller.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable indagate-board-power.service indagate-controller.service
```

## Checks after any change to the board

1. `systemctl is-active indagate-board-power.service indagate-controller.service` prints `active` twice.
2. The controller's log has `Board lines prepared` and no `GPIO read failed` or `relay … failed`.
3. A known card releases its door, and the event reaches the server.
4. **Reboot, and repeat 1 to 3 with nothing done by hand.**
5. **Remove the power, restore it, and repeat 1 to 3.** A controller that only works until
   the next power cut is not installed.
