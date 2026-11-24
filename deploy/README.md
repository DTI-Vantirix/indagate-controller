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

The controller's unit does not wait for the network. It makes its door decisions from its
own database, so it starts as soon as the board's power line is on and reaches the server
whenever the network comes up. Ordered after `network-online.target` it started two minutes
after a power cut, with the doors dead until then.

Nothing else on the board should prepare these lines. The board maker's application
(`monitor.service`) used to; it must stay disabled, and the controller's unit conflicts
with it so the two can never run together.

## Preparing a new board

A board arrives from its maker with things an Indagate controller must not have. Run
`prepare-board.sh` once on every board, before it goes into service.

| What the board comes with | Why it has to go |
|---|---|
| The maker's application, started by `monitor.service` | It drives the same relays, readers and inputs |
| The maker's update client (Mender: `mender-authd`, `mender-updated`, `mender-connect`) | It takes software, and remote terminal sessions, from the maker's account |
| A software-update web page (`swupdate`, port 8080) | Anyone on the network can offer the board a new system image |
| An FTP server (`vsftpd`) | A second way to log in, with the password sent unprotected |
| Accounts `user` and `weston` with published passwords | Anyone can look the passwords up |

The script switches the services off and masks them, removes the packages and files,
locks the two accounts, and installs the two Indagate services. Everything it removes is
first copied into one archive under `/root`.

```bash
scp -r deploy root@<board>:/root/indagate-deploy       # from the firmware repository
ssh root@<board>
bash /root/indagate-deploy/prepare-board.sh            # shows what it would do; changes nothing
bash /root/indagate-deploy/prepare-board.sh --apply    # does it
```

Then, by hand:

1. Change the root password (`passwd`). The script does not touch it.
2. Install a release and set the server address (next section).
3. Do the checks at the end of this page, including the reboot and the power cut.
4. Delete the archive under `/root` once the checks pass. It can hold the maker's update
   token.

`--no-display` also switches off the display service, for a board with no screen.
`--remove-pre-rename` is for a board that ran Indagate under its old names
(`hlaxs-access`, `highline-nexus`): it removes that layout too, and refuses unless the
board is already running from `/var/lib/indagate`.

The script leaves the operating system, the boot loader, the board support services
(`variscite-*`, NetworkManager, the modem, Bluetooth, Wi-Fi) and SSH alone. It ends by
listing what still accepts connections from the network, for you to judge.

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
