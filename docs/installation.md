# Installing Mantha Ray

Mantha Ray runs on x86-64 Linux. It needs:

- Git
- Python 3.11.4 or newer, with `venv`
- Tkinter (only for the older desktop window, `mantha-ray gui`; the web interface doesn't need it)
- Docker Engine, the Docker CLI and Buildx, usable by your account without `sudo`
- Node.js and npm only if you change the web interface

## Fedora and Nobara

```bash
sudo dnf install git python3 python3-pip python3-tkinter moby-engine docker-cli docker-buildx
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
```

## Ubuntu and Debian

```bash
sudo apt update
sudo apt install git python3 python3-venv python3-pip python3-tk docker.io docker-buildx-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
```

## Arch Linux

```bash
sudo pacman -S --needed git python python-pip tk docker docker-buildx
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
```

Log out and back in after `usermod` so the new group takes effect. Membership of the `docker` group is effectively root access on the host, so only grant it on a machine (ideally a VM) set aside for this.

## Check and set up

```bash
git clone https://github.com/shashankmantha/Mantha-Ray.git malware-scanner
cd malware-scanner
./scripts/check-requirements.sh
docker run --rm hello-world
./scripts/setup.sh
```

Don't run Mantha Ray or its scripts with `sudo`; the results should stay owned by your account.

`setup.sh` creates `.venv`, installs Mantha Ray, builds the `static-triage:core` analysis image and checks it. The first build needs internet access and takes several minutes: it downloads ClamAV signatures, capa with its rules and signatures, FLOSS, and the YARA-X scanner, whose download is checked against a pinned SHA-256. It ends by printing the ClamAV and YARA-X versions.

Run `setup.sh` again at least once a week. ClamAV signatures older than 7 days make every scan incomplete on purpose, and the rebuild only refreshes the signature layer.

Then install the rule packs:

```bash
mantha-ray packs update
mantha-ray packs status
```

## Changing the web interface

```bash
./scripts/setup.sh --build-frontend   # npm ci, npm run build, then the usual setup
```

The built files go to `src/static_triage/web_dist/`, which is committed so normal installs don't need Node.js.

## Running

```bash
mantha-ray                                   # opens the interface in your browser
mantha-ray web --no-browser        # prints the address instead
mantha-ray web --port 8080         # a fixed port
```

`setup.sh` links the `mantha-ray` command into `~/.local/bin` (it never replaces a file or a link that points elsewhere). If your shell says `command not found`, log out and back in so `~/.local/bin` is on your `PATH`, or use `./mantha-ray.sh` from the repository. Either way there's no need to activate `.venv`.

## For untrusted samples

- Use a dedicated VM and take a clean snapshot first.
- Turn off the VM's network adapter in the hypervisor once setup and `packs update` are done.
- Turn off shared folders, clipboard sharing and drag-and-drop.
- Never open samples with Wine or any other runtime, and don't treat a clean report as permission to run a file.
