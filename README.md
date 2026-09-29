# AirWatch

A Linux desktop app for finding an authorized Wi-Fi network, capturing WPA2-PSK handshake evidence, and trying local password candidates with Hashcat. It keeps the everyday workflow in six top tabs: **Networks**, **Capture**, **Evidence**, **Recovery**, **Adapters**, and **Activity**. The tabs remain usable during a scan. Details stay tucked away, and AI tips have an on/off switch.

## Start

Install Python 3 with Tkinter, NetworkManager (`nmcli`), `iw`, Aircrack-ng, TShark, Hashcat, and PolicyKit. Hashcat needs a working GPU driver and compute runtime. The included `hcxpcapngtool` is used if a system copy is unavailable.

Run `./start-airwatch.sh` from this folder. The app asks PolicyKit for administrator access when an adapter operation needs it; the GUI itself runs as your normal user.

## Use

1. **Networks:** Choose your network. AirWatch prefers an idle adapter so an existing Wi-Fi connection can stay online.
2. **Capture:** Start focused capture. A usable record for the selected access point ends capture, restores the adapter, and opens analysis. A broad scan alone does not confirm a handshake.
3. **Recovery:** Choose a wordlist or a pattern and GPU. **State phone numbers** can try digits (`2171234567`), two dashes (`217-123-4567`), or both; only the selected state's area codes are used. The offline search stops after the first recovered passphrase. If it exhausts the chosen search space, it has not found a match there.

You can open **Networks → Find networks** while Recovery runs. A scan and focused capture can use another adapter without pausing Hashcat. A new capture is saved separately; **Check new capture** becomes available after the current search stops. If only your connected adapter can scan, AirWatch asks before switching it to monitor mode.

**Pause & save** asks Hashcat to quit at its next checkpoint. You can then close AirWatch; **Continue old search** appears when you reopen it and uses the original pattern or wordlist. To run the loaded hash with a different pattern, select it and press **Start selected search** (or **Start Illinois search** for the Illinois preset). The old checkpoint stays in its results folder. Set **Stop after** to 0 to let the new search run until it finishes or you pause it. Closing the app during a search asks for a checkpoint and waits for the search to stop. Saved sessions live in private results folders, and the latest session is remembered in `~/.config/airwatch/saved-search.json`. Keep the hash, wordlist, and results folder at their original paths. Hashcat may repeat work done since its last restore point. [Hashcat's restore guide](https://hashcat.net/wiki/doku.php?id=restore) explains this behavior.

**Restore Wi-Fi** stays at the top of the app. It stops capture, returns the tracked adapter to managed mode, restarts NetworkManager, enables Wi-Fi, and waits briefly for a saved connection. If the driver or access point is unavailable, you may still need to reconnect through Linux's Wi-Fi menu.

**Stop all now** is for interrupting active workers immediately; it is separate from a resumable pause. It may leave the current search without a new checkpoint.

Optional AI tips send only anonymized, allow-listed capture measurements. Set `OPENAI_API_KEY` in the environment, or put it in `~/.config/airwatch/.env.local` as `OPENAI_API_KEY=...`. `AIRWATCH_ENV_FILE` can point to another local file. Credentials and recovered passwords are not committed to this repository. The AI switch can remain off without affecting capture or recovery.

Use AirWatch only on networks you own or are authorized to assess. Active reconnect testing is bounded, targets the selected access point, and requires a separate confirmation.
