import { Command } from "commander";
import chalk from "chalk";
import { SSAPClient } from "./ssap-client.js";

// Default TV IP — auto-detected from last scan or specified via flag
const DEFAULT_TV_IP = "192.168.1.65";

async function withTV(
  ip: string,
  fn: (client: SSAPClient) => Promise<void>
): Promise<void> {
  const client = new SSAPClient(ip);
  try {
    console.error(chalk.dim(`Connecting to TV at ${ip}:3000...`));
    await client.connect();
    console.error(chalk.dim("Registering (check TV for pairing prompt on first use)..."));
    await client.register();
    console.error(chalk.green("Connected and paired."));
    await fn(client);
  } catch (err: any) {
    console.error(chalk.red(`TV error: ${err.message}`));
    process.exit(1);
  } finally {
    client.disconnect();
  }
}

export function registerTVCommands(program: Command): void {
  const tv = program
    .command("tv")
    .description("Control LG webOS TV via SSAP protocol")
    .option("--ip <address>", "TV IP address", DEFAULT_TV_IP);

  // ─── Info commands ──────────────────────────────────────

  tv.command("info")
    .description("Show TV system info")
    .action(async () => {
      const ip = tv.opts().ip;
      await withTV(ip, async (client) => {
        const [info, services, inputs] = await Promise.all([
          client.getSystemInfo(),
          client.getServiceList(),
          client.getExternalInputList(),
        ]);

        console.log(chalk.cyan("\n  TV System Info"));
        console.log(chalk.dim("  ─────────────"));
        for (const [k, v] of Object.entries(info)) {
          console.log(`  ${chalk.dim(k)}: ${v}`);
        }

        console.log(chalk.cyan("\n  External Inputs"));
        for (const input of inputs) {
          const connected = input.connected ? chalk.green("connected") : chalk.dim("disconnected");
          console.log(`  ${input.id} — ${input.label} [${connected}]`);
        }

        console.log(chalk.cyan("\n  Services"));
        for (const svc of services.slice(0, 10)) {
          console.log(`  ${chalk.dim(svc.name)}`);
        }
        if (services.length > 10) {
          console.log(chalk.dim(`  ... and ${services.length - 10} more`));
        }
        console.log();
      });
    });

  // ─── App commands ──────────────────────────────────────

  tv.command("apps")
    .description("List installed apps")
    .action(async () => {
      const ip = tv.opts().ip;
      await withTV(ip, async (client) => {
        const apps = await client.getAppList();
        console.log(chalk.cyan(`\n  Installed Apps (${apps.length})`));
        console.log(chalk.dim("  ────────────────"));
        const sorted = apps.sort((a: any, b: any) => a.title?.localeCompare(b.title));
        for (const app of sorted) {
          console.log(`  ${chalk.dim(app.id.padEnd(40))} ${app.title}`);
        }
        console.log();
      });
    });

  tv.command("launch <appId>")
    .description("Launch an app (use 'tv apps' to see IDs)")
    .action(async (appId: string) => {
      const ip = tv.opts().ip;
      await withTV(ip, async (client) => {
        await client.launchApp(appId);
        console.log(chalk.green(`  Launched: ${appId}`));
      });
    });

  // ─── Volume commands ──────────────────────────────────

  tv.command("volume [level]")
    .description("Get or set volume (0-100)")
    .action(async (level?: string) => {
      const ip = tv.opts().ip;
      await withTV(ip, async (client) => {
        if (level !== undefined) {
          await client.setVolume(parseInt(level, 10));
          console.log(chalk.green(`  Volume set to ${level}`));
        } else {
          const vol = await client.getVolume();
          const bar = "█".repeat(Math.round(vol / 5)) + "░".repeat(20 - Math.round(vol / 5));
          console.log(`  Volume: ${bar} ${vol}/100`);
        }
      });
    });

  tv.command("mute [on|off]")
    .description("Toggle or set mute")
    .action(async (state?: string) => {
      const ip = tv.opts().ip;
      await withTV(ip, async (client) => {
        const mute = state === undefined || state === "on";
        await client.setMute(mute);
        console.log(chalk.green(`  Mute: ${mute ? "on" : "off"}`));
      });
    });

  // ─── Channel commands ──────────────────────────────────

  tv.command("channels")
    .description("List available TV channels")
    .action(async () => {
      const ip = tv.opts().ip;
      await withTV(ip, async (client) => {
        const channels = await client.getChannelList();
        console.log(chalk.cyan(`\n  TV Channels (${channels.length})`));
        console.log(chalk.dim("  ──────────────"));
        for (const ch of channels) {
          const num = String(ch.channelNumber ?? ch.majorNumber ?? "?").padStart(4);
          console.log(`  ${chalk.dim(num)}  ${ch.channelName ?? ch.channelId}`);
        }
        console.log();
      });
    });

  tv.command("channel [id]")
    .description("Get current channel or switch to channel ID")
    .action(async (id?: string) => {
      const ip = tv.opts().ip;
      await withTV(ip, async (client) => {
        if (id) {
          await client.setChannel(id);
          console.log(chalk.green(`  Switched to channel: ${id}`));
        } else {
          const ch = await client.getCurrentChannel();
          console.log(`  Current channel: ${ch?.channelName ?? ch?.channelId ?? "unknown"} (${ch?.channelNumber ?? "?"})`);
        }
      });
    });

  tv.command("ch+")
    .description("Channel up")
    .action(async () => {
      const ip = tv.opts().ip;
      await withTV(ip, async (client) => {
        await client.channelUp();
        console.log(chalk.green("  Channel ▲"));
      });
    });

  tv.command("ch-")
    .description("Channel down")
    .action(async () => {
      const ip = tv.opts().ip;
      await withTV(ip, async (client) => {
        await client.channelDown();
        console.log(chalk.green("  Channel ▼"));
      });
    });

  // ─── Browser / IPTV ────────────────────────────────────

  tv.command("open <url>")
    .description("Open a URL in the TV browser")
    .action(async (url: string) => {
      const ip = tv.opts().ip;
      await withTV(ip, async (client) => {
        await client.openBrowser(url);
        console.log(chalk.green(`  Opened: ${url}`));
      });
    });

  tv.command("iptv <m3uUrl>")
    .description("Open an IPTV M3U playlist URL in the TV browser")
    .action(async (m3uUrl: string) => {
      const ip = tv.opts().ip;
      await withTV(ip, async (client) => {
        // Try launching the built-in media player with the M3U URL first
        // webOS media player can handle M3U streams
        try {
          await client.launchApp("com.webos.app.photovideo", {
            target: m3uUrl,
          });
          console.log(chalk.green(`  Launched media player with: ${m3uUrl}`));
        } catch {
          // Fallback: open in browser (some IPTV web players work)
          await client.openBrowser(m3uUrl);
          console.log(chalk.yellow(`  Opened in browser (media player unavailable): ${m3uUrl}`));
        }
        console.log(chalk.dim("\n  Tip: For best IPTV experience, install an IPTV app on your TV:"));
        console.log(chalk.dim("    - IPTV Smarters Pro (com.webos.app.iptv-smarters)"));
        console.log(chalk.dim("    - OTTPlayer"));
        console.log(chalk.dim("    - SS IPTV"));
        console.log(chalk.dim("  Then load your M3U URL inside the app.\n"));
      });
    });

  // ─── Media controls ────────────────────────────────────

  tv.command("play").description("Play").action(async () => {
    await withTV(tv.opts().ip, (c) => c.play());
  });

  tv.command("pause").description("Pause").action(async () => {
    await withTV(tv.opts().ip, (c) => c.pause());
  });

  tv.command("stop").description("Stop").action(async () => {
    await withTV(tv.opts().ip, (c) => c.stop());
  });

  // ─── Utility ───────────────────────────────────────────

  tv.command("notify <message>")
    .description("Show a toast notification on the TV")
    .action(async (message: string) => {
      const ip = tv.opts().ip;
      await withTV(ip, async (client) => {
        await client.showNotification(message);
        console.log(chalk.green(`  Notification sent: "${message}"`));
      });
    });

  tv.command("input <inputId>")
    .description("Switch TV input (use 'tv info' to see inputs)")
    .action(async (inputId: string) => {
      const ip = tv.opts().ip;
      await withTV(ip, async (client) => {
        await client.switchInput(inputId);
        console.log(chalk.green(`  Switched to input: ${inputId}`));
      });
    });

  tv.command("off")
    .description("Turn off the TV")
    .action(async () => {
      const ip = tv.opts().ip;
      await withTV(ip, async (client) => {
        await client.powerOff();
        console.log(chalk.green("  TV powered off."));
      });
    });
}
