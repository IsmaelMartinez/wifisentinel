import WebSocket from "ws";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

const CONFIG_DIR = join(homedir(), ".netaudit");
const PAIRING_FILE = join(CONFIG_DIR, "tv-pairing.json");

// SSAP registration payload — tells the TV what permissions we want
const REGISTRATION_PAYLOAD = {
  forcePairing: false,
  pairingType: "PROMPT",
  manifest: {
    manifestVersion: 1,
    appVersion: "1.0.0",
    signed: {
      created: "20250101000000",
      appId: "com.netaudit.tvcontrol",
      vendorId: "com.netaudit",
      localizedAppNames: { "": "Network Analyser TV Control" },
      localizedVendorNames: { "": "netaudit" },
      permissions: [
        "LAUNCH",
        "LAUNCH_WEBAPP",
        "APP_TO_APP",
        "CONTROL_AUDIO",
        "CONTROL_DISPLAY",
        "CONTROL_INPUT_JOYSTICK",
        "CONTROL_INPUT_MEDIA_PLAYBACK",
        "CONTROL_INPUT_MEDIA_RECORDING",
        "CONTROL_INPUT_TEXT",
        "CONTROL_INPUT_TV",
        "CONTROL_MOUSE_AND_KEYBOARD",
        "CONTROL_POWER",
        "READ_APP_STATUS",
        "READ_CURRENT_CHANNEL",
        "READ_INPUT_DEVICE_LIST",
        "READ_INSTALLED_APPS",
        "READ_NETWORK_STATE",
        "READ_RUNNING_APPS",
        "READ_TV_CHANNEL_LIST",
        "WRITE_NOTIFICATION",
      ],
      serial: "netaudit001",
    },
    permissions: [
      "LAUNCH",
      "LAUNCH_WEBAPP",
      "APP_TO_APP",
      "CONTROL_AUDIO",
      "CONTROL_DISPLAY",
      "CONTROL_INPUT_JOYSTICK",
      "CONTROL_INPUT_MEDIA_PLAYBACK",
      "CONTROL_INPUT_MEDIA_RECORDING",
      "CONTROL_INPUT_TEXT",
      "CONTROL_INPUT_TV",
      "CONTROL_MOUSE_AND_KEYBOARD",
      "CONTROL_POWER",
      "READ_APP_STATUS",
      "READ_CURRENT_CHANNEL",
      "READ_INPUT_DEVICE_LIST",
      "READ_INSTALLED_APPS",
      "READ_NETWORK_STATE",
      "READ_RUNNING_APPS",
      "READ_TV_CHANNEL_LIST",
      "WRITE_NOTIFICATION",
    ],
    signatures: [{ signatureVersion: 1, signature: "" }],
  },
};

interface PairingData {
  ip: string;
  clientKey: string;
  name?: string;
}

function loadPairing(ip: string): string | null {
  if (!existsSync(PAIRING_FILE)) return null;
  try {
    const data = JSON.parse(readFileSync(PAIRING_FILE, "utf-8")) as PairingData[];
    const entry = data.find((d) => d.ip === ip);
    return entry?.clientKey ?? null;
  } catch {
    return null;
  }
}

function savePairing(ip: string, clientKey: string, name?: string): void {
  if (!existsSync(CONFIG_DIR)) mkdirSync(CONFIG_DIR, { recursive: true });
  let data: PairingData[] = [];
  if (existsSync(PAIRING_FILE)) {
    try {
      data = JSON.parse(readFileSync(PAIRING_FILE, "utf-8"));
    } catch {}
  }
  const idx = data.findIndex((d) => d.ip === ip);
  if (idx >= 0) {
    data[idx].clientKey = clientKey;
  } else {
    data.push({ ip, clientKey, name });
  }
  writeFileSync(PAIRING_FILE, JSON.stringify(data, null, 2), "utf-8");
}

export interface SSAPResponse {
  id: string;
  type: string;
  payload: Record<string, any>;
  error?: string;
}

export class SSAPClient {
  private ws: WebSocket | null = null;
  private ip: string;
  private msgId = 0;
  private pendingCallbacks = new Map<string, (resp: SSAPResponse) => void>();
  private clientKey: string | null = null;
  private connected = false;

  constructor(ip: string) {
    this.ip = ip;
    this.clientKey = loadPairing(ip);
  }

  async connect(timeoutMs = 10_000): Promise<void> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`Connection to ${this.ip}:3000 timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      this.ws = new WebSocket(`ws://${this.ip}:3000`, {
        origin: `http://${this.ip}:3000`,
        headers: {
          "User-Agent": "netaudit/1.0",
        },
        handshakeTimeout: timeoutMs,
      });

      this.ws.on("open", () => {
        this.connected = true;
        clearTimeout(timer);
        resolve();
      });

      this.ws.on("message", (data) => {
        try {
          const msg = JSON.parse(data.toString());
          const cb = this.pendingCallbacks.get(msg.id);
          if (cb) {
            this.pendingCallbacks.delete(msg.id);
            cb(msg);
          }
        } catch {}
      });

      this.ws.on("error", (err) => {
        clearTimeout(timer);
        reject(err);
      });

      this.ws.on("close", () => {
        this.connected = false;
      });
    });
  }

  private send(type: string, uri?: string, payload?: Record<string, any>): Promise<SSAPResponse> {
    return new Promise((resolve, reject) => {
      if (!this.ws || !this.connected) {
        reject(new Error("Not connected"));
        return;
      }

      const id = `msg_${++this.msgId}`;
      const msg: Record<string, any> = { id, type };
      if (uri) msg.uri = uri;
      if (payload) msg.payload = payload;

      const timer = setTimeout(() => {
        this.pendingCallbacks.delete(id);
        reject(new Error(`Request ${id} timed out`));
      }, 10_000);

      this.pendingCallbacks.set(id, (resp) => {
        clearTimeout(timer);
        resolve(resp);
      });

      this.ws.send(JSON.stringify(msg));
    });
  }

  async register(): Promise<string> {
    const payload: Record<string, any> = { ...REGISTRATION_PAYLOAD };
    if (this.clientKey) {
      payload["client-key"] = this.clientKey;
    }

    const resp = await this.send("register", undefined, payload);

    if (resp.type === "registered") {
      const key = resp.payload?.["client-key"];
      if (key) {
        this.clientKey = key;
        savePairing(this.ip, key);
      }
      return key || this.clientKey || "";
    }

    if (resp.type === "error") {
      throw new Error(`Registration failed: ${JSON.stringify(resp.payload)}`);
    }

    throw new Error(`Unexpected response: ${resp.type}`);
  }

  async request(uri: string, payload?: Record<string, any>): Promise<SSAPResponse> {
    return this.send("request", uri, payload);
  }

  // ─── Convenience methods ──────────────────────────────────

  async getVolume(): Promise<number> {
    const resp = await this.request("ssap://audio/getVolume");
    return resp.payload?.volume ?? 0;
  }

  async setVolume(level: number): Promise<void> {
    await this.request("ssap://audio/setVolume", { volume: level });
  }

  async volumeUp(): Promise<void> {
    await this.request("ssap://audio/volumeUp");
  }

  async volumeDown(): Promise<void> {
    await this.request("ssap://audio/volumeDown");
  }

  async setMute(mute: boolean): Promise<void> {
    await this.request("ssap://audio/setMute", { mute });
  }

  async getChannelList(): Promise<any[]> {
    const resp = await this.request("ssap://tv/getChannelList");
    return resp.payload?.channelList ?? [];
  }

  async getCurrentChannel(): Promise<any> {
    const resp = await this.request("ssap://tv/getCurrentChannel");
    return resp.payload;
  }

  async setChannel(channelId: string): Promise<void> {
    await this.request("ssap://tv/openChannel", { channelId });
  }

  async getAppList(): Promise<any[]> {
    const resp = await this.request("ssap://com.webos.applicationManager/listApps");
    return resp.payload?.apps ?? [];
  }

  async launchApp(appId: string, params?: Record<string, any>): Promise<void> {
    await this.request("ssap://system.launcher/launch", { id: appId, params });
  }

  async openBrowser(url: string): Promise<void> {
    await this.request("ssap://system.launcher/open", { target: url });
  }

  async getSystemInfo(): Promise<any> {
    const resp = await this.request("ssap://system/getSystemInfo");
    return resp.payload;
  }

  async getServiceList(): Promise<any[]> {
    const resp = await this.request("ssap://api/getServiceList");
    return resp.payload?.services ?? [];
  }

  async powerOff(): Promise<void> {
    await this.request("ssap://system/turnOff");
  }

  async showNotification(message: string): Promise<void> {
    await this.request("ssap://system.notifications/createToast", { message });
  }

  async getExternalInputList(): Promise<any[]> {
    const resp = await this.request("ssap://tv/getExternalInputList");
    return resp.payload?.devices ?? [];
  }

  async switchInput(inputId: string): Promise<void> {
    await this.request("ssap://tv/switchInput", { inputId });
  }

  async play(): Promise<void> {
    await this.request("ssap://media.controls/play");
  }

  async pause(): Promise<void> {
    await this.request("ssap://media.controls/pause");
  }

  async stop(): Promise<void> {
    await this.request("ssap://media.controls/stop");
  }

  async channelUp(): Promise<void> {
    await this.request("ssap://tv/channelUp");
  }

  async channelDown(): Promise<void> {
    await this.request("ssap://tv/channelDown");
  }

  disconnect(): void {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
      this.connected = false;
    }
  }
}
