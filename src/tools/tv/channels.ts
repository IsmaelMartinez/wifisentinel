// Curated UK IPTV channels — free, legal, HLS streams
// Source: iptv-org/iptv (community maintained)
// These are publicly available streams from official broadcasters

export interface Channel {
  id: string;
  name: string;
  group: string;
  url: string;
  quality: string;
  note?: string;
}

export const UK_CHANNELS: Channel[] = [
  // ─── BBC ────────────────────────────────────────────────
  {
    id: "bbc-four",
    name: "BBC Four HD",
    group: "BBC",
    url: "https://streamer.nexyl.uk/48559ccd-6400-457d-8acc-06b9e24c2ed8.m3u8",
    quality: "1080p",
  },
  {
    id: "bbc-three",
    name: "BBC Three HD",
    group: "BBC",
    url: "https://streamer.nexyl.uk/39290a19-b8dd-43ea-b8dc-081c37790f24.m3u8",
    quality: "720p",
  },
  {
    id: "bbc-scotland",
    name: "BBC Scotland",
    group: "BBC",
    url: "https://vs-hls-pushb-uk-live.akamaized.net/x=4/i=urn:bbc:pips:service:bbc_scotland_hd/pc_hd_abr_v2.m3u8",
    quality: "1080p",
    note: "May be geo-blocked to UK",
  },
  {
    id: "bbc-persian",
    name: "BBC Persian",
    group: "BBC",
    url: "https://vs-cmaf-pushb-ww-live.akamaized.net/x=4/i=urn:bbc:pips:service:bbc_persian_tv/pc_hd_abr_v2.mpd",
    quality: "720p",
  },

  // ─── Freeview ──────────────────────────────────────────
  {
    id: "channel-4",
    name: "Channel 4",
    group: "Freeview",
    url: "https://x.canlitvapp.com/u-channel-4/index.m3u8",
    quality: "720p",
  },
  {
    id: "channel-5",
    name: "Channel 5",
    group: "Freeview",
    url: "https://x.canlitvapp.com/u-channel-5/index.m3u8",
    quality: "720p",
  },
  {
    id: "gb-news",
    name: "GB News",
    group: "News",
    url: "https://amg01076-lightningintern-gbnewsau-samsungau-et7fz.amagi.tv/playlist/amg01076-lightningintern-gbnewsau-samsungau/playlist.m3u8",
    quality: "1080p",
  },
  {
    id: "together-tv",
    name: "Together TV",
    group: "Freeview",
    url: "https://csm-e-dazn-mtv5biasislive.tls1.yospace.com/csm/extlive/dazn01,MTV5-BiAsIsLive.m3u8",
    quality: "576p",
  },

  // ─── News ──────────────────────────────────────────────
  {
    id: "sky-news-weather",
    name: "Sky News Weather",
    group: "News",
    url: "https://distro001-gb-hls1-prd.delivery.skycdp.com/easel_cdn/ngrp:weather_loop.stream_all/playlist.m3u8",
    quality: "720p",
  },
  {
    id: "nbc-news",
    name: "NBC News NOW",
    group: "News",
    url: "https://d1bl6tskrpq9ze.cloudfront.net/hls/master.m3u8",
    quality: "1080p",
  },
  {
    id: "talksport",
    name: "talkSPORT",
    group: "News",
    url: "https://af7a8b4e.wurl.com/master/f36d25e7e52f1ba8d7e56eb859c636563214f541/TEctZ2JfdGFsa1NQT1JUX0hMUw/playlist.m3u8",
    quality: "1080p",
  },

  // ─── Entertainment ─────────────────────────────────────
  {
    id: "graham-norton",
    name: "The Graham Norton Show",
    group: "Entertainment",
    url: "https://amg00654-itv-amg00654c35-rakuten-gb-7598.playouts.now.amagi.tv/playlist.m3u8",
    quality: "1080p",
  },
  {
    id: "hells-kitchen",
    name: "Hell's Kitchen",
    group: "Entertainment",
    url: "https://amg00654-itv-amg00654c1-samsung-au-1072.playouts.now.amagi.tv/itv-hellskitchen-samsung/playlist.m3u8",
    quality: "1080p",
  },
  {
    id: "pluto-drama",
    name: "Pluto TV Drama",
    group: "Entertainment",
    url: "https://jmp2.uk/plu-5ddf91149880d60009d35d27.m3u8",
    quality: "720p",
  },
  {
    id: "pluto-movies",
    name: "Pluto TV Movies",
    group: "Movies",
    url: "https://jmp2.uk/plu-5ad8d3a31b95267e225e4e09.m3u8",
    quality: "720p",
  },

  // ─── Movies ────────────────────────────────────────────
  {
    id: "rakuten-top",
    name: "Rakuten Top Movies",
    group: "Movies",
    url: "https://0145451975a64b35866170fd2e8fa486.mediatailor.eu-west-1.amazonaws.com/v1/master/0547f18649bd788bec7b67b746e47670f558b6b2/production-LiveChannel-5987/master.m3u8",
    quality: "1080p",
  },
  {
    id: "rakuten-action",
    name: "Rakuten Action Movies",
    group: "Movies",
    url: "https://54045f0c40fd442c8b06df076aaf1e85.mediatailor.eu-west-1.amazonaws.com/v1/master/0547f18649bd788bec7b67b746e47670f558b6b2/production-LiveChannel-6065/master.m3u8",
    quality: "1080p",
  },
  {
    id: "rakuten-comedy",
    name: "Rakuten Comedy Movies",
    group: "Movies",
    url: "https://9be783d652cd4b099cf63e1dc134c4a3.mediatailor.eu-west-1.amazonaws.com/v1/master/0547f18649bd788bec7b67b746e47670f558b6b2/production-LiveChannel-6181/master.m3u8",
    quality: "1080p",
  },
  {
    id: "rakuten-family",
    name: "Rakuten Family Movies",
    group: "Movies",
    url: "https://e3207568b726401995c25670faaf32e4.mediatailor.eu-west-1.amazonaws.com/v1/master/0547f18649bd788bec7b67b746e47670f558b6b2/production-LiveChannel-6203/master.m3u8",
    quality: "1080p",
  },

  // ─── Kids ──────────────────────────────────────────────
  {
    id: "avatar",
    name: "Avatar",
    group: "Kids",
    url: "https://jmp2.uk/plu-656df599c0fc8800089c75ab.m3u8",
    quality: "720p",
  },

  // ─── Documentary ───────────────────────────────────────
  {
    id: "adventure-earth",
    name: "Adventure Earth",
    group: "Documentary",
    url: "https://a57e9c69976649b582a8d7604c00e69a.mediatailor.us-east-1.amazonaws.com/v1/master/44f73ba4d03e9607dcd9bebdcb8494d86964f1d8/RlaxxTV-eu_AdventureEarth/playlist.m3u8",
    quality: "1080p",
  },
  {
    id: "autentic-history",
    name: "Autentic History",
    group: "Documentary",
    url: "https://9e754fa707344ccca6d84955c8fcaf36.mediatailor.us-east-1.amazonaws.com/v1/master/44f73ba4d03e9607dcd9bebdcb8494d86964f1d8/RlaxxTV-eu_AutenticHistory/playlist.m3u8",
    quality: "1080p",
  },

  // ─── Music ─────────────────────────────────────────────
  {
    id: "afrobeats",
    name: "Afrobeats",
    group: "Music",
    url: "https://stream.ecable.tv/afrobeats/index.m3u8",
    quality: "1080p",
  },
];

export function getChannelsByGroup(): Map<string, Channel[]> {
  const groups = new Map<string, Channel[]>();
  for (const ch of UK_CHANNELS) {
    const list = groups.get(ch.group) ?? [];
    list.push(ch);
    groups.set(ch.group, list);
  }
  return groups;
}

export function findChannel(query: string): Channel | undefined {
  const lower = query.toLowerCase();
  return (
    UK_CHANNELS.find((ch) => ch.id === lower) ??
    UK_CHANNELS.find((ch) => ch.name.toLowerCase().includes(lower))
  );
}
