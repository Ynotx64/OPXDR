// All layers from the original geo.html, organized into groups
export const LAYERS = [
  // SPACE
  { id: "satellites",    name: "Satellites",        icon: "🛰",  group: "SPACE",     color: "#00e5ff", on: true,  count: 275 },
  { id: "spaceports",    name: "Spaceports",        icon: "🚀",  group: "SPACE",     color: "#a78bfa", on: false, count: 14 },
  // SIGNALS
  { id: "gpsJamming",    name: "GPS Jamming",       icon: "📡",  group: "SIGNALS",   color: "#ff6b35", on: true,  count: 168 },
  // CONFLICT
  { id: "conflictEvents",name: "Iran War Live",     icon: "⚔️",  group: "CONFLICT",  color: "#ff2d55", on: true,  count: 338 },
  { id: "airDefense",    name: "Air Defense Zones", icon: "🛡",  group: "CONFLICT",  color: "#ff9f0a", on: false, count: 24 },
  { id: "conflictZones", name: "Conflict Zones",    icon: "🔴",  group: "CONFLICT",  color: "#ff453a", on: false, count: 12 },
  { id: "civilUnrest",   name: "Civil Unrest",      icon: "✊",  group: "CONFLICT",  color: "#ff9f0a", on: false, count: 47 },
  // INFRA
  { id: "nuclearFacility",name: "Nuclear Facilities",icon:"☢️",  group: "INFRA",     color: "#34c759", on: false, count: 48 },
  { id: "undersea",      name: "Undersea Cables",   icon: "🔌",  group: "INFRA",     color: "#7c3aed", on: false, count: 58 },
  // AVIATION
  { id: "airports",      name: "Airports",          icon: "✈️",  group: "AVIATION",  color: "#64d2ff", on: false, count: 0 },
  { id: "militaryAv",    name: "Military Aviation", icon: "✈️",  group: "AVIATION",  color: "#38bdf8", on: false, count: 0 },
  // MARITIME
  { id: "maritime",      name: "Maritime",          icon: "🚢",  group: "MARITIME",  color: "#30d158", on: false, count: 0 },
  { id: "seaports",      name: "Seaports",          icon: "⚓",  group: "MARITIME",  color: "#0ea5e9", on: false, count: 0 },
  // DISASTERS
  { id: "wildfire",      name: "Wildfire",          icon: "🔥",  group: "DISASTERS", color: "#ff6b35", on: false, count: 0 },
  { id: "earthquakes",   name: "Earthquakes",       icon: "🌍",  group: "DISASTERS", color: "#ff9f0a", on: false, count: 0 },
  { id: "volcanoes",     name: "Volcanoes",         icon: "🌋",  group: "DISASTERS", color: "#f97316", on: false, count: 0 },
  // MILITARY
  { id: "milBases",      name: "Military Bases",    icon: "🏴",  group: "MILITARY",  color: "#5ac8fa", on: false, count: 0 },
  { id: "embassies",     name: "Embassies",         icon: "🏛",  group: "MILITARY",  color: "#a855f7", on: false, count: 0 },
  // CYBER (master toggle)
  { id: "webAttackers",  name: "Web Attackers",     icon: "🌐",  group: "CYBER", color: "#ff2d55", on: false, count: 0 },
  { id: "ddosAttackers", name: "DDoS Attackers",    icon: "⚡",  group: "CYBER", color: "#ff9f0a", on: false, count: 0 },
  { id: "intruders",     name: "Intruders",         icon: "🥷",  group: "CYBER", color: "#a855f7", on: false, count: 0 },
  { id: "scanners",      name: "Scanners",          icon: "🔭",  group: "CYBER", color: "#06b6d4", on: false, count: 0 },
  { id: "cyberOAS",      name: "OAS — On-Access",   icon: "🦠",  group: "CYBER", color: "#22c55e", on: false, count: 0 },
  { id: "cyberODS",      name: "ODS — On-Demand",   icon: "🔬",  group: "CYBER", color: "#84cc16", on: false, count: 0 },
  { id: "cyberMAV",      name: "MAV — Mail AV",     icon: "📧",  group: "CYBER", color: "#f59e0b", on: false, count: 0 },
  { id: "cyberWAV",      name: "WAV — Web AV",      icon: "🌐",  group: "CYBER", color: "#ef4444", on: false, count: 0 },
  { id: "cyberIDS",      name: "IDS — Intrusion",   icon: "🚨",  group: "CYBER", color: "#ff6b35", on: false, count: 0 },
  { id: "cyberVUL",      name: "VUL — Vuln Scan",   icon: "🩹",  group: "CYBER", color: "#fbbf24", on: false, count: 0 },
  { id: "cyberRMW",      name: "RMW — Ransomware",  icon: "🔒",  group: "CYBER", color: "#dc2626", on: false, count: 0 },
  { id: "shodanDevices", name: "Shodan Devices",    icon: "🔍",  group: "CYBER", color: "#f59e0b", on: false, count: 0 },
  { id: "honeypot",      name: "Honeypot Traffic", icon: "🍯",  group: "CYBER", color: "#ff7a18", on: false, count: 0 },
];

export const CYBER_IDS = LAYERS.filter(l => l.group === "CYBER").map(l => l.id);

// Static geographic data
export const GPS_ZONES = [
  { lat: 32.0, lng: 35.0, r: 280, level: "high",   region: "Israel/Lebanon" },
  { lat: 49.0, lng: 32.0, r: 380, level: "high",   region: "Ukraine" },
  { lat: 55.7, lng: 37.6, r: 220, level: "medium", region: "Moscow" },
  { lat: 35.7, lng: 51.4, r: 180, level: "medium", region: "Tehran" },
  { lat: 36.2, lng: 37.1, r: 140, level: "high",   region: "Syria" },
];

export const NUCLEAR = [
  { lat: 31.9, lng: 35.1,  name: "Dimona",      country: "Israel",  type: "suspected" },
  { lat: 32.8, lng: 48.2,  name: "Bushehr NPP", country: "Iran",    type: "power" },
  { lat: 56.8, lng: 54.1,  name: "Mayak",       country: "Russia",  type: "processing" },
  { lat: 51.2, lng: 30.2,  name: "Chernobyl",   country: "Ukraine", type: "decommissioned" },
  { lat: 39.8, lng: 125.7, name: "Yongbyon",    country: "DPRK",    type: "weapons" },
  { lat: 47.5, lng: 34.6,  name: "Zaporizhzhia",country: "Ukraine", type: "power" },
  { lat: 37.4, lng: 141.0, name: "Fukushima",   country: "Japan",   type: "decommissioned" },
];

export const AIR_DEFENSE = [
  { lat: 32.0, lng: 35.0, r: 180, name: "Iron Dome Cluster", country: "Israel" },
  { lat: 55.7, lng: 37.6, r: 450, name: "S-400 Moscow",      country: "Russia" },
  { lat: 35.7, lng: 51.4, r: 280, name: "S-300 Tehran",      country: "Iran" },
];

export const SATELLITES = [
  { lat: 51.6, lng: -120.3, alt: 408000, name: "ISS" },
  { lat: 53.2, lng: 45.1,   alt: 550000, name: "STARLINK-3291" },
  { lat: -23.4, lng: 28.7,  alt: 786000, name: "SENTINEL-2A" },
  { lat: 72.1, lng: -44.2,  alt: 870000, name: "NOAA-19" },
];

export const CONFLICT_ZONES = [
  { lat: 48.3, lng: 31.2, region: "Ukraine",     count: 15 },
  { lat: 32.0, lng: 35.0, region: "Gaza/Israel", count: 10 },
  { lat: 36.2, lng: 37.1, region: "Syria",       count: 6 },
  { lat: 15.3, lng: 44.1, region: "Yemen",       count: 5 },
  { lat: 13.5, lng: 23.3, region: "Sudan",       count: 3 },
];

// API config — for the registry screen
export const API_CONFIGS = [
  { id: "n2yo",          icon: "🛰",  name: "N2YO — Satellite Tracking",  color: "#00e5ff",  desc: "Real-time satellite positions",        url: "https://www.n2yo.com/api/",                                free: "Free: 1,000 req/hour" },
  { id: "acled",         icon: "⚔️",  name: "ACLED — Conflict Data",      color: "#ff2d55",  desc: "Live conflict events worldwide",       url: "https://developer.acleddata.com/",                         free: "Free for researchers" },
  { id: "opensky",       icon: "✈️",  name: "OpenSky — Live Aircraft",    color: "#64d2ff",  desc: "Real-time ADS-B aircraft globally",    url: "https://opensky-network.org/register",                     free: "Free: 400 credits/day" },
  { id: "aisstream",     icon: "🚢",  name: "AIS Stream — Maritime",      color: "#30d158",  desc: "Live vessel positions worldwide",      url: "https://aisstream.io/",                                    free: "Free unlimited read" },
  { id: "nasa_firms",    icon: "🔥",  name: "NASA FIRMS — Wildfire",      color: "#ff6b35",  desc: "MODIS+VIIRS fire detection",           url: "https://firms.modaps.eosdis.nasa.gov/api/map_key/",        free: "Free — instant approval" },
  { id: "openweather",   icon: "🌤", name: "OpenWeatherMap",              color: "#38bdf8",  desc: "Weather, radar, wind",                 url: "https://home.openweathermap.org/users/sign_up",            free: "Free: 60 calls/min" },
  { id: "alientvault",   icon: "💻",  name: "AlienVault OTX",             color: "#06b6d4",  desc: "Open threat exchange — IOCs",          url: "https://otx.alienvault.com/api/",                          free: "Free account" },
  { id: "shodan",        icon: "🔍",  name: "Shodan — Exposed Devices",   color: "#f59e0b",  desc: "Internet-connected devices",           url: "https://account.shodan.io/register",                       free: "Free: 100 results/query" },
];

export const FREE_SOURCES = [
  { icon: "🌍", name: "USGS Earthquakes",     desc: "M2.5+ global real-time" },
  { icon: "📡", name: "GPSJam.org",            desc: "Daily GPS jamming zones" },
  { icon: "🌋", name: "Smithsonian GVP",       desc: "Global volcano activity" },
  { icon: "🔌", name: "TeleGeography Cables",  desc: "58 submarine cables" },
  { icon: "⚔️", name: "GDELT Project",         desc: "Real-time conflict events" },
  { icon: "🏭", name: "IAEA PRIS",             desc: "Nuclear reactors worldwide" },
  { icon: "🛰", name: "CelesTrak",             desc: "TLE for all satellites" },
];

// Search database
export const PLACE_DB = [
  { n: "New York City",  s: "Manhattan, US",  icon: "🏙",  lat: 40.7128, lng: -74.006 },
  { n: "London",         s: "UK",             icon: "🏙",  lat: 51.5074, lng: -0.1278 },
  { n: "Paris",          s: "France",         icon: "🏙",  lat: 48.8566, lng: 2.3522 },
  { n: "Tokyo",          s: "Japan",          icon: "🏙",  lat: 35.6762, lng: 139.6503 },
  { n: "Moscow",         s: "Russia",         icon: "🏙",  lat: 55.7558, lng: 37.6176 },
  { n: "Beijing",        s: "China",          icon: "🏙",  lat: 39.9042, lng: 116.4074 },
  { n: "Tehran",         s: "Iran",           icon: "🏙",  lat: 35.6892, lng: 51.3890 },
  { n: "Tel Aviv",       s: "Israel",         icon: "🏙",  lat: 32.0853, lng: 34.7818 },
  { n: "Kyiv",           s: "Ukraine",        icon: "🏙",  lat: 50.4501, lng: 30.5234 },
  { n: "Seoul",          s: "South Korea",    icon: "🏙",  lat: 37.5665, lng: 126.9780 },
  { n: "Gaza City",      s: "Gaza Strip",     icon: "⚔️",  lat: 31.5017, lng: 34.4668 },
  { n: "Strait of Hormuz",s:"Iran/Oman",      icon: "🚢",  lat: 26.5667, lng: 56.2500 },
  { n: "Taiwan Strait",  s: "Taiwan/China",   icon: "⚔️",  lat: 24.5,    lng: 120.5 },
  { n: "Bushehr NPP",    s: "Iran",           icon: "☢️",  lat: 28.8346, lng: 50.8861 },
  { n: "Yongbyon",       s: "North Korea",    icon: "☢️",  lat: 39.7908, lng: 125.7471 },
  { n: "Zaporizhzhia",   s: "Ukraine",        icon: "☢️",  lat: 47.5061, lng: 34.5844 },
  { n: "Pentagon",       s: "Virginia, US",   icon: "🏴",  lat: 38.8719, lng: -77.0563 },
];

export const REGIONS = [
  { name: "Global",   lat: 20,  lng: 0,    zoom: 2 },
  { name: "Americas", lat: -15, lng: -75,  zoom: 3 },
  { name: "Europe",   lat: 50,  lng: 10,   zoom: 4 },
  { name: "MENA",     lat: 25,  lng: 40,   zoom: 4 },
  { name: "Asia",     lat: 35,  lng: 100,  zoom: 3 },
  { name: "Africa",   lat: 0,   lng: 20,   zoom: 3 },
  { name: "Arctic",   lat: 80,  lng: 0,    zoom: 3 },
];

// Undersea cable subset (full 58 routes in TELEGEOGRAPHY_CABLES — abbreviated here)
export const CABLES = [
  { name: "MAREA",            rfs: 2017, path: [[38.9, -75.1], [42, -30], [42.8, -8.7]] },
  { name: "AEConnect-1",      rfs: 2016, path: [[40.7, -73.9], [51, -20], [53.3, -6]] },
  { name: "FASTER",           rfs: 2016, path: [[31.2, 121.5], [37, 150], [45, 175], [50, -165], [37.8, -122.4]] },
  { name: "SEA-ME-WE 5",      rfs: 2016, path: [[1.3, 103.8], [22, 80], [22, 58], [12, 38], [38.7, -8]] },
  { name: "2Africa",          rfs: 2024, path: [[1.3, 103.8], [-34, 18], [5, 0], [38.7, -8.5]] },
  { name: "Southern Cross",   rfs: 2000, path: [[-33.8, 151.2], [-21.3, -157.8], [21.3, -157.8]] },
  { name: "Hawaiki",          rfs: 2018, path: [[-33.8, 151.2], [21.3, -157.8]] },
  { name: "EllaLink",         rfs: 2021, path: [[38.7, -8.9], [-23, -43]] },
  { name: "Google Equiano",   rfs: 2022, path: [[38.7, -8.5], [-34, 18]] },
  { name: "JUPITER",          rfs: 2020, path: [[35.6, 139.7], [23, -170], [21.3, -157.8]] },
];

// Generic country coords for cyber arc routing
export const GEO_BY_CC = {
  US: { lat: 38.9, lng: -77.0, name: "United States" },
  CN: { lat: 35.9, lng: 104.2, name: "China" },
  RU: { lat: 55.7, lng: 37.6,  name: "Russia" },
  DE: { lat: 52.5, lng: 13.4,  name: "Germany" },
  NL: { lat: 52.4, lng: 4.9,   name: "Netherlands" },
  IR: { lat: 32.4, lng: 53.7,  name: "Iran" },
  KP: { lat: 40.3, lng: 127.5, name: "North Korea" },
  UA: { lat: 49.0, lng: 32.0,  name: "Ukraine" },
  GB: { lat: 51.5, lng: -0.1,  name: "UK" },
  BR: { lat: -14.2, lng: -51.9, name: "Brazil" },
  IN: { lat: 20.6, lng: 78.9,  name: "India" },
  JP: { lat: 36.2, lng: 138.3, name: "Japan" },
  SG: { lat: 1.35, lng: 103.8, name: "Singapore" },
  AU: { lat: -25.3, lng: 133.8, name: "Australia" },
};
