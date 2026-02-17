const STORAGE_COOKIE_KEY = "cyberpulse_feed_config";
const STORAGE_LOCAL_KEY = "cyberpulse_feed_config_backup";
const COOKIE_SOFT_LIMIT = 3800;
const COOKIE_DAYS = 3650;
const COLLAPSED_STORIES = 10;
const SOURCE_COLLAPSED_STORIES = 8;
const MAX_STORIES_PER_SOURCE = 60;
const MAX_TICKER_ITEMS = 12;
const EPSS_LIMIT = 8;

const CATEGORY_ORDER = ["Threat Intel", "Vulnerabilities", "Breaches", "Malware", "Policy", "Research"];

const DEFAULT_CONFIG = {
  version: 2,
  feeds: [
    {
      id: "dark-reading",
      category: "Threat Intel",
      name: "Dark Reading",
      type: "rss",
      url: "https://www.darkreading.com/rss.xml"
    },
    {
      id: "the-record",
      category: "Breaches",
      name: "The Record",
      type: "rss",
      url: "https://therecord.media/feed"
    },
    {
      id: "google-tag",
      category: "Threat Intel",
      name: "Google TAG",
      type: "rss",
      url: "https://blog.google/threat-analysis-group/rss/"
    },
    {
      id: "securelist",
      category: "Malware",
      name: "Securelist",
      type: "rss",
      url: "https://securelist.com/feed/"
    },
    {
      id: "kaspersky-blog",
      category: "Malware",
      name: "Kaspersky Blog",
      type: "rss",
      url: "https://www.kaspersky.com/blog/feed/"
    },
    {
      id: "hacker-news",
      category: "Threat Intel",
      name: "The Hacker News",
      type: "rss",
      url: "https://feeds.feedburner.com/TheHackersNews"
    },
    {
      id: "talos-blog",
      category: "Research",
      name: "Cisco Talos",
      type: "rss",
      url: "https://blog.talosintelligence.com/rss/"
    },
    {
      id: "wired-security",
      category: "Research",
      name: "Wired Security",
      type: "rss",
      url: "https://www.wired.com/feed/category/security/latest/rss"
    },
    {
      id: "security-week",
      category: "Threat Intel",
      name: "SecurityWeek",
      type: "rss",
      url: "https://www.securityweek.com/feed/"
    },
    {
      id: "sans-isc",
      category: "Threat Intel",
      name: "SANS ISC",
      type: "rss",
      url: "https://isc.sans.edu/rssfeed.xml"
    },
    {
      id: "help-net-security",
      category: "Threat Intel",
      name: "Help Net Security",
      type: "rss",
      url: "https://www.helpnetsecurity.com/feed/"
    },
    {
      id: "infosecurity-mag",
      category: "Breaches",
      name: "Infosecurity Magazine",
      type: "rss",
      url: "https://www.infosecurity-magazine.com/rss/news/"
    },
    {
      id: "cso-online",
      category: "Policy",
      name: "CSO Online",
      type: "rss",
      url: "https://www.csoonline.com/feed/"
    },
    {
      id: "the-register-security",
      category: "Research",
      name: "The Register Security",
      type: "rss",
      url: "https://www.theregister.com/security/headlines.atom"
    },
    {
      id: "schneier-security",
      category: "Research",
      name: "Schneier on Security",
      type: "rss",
      url: "https://www.schneier.com/feed/"
    },
    {
      id: "ncsc-all",
      category: "Policy",
      name: "NCSC UK",
      type: "rss",
      url: "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml"
    },
    {
      id: "nvd-cves",
      category: "Vulnerabilities",
      name: "NVD Recent CVEs",
      type: "nvd",
      url: "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=80"
    }
  ]
};

const THREAT_KEYWORDS = [
  "ransomware",
  "zero-day",
  "cve",
  "vulnerability",
  "breach",
  "malware",
  "phishing",
  "botnet",
  "exploit",
  "backdoor",
  "patch",
  "supply chain",
  "apt",
  "data leak",
  "critical"
];

const state = {
  config: loadConfig(),
  isLoading: false,
  activeView: "dashboard",
  activeCategory: "All",
  activeSourceCategory: "All",
  sourceSearch: "",
  expandedSections: new Set(),
  expandedSources: new Set(),
  sections: new Map(),
  sourceGroups: [],
  feedHealth: new Map(),
  epssItems: [],
  nvdSummary: {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  },
  lastRefreshAt: null
};

const ui = {
  board: document.getElementById("board"),
  threatTicker: document.getElementById("threatTicker"),
  categoryNav: document.getElementById("categoryNav"),
  viewDashboardBtn: document.getElementById("viewDashboardBtn"),
  viewSourcesBtn: document.getElementById("viewSourcesBtn"),
  dashboardView: document.getElementById("dashboardView"),
  sourcesView: document.getElementById("sourcesView"),
  sourceSummary: document.getElementById("sourceSummary"),
  sourceSearch: document.getElementById("sourceSearch"),
  sourceCategoryNav: document.getElementById("sourceCategoryNav"),
  sourceBoard: document.getElementById("sourceBoard"),
  feedTags: document.getElementById("feedTags"),
  addFeedForm: document.getElementById("addFeedForm"),
  refreshBtn: document.getElementById("refreshBtn"),
  exportBtn: document.getElementById("exportBtn"),
  importBtn: document.getElementById("importBtn"),
  importFile: document.getElementById("importFile"),
  todayLabel: document.getElementById("todayLabel"),
  statusLine: document.getElementById("statusLine"),
  activityChart: document.getElementById("activityChart"),
  categoryChart: document.getElementById("categoryChart"),
  keywordChart: document.getElementById("keywordChart"),
  epssList: document.getElementById("epssList"),
  kpiSignals: document.getElementById("kpiSignals"),
  kpiHighRisk: document.getElementById("kpiHighRisk"),
  kpiSources: document.getElementById("kpiSources"),
  kpiRisk: document.getElementById("kpiRisk"),
  sectionTemplate: document.getElementById("sectionTemplate"),
  storyTemplate: document.getElementById("storyTemplate"),
  sourceTemplate: document.getElementById("sourceTemplate")
};

init();

function init() {
  if (window.location.hash === "#sources") {
    state.activeView = "sources";
  }

  renderToday();
  persistConfig();
  bindEvents();
  renderViewSwitch();
  renderFeedTags();
  refreshDashboard();
}

function bindEvents() {
  ui.addFeedForm.addEventListener("submit", handleAddFeed);
  ui.feedTags.addEventListener("click", handleFeedTagClick);
  ui.board.addEventListener("click", handleBoardClick);
  ui.sourceBoard.addEventListener("click", handleBoardClick);
  ui.categoryNav.addEventListener("click", handleCategoryNavClick);
  ui.sourceCategoryNav.addEventListener("click", handleSourceCategoryNavClick);
  ui.sourceSearch.addEventListener("input", handleSourceSearchInput);
  ui.viewDashboardBtn.addEventListener("click", () => switchView("dashboard"));
  ui.viewSourcesBtn.addEventListener("click", () => switchView("sources"));
  window.addEventListener("hashchange", handleHashChange);
  ui.refreshBtn.addEventListener("click", refreshDashboard);
  ui.exportBtn.addEventListener("click", exportConfig);
  ui.importBtn.addEventListener("click", () => ui.importFile.click());
  ui.importFile.addEventListener("change", handleImportFile);
}

function renderToday() {
  const formatter = new Intl.DateTimeFormat("en-US", {
    weekday: "short",
    month: "short",
    day: "numeric"
  });

  ui.todayLabel.textContent = formatter.format(new Date());
}

function handleAddFeed(event) {
  event.preventDefault();

  const form = new FormData(ui.addFeedForm);
  const feed = normalizeFeed({
    id: createFeedId(),
    category: form.get("category"),
    name: form.get("name"),
    url: form.get("url"),
    type: "rss"
  });

  if (!feed) {
    setStatus("Feed values are invalid.", true);
    return;
  }

  const exists = state.config.feeds.some(
    (entry) => entry.type === feed.type && entry.url.toLowerCase() === feed.url.toLowerCase()
  );
  if (exists) {
    setStatus("That feed already exists.", true);
    return;
  }

  state.config.feeds.push(feed);
  if (!persistConfig()) {
    setStatus("Saved to local backup. Cookie size limit exceeded.", true);
  } else {
    setStatus("Feed added and saved.");
  }

  ui.addFeedForm.reset();
  renderFeedTags();
  refreshDashboard();
}

function handleFeedTagClick(event) {
  const removeButton = event.target.closest("button[data-remove-feed]");
  if (!removeButton) {
    return;
  }

  const feedId = removeButton.getAttribute("data-remove-feed");
  const nextFeeds = state.config.feeds.filter((feed) => feed.id !== feedId);

  if (nextFeeds.length === state.config.feeds.length) {
    return;
  }

  state.config.feeds = nextFeeds;
  persistConfig();
  renderFeedTags();
  refreshDashboard();
  setStatus("Feed removed.");
}

function handleBoardClick(event) {
  const toggle = event.target.closest("a[data-section-toggle]");
  const sourceToggle = event.target.closest("a[data-source-toggle]");

  if (!toggle && !sourceToggle) {
    return;
  }

  if (sourceToggle) {
    event.preventDefault();

    const sourceId = sourceToggle.getAttribute("data-source-toggle");
    if (!sourceId) {
      return;
    }

    if (state.expandedSources.has(sourceId)) {
      state.expandedSources.delete(sourceId);
      setStatus("Collapsed source feed view.");
    } else {
      state.expandedSources.add(sourceId);
      setStatus("Expanded source feed view.");
    }

    renderSourcesPage();
    return;
  }

  event.preventDefault();
  const section = toggle.getAttribute("data-section-toggle");
  if (!section) {
    return;
  }

  if (state.expandedSections.has(section)) {
    state.expandedSections.delete(section);
    setStatus(`Collapsed ${section}.`);
  } else {
    state.expandedSections.add(section);
    setStatus(`Expanded ${section}.`);
  }

  renderBoard();
}

function handleCategoryNavClick(event) {
  const button = event.target.closest("button[data-category]");
  if (!button) {
    return;
  }

  const nextCategory = button.getAttribute("data-category") || "All";
  if (state.activeCategory === nextCategory) {
    return;
  }

  state.activeCategory = nextCategory;
  renderCategoryNav();
  renderBoard();
  renderThreatTicker();
  renderTelemetry();
  setStatus(`Viewing ${nextCategory} category.`);
}

function handleSourceCategoryNavClick(event) {
  const button = event.target.closest("button[data-source-category]");
  if (!button) {
    return;
  }

  const nextCategory = button.getAttribute("data-source-category") || "All";
  if (state.activeSourceCategory === nextCategory) {
    return;
  }

  state.activeSourceCategory = nextCategory;
  renderSourceCategoryNav();
  renderSourcesPage();
  setStatus(`Filtering sources by ${nextCategory}.`);
}

function handleSourceSearchInput(event) {
  state.sourceSearch = (event.target.value || "").trim().toLowerCase();
  renderSourcesPage();
}

function switchView(view) {
  if (state.activeView === view) {
    return;
  }

  state.activeView = view;
  const nextHash = view === "sources" ? "#sources" : "#dashboard";
  if (window.location.hash !== nextHash) {
    window.location.hash = nextHash;
  }
  renderViewSwitch();

  if (view === "sources") {
    setStatus("Viewing source websites page.");
  } else {
    setStatus("Viewing dashboard.");
  }
}

function handleHashChange() {
  if (window.location.hash === "#sources" && state.activeView !== "sources") {
    state.activeView = "sources";
    renderViewSwitch();
    return;
  }

  if (window.location.hash !== "#sources" && state.activeView !== "dashboard") {
    state.activeView = "dashboard";
    renderViewSwitch();
  }
}

function renderViewSwitch() {
  const showDashboard = state.activeView === "dashboard";
  ui.dashboardView.hidden = !showDashboard;
  ui.sourcesView.hidden = showDashboard;

  ui.viewDashboardBtn.classList.toggle("active", showDashboard);
  ui.viewSourcesBtn.classList.toggle("active", !showDashboard);
}

function renderFeedTags() {
  ui.feedTags.innerHTML = "";

  if (!state.config.feeds.length) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "No feeds configured. Add one above or import a JSON config.";
    ui.feedTags.appendChild(empty);
    return;
  }

  for (const feed of state.config.feeds) {
    const tag = document.createElement("span");
    tag.className = "feed-tag";

    const label = document.createElement("span");
    label.textContent = `${feed.category}: ${feed.name}`;

    const remove = document.createElement("button");
    remove.type = "button";
    remove.setAttribute("aria-label", `Remove ${feed.name}`);
    remove.setAttribute("data-remove-feed", feed.id);
    remove.textContent = "x";

    tag.appendChild(label);
    tag.appendChild(remove);
    ui.feedTags.appendChild(tag);
  }
}

async function refreshDashboard() {
  if (state.isLoading) {
    return;
  }

  if (!state.config.feeds.length) {
    state.sections = new Map();
    state.sourceGroups = [];
    state.feedHealth = new Map();
    state.expandedSections.clear();
    state.expandedSources.clear();
    renderCategoryNav();
    renderThreatTicker();
    renderBoard();
    renderSourceCategoryNav();
    renderSourcesPage();
    renderTelemetry();
    renderEpss();
    setStatus("No feeds configured.", true);
    return;
  }

  state.isLoading = true;
  setStatus("Loading cyber feeds and telemetry...");

  try {
    const results = await Promise.allSettled(state.config.feeds.map((feed) => loadFeedStories(feed)));
    const grouped = groupStories(results, state.config.feeds);

    state.sections = grouped.sections;
    state.sourceGroups = grouped.sourceGroups;
    state.feedHealth = grouped.feedHealth;
    state.lastRefreshAt = new Date();

    syncExpandedSections();
    syncExpandedSources();

    const categories = Array.from(state.sections.keys());
    if (state.activeCategory !== "All" && !categories.includes(state.activeCategory)) {
      state.activeCategory = "All";
    }

    const sourceCategories = new Set(state.sourceGroups.map((group) => group.category));
    if (state.activeSourceCategory !== "All" && !sourceCategories.has(state.activeSourceCategory)) {
      state.activeSourceCategory = "All";
    }

    renderCategoryNav();
    renderThreatTicker();
    renderBoard();
    renderSourceCategoryNav();
    renderSourcesPage();
    renderTelemetry();

    await refreshEpssTelemetry();

    const loadedCount = Array.from(state.feedHealth.values()).filter((item) => item.ok).length;
    const failedCount = state.config.feeds.length - loadedCount;

    if (failedCount > 0) {
      setStatus(
        `Loaded ${loadedCount}/${state.config.feeds.length} feeds at ${formatClock(state.lastRefreshAt)}. ${failedCount} source(s) failed.`,
        true
      );
    } else {
      setStatus(`Loaded ${loadedCount} feeds at ${formatClock(state.lastRefreshAt)}.`);
    }
  } catch (error) {
    state.sections = new Map();
    state.sourceGroups = [];
    state.feedHealth = new Map();
    state.expandedSections.clear();
    state.expandedSources.clear();

    renderCategoryNav();
    renderThreatTicker();
    renderBoard();
    renderSourceCategoryNav();
    renderSourcesPage();
    renderTelemetry();
    renderEpss();

    setStatus(error.message || "Failed to refresh dashboard.", true);
  } finally {
    state.isLoading = false;
  }
}

async function loadFeedStories(feed) {
  if (feed.type === "nvd") {
    return loadNvdStories(feed);
  }

  return loadRssStories(feed);
}

async function loadRssStories(feed) {
  const attempts = [
    async () => parseXmlFeed(await fetchText(feed.url)).items,
    async () => parseXmlFeed(await fetchText(buildCodeTabsProxy(feed.url), true)).items,
    async () => fetchViaRss2Json(feed.url)
  ];

  let lastError = new Error("Unknown feed error.");

  for (const attempt of attempts) {
    try {
      const items = await attempt();
      const stories = items.map((item) => mapRssStory(item, feed)).filter(Boolean);
      if (!stories.length) {
        throw new Error("No stories found.");
      }

      return stories.slice(0, MAX_STORIES_PER_SOURCE);
    } catch (error) {
      lastError = error;
    }
  }

  throw new Error(lastError.message || `${feed.name} unavailable.`);
}

async function loadNvdStories(feed) {
  const response = await fetch(buildRecentNvdUrl(feed.url), {
    headers: {
      Accept: "application/json"
    }
  });

  if (!response.ok) {
    throw new Error(`NVD API HTTP ${response.status}`);
  }

  const payload = await response.json();
  const vulnerabilities = Array.isArray(payload.vulnerabilities) ? payload.vulnerabilities : [];

  const summary = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  };

  const stories = vulnerabilities
    .map((entry) => {
      const cve = entry.cve;
      if (!cve || !cve.id) {
        return null;
      }

      const severity = extractCvssInfo(cve.metrics);
      const severityLabel = normalizeSeverity(severity.label, severity.baseScore);

      if (severityLabel === "CRITICAL") {
        summary.critical += 1;
      } else if (severityLabel === "HIGH") {
        summary.high += 1;
      } else if (severityLabel === "MEDIUM") {
        summary.medium += 1;
      } else {
        summary.low += 1;
      }

      const englishDescription = readEnglishDescription(cve.descriptions);
      const description = trimText(englishDescription || "No description available.", 128);
      const title = `${cve.id} [${severityLabel}] ${description}`;
      const dateMs = Date.parse(cve.published || "");

      return {
        category: feed.category,
        source: feed.name,
        sourceType: "nvd",
        sourceUrl: feed.url,
        title,
        link: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve.id)}`,
        time: Number.isNaN(dateMs) ? 0 : dateMs,
        timeText: Number.isNaN(dateMs) ? "" : formatRelativeTime(dateMs),
        score: severityToThreatScore(severity.baseScore),
        severity: severityLabel
      };
    })
    .filter(Boolean)
    .sort((a, b) => b.time - a.time)
    .slice(0, MAX_STORIES_PER_SOURCE);

  state.nvdSummary = summary;
  return stories;
}

async function fetchText(url, isProxy = false) {
  const response = await fetch(url, {
    headers: {
      Accept: "application/rss+xml, application/xml, text/xml, application/atom+xml, */*"
    }
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }

  const text = await response.text();
  if (isBotChallengePage(text)) {
    throw new Error("Blocked by anti-bot protection.");
  }

  if (!looksLikeFeedXml(text) && !isProxy) {
    throw new Error("Response is not RSS/Atom XML.");
  }

  return text;
}

async function fetchViaRss2Json(url) {
  const endpoint = `https://api.rss2json.com/v1/api.json?rss_url=${encodeURIComponent(url)}`;
  const response = await fetch(endpoint);

  if (!response.ok) {
    throw new Error(`rss2json HTTP ${response.status}`);
  }

  const payload = await response.json();
  if (payload.status !== "ok") {
    throw new Error(payload.message || "rss2json failed.");
  }

  const items = Array.isArray(payload.items) ? payload.items : [];
  return items.map((item) => ({
    title: sanitizeInlineText(item.title || ""),
    link: item.link || item.guid || "",
    date: item.pubDate || item.published || item.updated || ""
  }));
}

function parseXmlFeed(xmlText) {
  const parser = new DOMParser();
  const doc = parser.parseFromString(xmlText, "application/xml");

  if (doc.querySelector("parsererror")) {
    throw new Error("Invalid XML payload.");
  }

  let entries = Array.from(doc.querySelectorAll("channel > item"));
  if (!entries.length) {
    entries = Array.from(doc.querySelectorAll("feed > entry"));
  }

  return {
    items: entries
      .map((entry) => ({
        title: readText(entry, ["title"]),
        link: readLink(entry),
        date: readText(entry, ["pubDate", "published", "updated", "dc\\:date"])
      }))
      .filter((item) => item.title && item.link)
  };
}

function readLink(node) {
  const explicit = node.querySelector('link[rel="alternate"][href], link[href]');
  if (explicit) {
    return explicit.getAttribute("href") || "";
  }

  const plain = node.querySelector("link");
  if (!plain) {
    return "";
  }

  const href = plain.getAttribute("href");
  if (href) {
    return href;
  }

  return plain.textContent ? plain.textContent.trim() : "";
}

function readText(node, selectors) {
  for (const selector of selectors) {
    const target = node.querySelector(selector);
    if (!target) {
      continue;
    }

    const value = sanitizeInlineText(target.textContent || "");
    if (value) {
      return value;
    }
  }

  return "";
}

function mapRssStory(item, feed) {
  const title = trimText(sanitizeInlineText(item.title || "Untitled"), 140);
  const link = item.link || feed.url;

  if (!title || !link) {
    return null;
  }

  const dateMs = Date.parse(item.date || "");

  return {
    category: feed.category,
    source: feed.name,
    sourceType: "rss",
    sourceUrl: feed.url,
    title,
    link,
    time: Number.isNaN(dateMs) ? 0 : dateMs,
    timeText: Number.isNaN(dateMs) ? "" : formatRelativeTime(dateMs),
    score: computeThreatScore(title),
    severity: ""
  };
}

function groupStories(results, feeds) {
  const sections = new Map();
  const feedHealth = new Map();
  const sourceGroups = [];

  for (const feed of feeds) {
    if (!sections.has(feed.category)) {
      sections.set(feed.category, []);
    }
  }

  results.forEach((result, index) => {
    const feed = feeds[index];

    if (result.status !== "fulfilled") {
      feedHealth.set(feed.id, {
        ok: false,
        message: result.reason?.message || "Load failed."
      });

      sourceGroups.push({
        id: feed.id,
        category: feed.category,
        name: feed.name,
        type: feed.type,
        url: feed.url,
        stories: [],
        ok: false,
        message: result.reason?.message || "Load failed."
      });
      return;
    }

    const stories = Array.isArray(result.value) ? result.value : [];
    const bucket = sections.get(feed.category) || [];
    bucket.push(...stories);
    sections.set(feed.category, bucket);

    feedHealth.set(feed.id, {
      ok: true,
      message: `Loaded ${stories.length} stories.`
    });

    sourceGroups.push({
      id: feed.id,
      category: feed.category,
      name: feed.name,
      type: feed.type,
      url: feed.url,
      stories,
      ok: true,
      message: `Loaded ${stories.length} stories.`
    });
  });

  for (const [category, stories] of sections) {
    stories.sort((a, b) => {
      if (b.time !== a.time) {
        return b.time - a.time;
      }
      return b.score - a.score;
    });
  }

  sourceGroups.sort((a, b) => {
    const aIndex = CATEGORY_ORDER.indexOf(a.category);
    const bIndex = CATEGORY_ORDER.indexOf(b.category);

    if (aIndex !== bIndex) {
      if (aIndex === -1) {
        return 1;
      }
      if (bIndex === -1) {
        return -1;
      }
      return aIndex - bIndex;
    }

    return a.name.localeCompare(b.name);
  });

  return {
    sections,
    feedHealth,
    sourceGroups
  };
}

function syncExpandedSections() {
  for (const section of Array.from(state.expandedSections)) {
    if (!state.sections.has(section)) {
      state.expandedSections.delete(section);
    }
  }
}

function syncExpandedSources() {
  const validSourceIds = new Set(state.sourceGroups.map((group) => group.id));
  for (const sourceId of Array.from(state.expandedSources)) {
    if (!validSourceIds.has(sourceId)) {
      state.expandedSources.delete(sourceId);
    }
  }
}

function renderCategoryNav() {
  ui.categoryNav.innerHTML = "";

  const categories = sortedCategoriesFromState();
  const counts = new Map(categories.map((category) => [category, (state.sections.get(category) || []).length]));
  const allCount = Array.from(counts.values()).reduce((sum, value) => sum + value, 0);

  const allButton = document.createElement("button");
  allButton.type = "button";
  allButton.className = "category-pill";
  allButton.setAttribute("data-category", "All");
  allButton.textContent = `All (${allCount})`;
  allButton.classList.toggle("active", state.activeCategory === "All");
  ui.categoryNav.appendChild(allButton);

  for (const category of categories) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "category-pill";
    button.setAttribute("data-category", category);
    button.textContent = `${category} (${counts.get(category) || 0})`;
    button.classList.toggle("active", state.activeCategory === category);
    ui.categoryNav.appendChild(button);
  }
}

function renderSourceCategoryNav() {
  ui.sourceCategoryNav.innerHTML = "";

  const counts = new Map();
  for (const group of state.sourceGroups) {
    counts.set(group.category, (counts.get(group.category) || 0) + 1);
  }

  const categories = Array.from(counts.keys()).sort((a, b) => {
    const aIndex = CATEGORY_ORDER.indexOf(a);
    const bIndex = CATEGORY_ORDER.indexOf(b);

    if (aIndex === -1 && bIndex === -1) {
      return a.localeCompare(b);
    }
    if (aIndex === -1) {
      return 1;
    }
    if (bIndex === -1) {
      return -1;
    }
    return aIndex - bIndex;
  });

  const allButton = document.createElement("button");
  allButton.type = "button";
  allButton.className = "category-pill";
  allButton.setAttribute("data-source-category", "All");
  allButton.textContent = `All Sources (${state.sourceGroups.length})`;
  allButton.classList.toggle("active", state.activeSourceCategory === "All");
  ui.sourceCategoryNav.appendChild(allButton);

  for (const category of categories) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "category-pill";
    button.setAttribute("data-source-category", category);
    button.textContent = `${category} (${counts.get(category) || 0})`;
    button.classList.toggle("active", state.activeSourceCategory === category);
    ui.sourceCategoryNav.appendChild(button);
  }
}

function getVisibleSourceGroups() {
  const search = state.sourceSearch;

  return state.sourceGroups.filter((group) => {
    if (state.activeSourceCategory !== "All" && group.category !== state.activeSourceCategory) {
      return false;
    }

    if (!search) {
      return true;
    }

    const haystack = `${group.name} ${group.category} ${group.url}`.toLowerCase();
    return haystack.includes(search);
  });
}

function renderSourcesPage() {
  ui.sourceBoard.innerHTML = "";

  const visibleGroups = getVisibleSourceGroups();
  const totalStories = visibleGroups.reduce((sum, group) => sum + group.stories.length, 0);

  ui.sourceSummary.textContent =
    `${visibleGroups.length} source site${visibleGroups.length === 1 ? "" : "s"} • ` +
    `${totalStories} visible stories`;

  if (!visibleGroups.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "No sources match this filter.";
    ui.sourceBoard.appendChild(empty);
    return;
  }

  for (const group of visibleGroups) {
    const fragment = ui.sourceTemplate.content.cloneNode(true);
    const card = fragment.querySelector(".source-card");
    const title = fragment.querySelector(".source-title");
    const stateNode = fragment.querySelector(".source-state");
    const category = fragment.querySelector(".source-category");
    const sourceUrl = fragment.querySelector(".source-url");
    const list = fragment.querySelector(".source-story-list");
    const moreLink = fragment.querySelector(".source-more-link");

    const stories = group.stories;
    const isExpanded = state.expandedSources.has(group.id);
    const canExpand = stories.length > SOURCE_COLLAPSED_STORIES;
    const visibleStories = isExpanded ? stories : stories.slice(0, SOURCE_COLLAPSED_STORIES);

    title.textContent = group.name;
    category.textContent = group.category;
    sourceUrl.href = group.url;
    sourceUrl.textContent = group.url.replace(/^https?:\/\//, "");

    stateNode.textContent = group.ok
      ? `${stories.length} ${stories.length === 1 ? "story" : "stories"}`
      : "offline";
    stateNode.classList.toggle("offline", !group.ok);
    card.classList.toggle("expanded", isExpanded);

    if (!stories.length) {
      const row = document.createElement("li");
      row.className = "story-row";
      row.textContent = group.ok
        ? "No stories loaded for this source."
        : `Source unavailable: ${group.message}`;
      list.appendChild(row);
    } else {
      for (const story of visibleStories) {
        const storyFragment = ui.storyTemplate.content.cloneNode(true);
        const row = storyFragment.querySelector(".story-row");
        const link = storyFragment.querySelector(".story-link");
        const meta = storyFragment.querySelector(".story-meta");

        if (story.score >= 7) {
          row.classList.add("risk-high");
        } else if (story.score >= 4) {
          row.classList.add("risk-medium");
        }

        link.textContent = story.title;
        link.href = story.link;

        const metaChunks = [];
        if (story.timeText) {
          metaChunks.push(story.timeText);
        }
        if (story.severity) {
          metaChunks.push(story.severity);
        }
        if (story.category && story.category !== group.category) {
          metaChunks.push(story.category);
        }

        meta.textContent = metaChunks.join(" • ") || group.category;
        list.appendChild(storyFragment);
      }
    }

    moreLink.href = "#";
    moreLink.classList.remove("disabled");
    moreLink.removeAttribute("data-source-toggle");

    if (canExpand) {
      moreLink.setAttribute("data-source-toggle", group.id);
      moreLink.textContent = isExpanded
        ? "Show less"
        : `More ... (${stories.length - SOURCE_COLLAPSED_STORIES})`;
    } else if (!group.ok) {
      moreLink.textContent = "Source unavailable";
      moreLink.classList.add("disabled");
    } else {
      moreLink.textContent = stories.length ? "No more stories" : "No stories";
      moreLink.classList.add("disabled");
    }

    ui.sourceBoard.appendChild(card);
  }
}

function renderThreatTicker() {
  ui.threatTicker.innerHTML = "";

  const visibleStories = getVisibleStories();
  if (!visibleStories.length) {
    ui.threatTicker.textContent = "No threat headlines available for the current selection.";
    return;
  }

  const topStories = visibleStories
    .filter((story) => story.time > 0)
    .sort((a, b) => b.time - a.time)
    .slice(0, MAX_TICKER_ITEMS);

  if (!topStories.length) {
    ui.threatTicker.textContent = "No timestamped headlines available for the current selection.";
    return;
  }

  const fragment = document.createDocumentFragment();

  topStories.forEach((story, index) => {
    const link = document.createElement("a");
    link.href = story.link;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.textContent = `${story.source}: ${story.title}`;
    fragment.appendChild(link);

    if (index < topStories.length - 1) {
      const sep = document.createElement("span");
      sep.textContent = "  •  ";
      fragment.appendChild(sep);
    }
  });

  ui.threatTicker.appendChild(fragment);
}

function renderBoard() {
  ui.board.innerHTML = "";

  const visibleCategories = getVisibleCategories();

  if (!visibleCategories.length) {
    renderEmptyBoard("No categories available.");
    return;
  }

  let renderedCards = 0;

  for (const category of visibleCategories) {
    const stories = state.sections.get(category) || [];

    if (state.activeCategory !== "All" && category !== state.activeCategory) {
      continue;
    }

    renderedCards += 1;

    const fragment = ui.sectionTemplate.content.cloneNode(true);
    const card = fragment.querySelector(".section-card");
    const title = fragment.querySelector("h2");
    const count = fragment.querySelector(".section-count");
    const list = fragment.querySelector(".story-list");
    const moreLink = fragment.querySelector(".more-link");

    const isExpanded = state.expandedSections.has(category);
    const canExpand = stories.length > COLLAPSED_STORIES;
    const visibleStories = isExpanded ? stories : stories.slice(0, COLLAPSED_STORIES);

    title.textContent = category;
    count.textContent = `${stories.length} ${stories.length === 1 ? "story" : "stories"}`;
    card.classList.toggle("expanded", isExpanded);

    if (!stories.length) {
      const row = document.createElement("li");
      row.className = "story-row";
      row.textContent = "No stories loaded for this category.";
      list.appendChild(row);
    } else {
      for (const story of visibleStories) {
        const storyFragment = ui.storyTemplate.content.cloneNode(true);
        const row = storyFragment.querySelector(".story-row");
        const link = storyFragment.querySelector(".story-link");
        const meta = storyFragment.querySelector(".story-meta");

        if (story.score >= 7) {
          row.classList.add("risk-high");
        } else if (story.score >= 4) {
          row.classList.add("risk-medium");
        }

        link.textContent = story.title;
        link.href = story.link;

        const metaChunks = [story.source];
        if (story.timeText) {
          metaChunks.push(story.timeText);
        }
        if (story.severity) {
          metaChunks.push(story.severity);
        }

        meta.textContent = metaChunks.join(" • ");
        list.appendChild(storyFragment);
      }
    }

    moreLink.href = "#";
    moreLink.classList.remove("disabled");
    moreLink.removeAttribute("data-section-toggle");

    if (canExpand) {
      moreLink.setAttribute("data-section-toggle", category);
      moreLink.textContent = isExpanded
        ? "Show less"
        : `More ... (${stories.length - COLLAPSED_STORIES})`;
    } else {
      moreLink.textContent = stories.length ? "No more stories" : "No stories";
      moreLink.classList.add("disabled");
    }

    ui.board.appendChild(card);
  }

  if (!renderedCards) {
    renderEmptyBoard("No stories available for this category selection.");
  }
}

function renderTelemetry() {
  const visibleStories = getVisibleStories();
  const last24hStories = visibleStories.filter((story) => isWithinHours(story.time, 24));
  const highRisk = visibleStories.filter((story) => story.score >= 7);

  const onlineSources = Array.from(state.feedHealth.values()).filter((feed) => feed.ok).length;
  const totalSources = state.config.feeds.length;

  const riskIndex = computeRiskIndex(visibleStories, highRisk, last24hStories, state.nvdSummary);

  ui.kpiSignals.textContent = String(last24hStories.length);
  ui.kpiHighRisk.textContent = String(highRisk.length);
  ui.kpiSources.textContent = `${onlineSources}/${totalSources}`;
  ui.kpiRisk.textContent = `${riskIndex}/100`;

  renderActivityChart(visibleStories);
  renderCategoryChart(visibleStories);
  renderKeywordChart(visibleStories);
}

function renderActivityChart(stories) {
  ui.activityChart.innerHTML = "";

  const bins = Array.from({ length: 24 }, () => 0);
  const now = Date.now();

  for (const story of stories) {
    if (!story.time || story.time > now) {
      continue;
    }

    const hoursAgo = Math.floor((now - story.time) / 3600000);
    if (hoursAgo < 0 || hoursAgo >= 24) {
      continue;
    }

    bins[23 - hoursAgo] += 1;
  }

  const max = Math.max(...bins, 1);

  bins.forEach((value, index) => {
    const bar = document.createElement("div");
    bar.className = "activity-bar";
    bar.style.height = `${Math.max(6, Math.round((value / max) * 100))}%`;
    bar.title = `${index + 1}h bin: ${value}`;
    ui.activityChart.appendChild(bar);
  });
}

function renderCategoryChart(stories) {
  ui.categoryChart.innerHTML = "";

  const counts = new Map();
  for (const story of stories) {
    counts.set(story.category, (counts.get(story.category) || 0) + 1);
  }

  const entries = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
  if (!entries.length) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "No data.";
    ui.categoryChart.appendChild(empty);
    return;
  }

  const max = Math.max(...entries.map((entry) => entry[1]), 1);

  for (const [label, value] of entries) {
    const row = buildMetricRow(label, value, max);
    ui.categoryChart.appendChild(row);
  }
}

function renderKeywordChart(stories) {
  ui.keywordChart.innerHTML = "";

  const counts = countKeywords(stories);
  const top = Array.from(counts.entries())
    .filter((entry) => entry[1] > 0)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8);

  if (!top.length) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "No keyword hits.";
    ui.keywordChart.appendChild(empty);
    return;
  }

  const max = Math.max(...top.map((entry) => entry[1]), 1);

  for (const [keyword, value] of top) {
    const row = buildMetricRow(keyword, value, max);
    ui.keywordChart.appendChild(row);
  }
}

function buildMetricRow(label, value, max) {
  const container = document.createElement("div");
  container.className = "metric-row";

  const labelNode = document.createElement("span");
  labelNode.className = "metric-label";
  labelNode.textContent = label;

  const valueNode = document.createElement("span");
  valueNode.className = "metric-value";
  valueNode.textContent = String(value);

  const track = document.createElement("div");
  track.className = "metric-track";

  const fill = document.createElement("div");
  fill.className = "metric-fill";
  fill.style.width = `${Math.max(6, Math.round((value / max) * 100))}%`;

  track.appendChild(fill);
  container.appendChild(labelNode);
  container.appendChild(valueNode);
  container.appendChild(track);

  return container;
}

async function refreshEpssTelemetry() {
  try {
    const endpoint = `https://api.first.org/data/v1/epss?order=!epss&limit=${EPSS_LIMIT}`;
    const response = await fetch(endpoint, {
      headers: {
        Accept: "application/json"
      }
    });

    if (!response.ok) {
      throw new Error(`EPSS API HTTP ${response.status}`);
    }

    const payload = await response.json();
    const data = Array.isArray(payload.data) ? payload.data : [];

    state.epssItems = data
      .map((entry) => ({
        cve: entry.cve,
        epss: Number.parseFloat(entry.epss),
        percentile: Number.parseFloat(entry.percentile)
      }))
      .filter((entry) => entry.cve && Number.isFinite(entry.epss));

    renderEpss();
  } catch {
    state.epssItems = [];
    renderEpss("EPSS telemetry unavailable right now.");
  }
}

function renderEpss(errorMessage = "") {
  ui.epssList.innerHTML = "";

  if (errorMessage) {
    const li = document.createElement("li");
    li.textContent = errorMessage;
    ui.epssList.appendChild(li);
    return;
  }

  if (!state.epssItems.length) {
    const li = document.createElement("li");
    li.textContent = "No EPSS entries loaded.";
    ui.epssList.appendChild(li);
    return;
  }

  for (const item of state.epssItems) {
    const li = document.createElement("li");

    const link = document.createElement("a");
    link.href = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(item.cve)}`;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.textContent = item.cve;

    const score = document.createElement("span");
    score.className = "epss-score";
    score.textContent = `  EPSS ${item.epss.toFixed(3)} | P${Math.round(item.percentile * 100)}`;

    li.appendChild(link);
    li.appendChild(score);
    ui.epssList.appendChild(li);
  }
}

function renderEmptyBoard(message) {
  ui.board.innerHTML = "";
  const empty = document.createElement("div");
  empty.className = "empty-state";
  empty.textContent = message;
  ui.board.appendChild(empty);
}

function getVisibleCategories() {
  return sortedCategoriesFromState();
}

function getVisibleStories() {
  const categories = getVisibleCategories();

  if (state.activeCategory === "All") {
    const output = [];
    for (const category of categories) {
      output.push(...(state.sections.get(category) || []));
    }
    return output;
  }

  return state.sections.get(state.activeCategory) || [];
}

function sortedCategoriesFromState() {
  const categories = Array.from(state.sections.keys());

  return categories.sort((a, b) => {
    const aIndex = CATEGORY_ORDER.indexOf(a);
    const bIndex = CATEGORY_ORDER.indexOf(b);

    if (aIndex === -1 && bIndex === -1) {
      return a.localeCompare(b);
    }

    if (aIndex === -1) {
      return 1;
    }

    if (bIndex === -1) {
      return -1;
    }

    return aIndex - bIndex;
  });
}

function countKeywords(stories) {
  const counts = new Map(THREAT_KEYWORDS.map((keyword) => [keyword, 0]));

  for (const story of stories) {
    const title = story.title.toLowerCase();
    for (const keyword of THREAT_KEYWORDS) {
      if (title.includes(keyword)) {
        counts.set(keyword, (counts.get(keyword) || 0) + 1);
      }
    }
  }

  return counts;
}

function computeRiskIndex(stories, highRiskStories, stories24h, nvdSummary) {
  if (!stories.length) {
    return 0;
  }

  const highRiskWeight = highRiskStories.length * 2.2;
  const recentWeight = stories24h.length * 1.1;
  const criticalCvssWeight = (nvdSummary.critical || 0) * 0.6;

  const raw = ((highRiskWeight + recentWeight + criticalCvssWeight) / stories.length) * 24;
  return Math.max(0, Math.min(100, Math.round(raw)));
}

function computeThreatScore(title) {
  const text = title.toLowerCase();
  let score = 1;

  if (/critical|actively exploited|zero-day|0-day|rce|remote code execution|wormable/.test(text)) {
    score += 4;
  }
  if (/ransomware|breach|data leak|stolen|exposed|botnet|backdoor|malware|trojan/.test(text)) {
    score += 3;
  }
  if (/vulnerability|cve-|exploit|phishing|advisory|patch/.test(text)) {
    score += 2;
  }
  if (/campaign|apt|threat actor|supply chain/.test(text)) {
    score += 2;
  }

  return Math.min(10, score);
}

function severityToThreatScore(baseScore) {
  if (baseScore >= 9) {
    return 10;
  }
  if (baseScore >= 7) {
    return 8;
  }
  if (baseScore >= 4) {
    return 5;
  }
  if (baseScore > 0) {
    return 3;
  }
  return 2;
}

function extractCvssInfo(metrics) {
  const groups = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"];

  for (const group of groups) {
    const entries = metrics && Array.isArray(metrics[group]) ? metrics[group] : null;
    if (!entries || !entries.length) {
      continue;
    }

    const metric = entries[0];
    const cvssData = metric.cvssData || {};

    return {
      baseScore: Number.parseFloat(cvssData.baseScore || metric.baseScore || 0) || 0,
      label: String(cvssData.baseSeverity || metric.baseSeverity || "UNKNOWN")
    };
  }

  return {
    baseScore: 0,
    label: "UNKNOWN"
  };
}

function normalizeSeverity(label, baseScore) {
  const upper = String(label || "").toUpperCase();
  if (upper && upper !== "UNKNOWN") {
    return upper;
  }

  if (baseScore >= 9) {
    return "CRITICAL";
  }
  if (baseScore >= 7) {
    return "HIGH";
  }
  if (baseScore >= 4) {
    return "MEDIUM";
  }
  if (baseScore > 0) {
    return "LOW";
  }

  return "UNKNOWN";
}

function readEnglishDescription(descriptions) {
  if (!Array.isArray(descriptions)) {
    return "";
  }

  const english = descriptions.find((entry) => entry.lang === "en" && entry.value);
  if (english) {
    return sanitizeInlineText(english.value);
  }

  const first = descriptions.find((entry) => entry.value);
  return first ? sanitizeInlineText(first.value) : "";
}

function isWithinHours(timestamp, hours) {
  if (!timestamp || Number.isNaN(timestamp)) {
    return false;
  }

  const diff = Date.now() - timestamp;
  return diff >= 0 && diff <= hours * 3600000;
}

function trimText(text, maxChars) {
  if (text.length <= maxChars) {
    return text;
  }

  return `${text.slice(0, maxChars - 3)}...`;
}

function looksLikeFeedXml(text) {
  const sample = text.trim().slice(0, 180).toLowerCase();
  return sample.startsWith("<?xml") || sample.startsWith("<rss") || sample.startsWith("<feed");
}

function isBotChallengePage(text) {
  const lower = text.toLowerCase();
  return lower.includes("just a moment") && lower.includes("cf_chl");
}

function buildCodeTabsProxy(url) {
  return `https://api.codetabs.com/v1/proxy?quest=${encodeURIComponent(url)}`;
}

function buildRecentNvdUrl(baseUrl) {
  const endpoint = new URL(baseUrl);
  const endDate = new Date();
  const startDate = new Date(endDate.getTime() - 14 * 24 * 60 * 60 * 1000);

  endpoint.searchParams.set("resultsPerPage", "120");
  endpoint.searchParams.set("pubStartDate", formatNvdDate(startDate));
  endpoint.searchParams.set("pubEndDate", formatNvdDate(endDate));

  return endpoint.toString();
}

function formatNvdDate(date) {
  return date.toISOString().replace(/\.\d{3}Z$/, ".000Z");
}

function exportConfig() {
  const payload = {
    version: 2,
    exportedAt: new Date().toISOString(),
    feeds: state.config.feeds
  };

  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const href = URL.createObjectURL(blob);
  const link = document.createElement("a");
  const datePart = new Date().toISOString().slice(0, 10);

  link.href = href;
  link.download = `cyberpulse-feeds-${datePart}.json`;
  link.click();

  URL.revokeObjectURL(href);
  setStatus("Feed configuration exported.");
}

async function handleImportFile(event) {
  const file = event.target.files && event.target.files[0];
  if (!file) {
    return;
  }

  try {
    const content = await file.text();
    const parsed = JSON.parse(content);

    const feeds = Array.isArray(parsed)
      ? parsed
      : Array.isArray(parsed.feeds)
      ? parsed.feeds
      : [];

    if (!feeds.length) {
      throw new Error("Imported JSON has no feeds.");
    }

    const normalized = feeds.map(normalizeFeed).filter(Boolean);
    if (!normalized.length) {
      throw new Error("No valid feeds found in import file.");
    }

    state.config = {
      version: 2,
      feeds: dedupeFeeds(normalized)
    };

    persistConfig();
    renderFeedTags();
    refreshDashboard();
    setStatus(`Imported ${state.config.feeds.length} feeds.`);
  } catch (error) {
    setStatus(error.message || "Failed to import feeds.", true);
  } finally {
    ui.importFile.value = "";
  }
}

function dedupeFeeds(feeds) {
  const seen = new Set();
  const output = [];

  for (const feed of feeds) {
    const key = `${feed.type}|${feed.url.toLowerCase()}`;
    if (seen.has(key)) {
      continue;
    }

    seen.add(key);
    output.push(feed);
  }

  return output;
}

function normalizeFeed(feed) {
  if (!feed || typeof feed !== "object") {
    return null;
  }

  const category = sanitizeInlineText(String(feed.category || "")).trim();
  const name = sanitizeInlineText(String(feed.name || "")).trim();
  const type = sanitizeInlineText(String(feed.type || "rss")).trim().toLowerCase();
  const rawUrl = String(feed.url || "").trim();

  if (!category || !name || !rawUrl || !["rss", "nvd"].includes(type)) {
    return null;
  }

  let url = "";
  try {
    url = new URL(rawUrl).toString();
  } catch {
    return null;
  }

  return {
    id: feed.id && String(feed.id).trim() ? String(feed.id).trim() : createFeedId(),
    category,
    name,
    type,
    url
  };
}

function loadConfig() {
  const cookieValue = getCookie(STORAGE_COOKIE_KEY);
  if (cookieValue) {
    const parsed = parseConfig(cookieValue);
    if (parsed) {
      return parsed;
    }
  }

  const localValue = localStorage.getItem(STORAGE_LOCAL_KEY);
  if (localValue) {
    const parsed = parseConfig(localValue);
    if (parsed) {
      return parsed;
    }
  }

  return structuredClone(DEFAULT_CONFIG);
}

function parseConfig(value) {
  try {
    const parsed = JSON.parse(value);
    if (!parsed || typeof parsed !== "object") {
      return null;
    }

    const feeds = Array.isArray(parsed.feeds) ? parsed.feeds.map(normalizeFeed).filter(Boolean) : [];
    if (!feeds.length) {
      return null;
    }

    return {
      version: 2,
      feeds: dedupeFeeds(feeds)
    };
  } catch {
    return null;
  }
}

function persistConfig() {
  const payload = JSON.stringify(state.config);
  const encodedSize = encodeURIComponent(payload).length;

  localStorage.setItem(STORAGE_LOCAL_KEY, payload);

  if (encodedSize > COOKIE_SOFT_LIMIT) {
    clearCookie(STORAGE_COOKIE_KEY);
    return false;
  }

  setCookie(STORAGE_COOKIE_KEY, payload, COOKIE_DAYS);
  return true;
}

function setCookie(name, value, days) {
  const expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toUTCString();
  document.cookie = `${name}=${encodeURIComponent(value)}; expires=${expiresAt}; path=/; SameSite=Lax`;
}

function clearCookie(name) {
  document.cookie = `${name}=; Max-Age=0; path=/; SameSite=Lax`;
}

function getCookie(name) {
  const key = `${name}=`;
  const parts = document.cookie.split(";");

  for (const part of parts) {
    const trimmed = part.trim();
    if (!trimmed.startsWith(key)) {
      continue;
    }

    return decodeURIComponent(trimmed.slice(key.length));
  }

  return "";
}

function sanitizeInlineText(value) {
  const tmp = document.createElement("div");
  tmp.innerHTML = value;
  return (tmp.textContent || "").replace(/\s+/g, " ").trim();
}

function setStatus(message, warning = false) {
  ui.statusLine.textContent = message;
  ui.statusLine.classList.toggle("warning", warning);
}

function formatRelativeTime(timestamp) {
  const diffMs = Date.now() - timestamp;

  if (diffMs < 0) {
    return "just now";
  }

  const minutes = Math.floor(diffMs / 60000);
  if (minutes < 1) {
    return "just now";
  }

  if (minutes < 60) {
    return `${minutes}m ago`;
  }

  const hours = Math.floor(minutes / 60);
  if (hours < 24) {
    return `${hours}h ago`;
  }

  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function formatClock(date) {
  return new Intl.DateTimeFormat("en-US", {
    hour: "numeric",
    minute: "2-digit"
  }).format(date);
}

function createFeedId() {
  if (window.crypto && typeof window.crypto.randomUUID === "function") {
    return window.crypto.randomUUID();
  }

  return `feed-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}
