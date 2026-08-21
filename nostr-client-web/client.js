/*
 * Nostr client for this page.
 *
 * Reads bootstrap.txt for the author npub and the relay list, connects to every
 * relay in parallel, and renders the results into the category panels.
 *
 * Categories are declared in CATEGORIES below. Every category with `filter`
 * set is fetched in the background on load, regardless of which tab is
 * selected, so switching tabs is instant. To add a category, give it a filter
 * and a render function -- nothing else needs to change.
 *
 * Everything arriving from a relay is untrusted: text goes in via textContent,
 * and URLs are passed through safeUrl() before they reach an href or src.
 */
(function () {
  'use strict';

  var BOOTSTRAP = 'bootstrap.txt';
  var EOSE_GRACE = 1500;   // ms to keep a socket open after EOSE for late events
  var CONNECT_TIMEOUT = 12000;

  /* ------------------------------------------------------------------ *
   * Categories
   * ------------------------------------------------------------------ */

  var MEDIA_TAGS = ['meme', 'photography', 'video'];

  var CATEGORIES = {
    shortform: { filter: { kinds: [1], limit: 100 }, render: renderShortform },
    longform:  { filter: { kinds: [30023], limit: 100 }, render: renderLongform },
    // Shortform notes tagged as media. The relay-side '#t' filter does the
    // work; MEDIA_TAGS is re-checked client-side so odd casing still matches.
    media:     { filter: { kinds: [1], '#t': MEDIA_TAGS, limit: 100 }, render: renderMedia },
    ebooks: {
      // 33953 standalone ebook, 34609 publication/series, 39731 issue of a series.
      filter: { kinds: [33953, 34609, 39731], limit: 200 },
      render: renderEbooks
    },
    // Saved links (NIP-B0 web bookmarks) and marked passages (NIP-84
    // highlights), interleaved on one timeline.
    bookmarks: { filter: { kinds: [39701, 9802], limit: 200 }, render: renderBookmarks }
  };

  /* ------------------------------------------------------------------ *
   * bech32 (NIP-19)
   * ------------------------------------------------------------------ */

  var CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

  function polymod(values) {
    var GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    var chk = 1;
    for (var i = 0; i < values.length; i++) {
      var top = chk >> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ values[i];
      for (var j = 0; j < 5; j++) if ((top >> j) & 1) chk ^= GEN[j];
    }
    return chk;
  }

  function hrpExpand(hrp) {
    var out = [], i;
    for (i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >> 5);
    out.push(0);
    for (i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 31);
    return out;
  }

  function convertBits(data, from, to, pad) {
    var acc = 0, bits = 0, out = [], maxv = (1 << to) - 1;
    for (var i = 0; i < data.length; i++) {
      acc = (acc << from) | data[i];
      bits += from;
      while (bits >= to) { bits -= to; out.push((acc >> bits) & maxv); }
    }
    if (pad && bits > 0) out.push((acc << (to - bits)) & maxv);
    return out;
  }

  function bech32Decode(str) {
    var s = str.toLowerCase();
    var pos = s.lastIndexOf('1');
    if (pos < 1 || pos + 7 > s.length) return null;
    var hrp = s.slice(0, pos), data = [];
    for (var i = pos + 1; i < s.length; i++) {
      var v = CHARSET.indexOf(s.charAt(i));
      if (v === -1) return null;
      data.push(v);
    }
    if (polymod(hrpExpand(hrp).concat(data)) !== 1) return null;
    return { hrp: hrp, data: data.slice(0, data.length - 6) };
  }

  function bech32Encode(hrp, data) {
    var values = hrpExpand(hrp).concat(data);
    var chk = polymod(values.concat([0, 0, 0, 0, 0, 0])) ^ 1;
    var out = hrp + '1';
    for (var i = 0; i < data.length; i++) out += CHARSET.charAt(data[i]);
    for (var k = 0; k < 6; k++) out += CHARSET.charAt((chk >> (5 * (5 - k))) & 31);
    return out;
  }

  function npubToHex(npub) {
    var d = bech32Decode(npub.trim());
    if (!d || d.hrp !== 'npub') return null;
    var bytes = convertBits(d.data, 5, 8, false).slice(0, 32);
    if (bytes.length !== 32) return null;
    return bytes.map(function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
  }

  function hexToBytes(hex) {
    var out = [];
    for (var i = 0; i + 1 < hex.length; i += 2) out.push(parseInt(hex.substr(i, 2), 16));
    return out;
  }

  function utf8Bytes(str) {
    var out = [], enc = encodeURIComponent(str);
    for (var i = 0; i < enc.length; i++) {
      if (enc.charAt(i) === '%') { out.push(parseInt(enc.substr(i + 1, 2), 16)); i += 2; }
      else out.push(enc.charCodeAt(i));
    }
    return out;
  }

  function tlv(type, bytes) { return [type, bytes.length].concat(bytes); }

  // naddr for an addressable event (kind:pubkey:d-tag).
  function encodeNaddr(kind, pubkeyHex, identifier) {
    var bytes = []
      .concat(tlv(0, utf8Bytes(identifier)))
      .concat(tlv(2, hexToBytes(pubkeyHex)))
      .concat(tlv(3, [(kind >> 24) & 255, (kind >> 16) & 255, (kind >> 8) & 255, kind & 255]));
    return bech32Encode('naddr', convertBits(bytes, 8, 5, true));
  }

  // note1 for a plain event id.
  function encodeNote(idHex) {
    return bech32Encode('note', convertBits(hexToBytes(idHex), 8, 5, true));
  }

  // npub1 for a raw pubkey.
  function encodeNpub(pubkeyHex) {
    if (!/^[0-9a-f]{64}$/i.test(pubkeyHex)) return null;
    return bech32Encode('npub', convertBits(hexToBytes(pubkeyHex), 8, 5, true));
  }

  /* ------------------------------------------------------------------ *
   * bootstrap.txt
   * ------------------------------------------------------------------ */

  function parseBootstrap(text) {
    var cfg = { npub: null, relays: [] };
    text.split(/\r?\n/).forEach(function (raw) {
      var line = raw.split('#')[0].trim();
      if (!line) return;
      var i = line.indexOf(':');
      if (i === -1) return;
      var key = line.slice(0, i).trim().toLowerCase();
      var value = line.slice(i + 1).trim();
      if (!value) return;
      if (key === 'npub') cfg.npub = value;
      else if (key === 'relay') cfg.relays.push(value);
    });
    return cfg;
  }

  /* ------------------------------------------------------------------ *
   * Event helpers
   * ------------------------------------------------------------------ */

  function tagValue(ev, name) {
    for (var i = 0; i < ev.tags.length; i++) {
      if (ev.tags[i][0] === name && ev.tags[i].length > 1) return ev.tags[i][1];
    }
    return null;
  }

  function tagValues(ev, name) {
    var out = [];
    ev.tags.forEach(function (t) { if (t[0] === name && t.length > 1) out.push(t[1]); });
    return out;
  }

  function isAddressable(kind) {
    return (kind >= 30000 && kind < 40000) || (kind >= 10000 && kind < 20000) || kind === 0 || kind === 3;
  }

  // Replaceable events collapse to one entry per (kind, d); newest wins.
  function eventKey(ev) {
    return isAddressable(ev.kind) ? ev.kind + ':' + (tagValue(ev, 'd') || '') : ev.id;
  }

  function published(ev) {
    var p = parseInt(tagValue(ev, 'published_at'), 10);
    return isFinite(p) && p > 0 ? p : ev.created_at;
  }

  /* ------------------------------------------------------------------ *
   * Formatting / sanitising
   * ------------------------------------------------------------------ */

  function safeUrl(url) {
    if (!url) return null;
    try {
      var u = new URL(url, location.href);
      return (u.protocol === 'https:' || u.protocol === 'http:') ? u.href : null;
    } catch (e) { return null; }
  }

  function formatDate(seconds) {
    var d = new Date(seconds * 1000);
    return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  }

  function formatDateTime(seconds) {
    var d = new Date(seconds * 1000);
    return formatDate(seconds) + ' · ' +
      d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
  }

  function formatSize(bytes) {
    var n = parseInt(bytes, 10);
    if (!isFinite(n) || n <= 0) return null;
    var units = ['B', 'KB', 'MB', 'GB'], i = 0;
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
    return (n >= 10 || i === 0 ? Math.round(n) : n.toFixed(1)) + ' ' + units[i];
  }

  var MIME_LABELS = {
    'application/pdf': 'PDF',
    'application/epub+zip': 'EPUB',
    'application/x-mobipocket-ebook': 'MOBI',
    'application/vnd.amazon.ebook': 'AZW'
  };

  function formatType(mime, url) {
    if (mime && MIME_LABELS[mime]) return MIME_LABELS[mime];
    var m = /\.([a-z0-9]{2,5})(?:[?#]|$)/i.exec(url || '');
    if (m) return m[1].toUpperCase();
    return mime ? mime.split('/').pop().toUpperCase() : null;
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
  }

  // Plain text with bare http(s) URLs turned into links. Never uses innerHTML.
  function linkify(container, text) {
    var re = /https?:\/\/[^\s<>"')]+/g, last = 0, m;
    while ((m = re.exec(text)) !== null) {
      if (m.index > last) container.appendChild(document.createTextNode(text.slice(last, m.index)));
      var href = safeUrl(m[0]);
      if (href) {
        var a = el('a', null, m[0]);
        a.href = href;
        a.rel = 'noopener noreferrer nofollow';
        a.target = '_blank';
        container.appendChild(a);
      } else {
        container.appendChild(document.createTextNode(m[0]));
      }
      last = m.index + m[0].length;
    }
    if (last < text.length) container.appendChild(document.createTextNode(text.slice(last)));
  }

  /* ------------------------------------------------------------------ *
   * YouTube embeds
   *
   * Rendered as a click-to-play facade: the card shows a thumbnail, and the
   * player iframe is only created once the reader presses play. Dropping a
   * live iframe per link would pull YouTube's player onto every card in the
   * feed. Playback uses youtube-nocookie.com.
   * ------------------------------------------------------------------ */

  function parseStart(value) {
    if (!value) return 0;
    if (/^\d+$/.test(value)) return parseInt(value, 10);
    var m = /^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/.exec(value);
    if (!m) return 0;
    return (parseInt(m[1] || 0, 10) * 3600) + (parseInt(m[2] || 0, 10) * 60) + parseInt(m[3] || 0, 10);
  }

  function youtubeInfo(url) {
    var u;
    try { u = new URL(url, location.href); } catch (e) { return null; }
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;

    var host = u.hostname.replace(/^(?:www\.|m\.|music\.)/i, '').toLowerCase();
    var id = null;
    if (host === 'youtu.be') {
      id = u.pathname.split('/')[1];
    } else if (host === 'youtube.com') {
      if (u.pathname === '/watch') id = u.searchParams.get('v');
      else if (/^\/(?:shorts|embed|live|v)\//.test(u.pathname)) id = u.pathname.split('/')[2];
    }
    if (!id || !/^[\w-]{11}$/.test(id)) return null;

    return {
      id: id,
      start: parseStart(u.searchParams.get('t') || u.searchParams.get('start')),
      url: u.href
    };
  }

  function youtubeEmbed(info) {
    var wrap = el('div', 'yt_embed');

    var facade = el('button', 'yt_facade');
    facade.type = 'button';
    facade.setAttribute('aria-label', 'Play video on YouTube');

    var thumb = document.createElement('img');
    thumb.src = 'https://i.ytimg.com/vi/' + info.id + '/hqdefault.jpg';
    thumb.alt = '';
    thumb.loading = 'lazy';
    thumb.referrerPolicy = 'no-referrer';
    facade.appendChild(thumb);
    facade.appendChild(el('span', 'yt_play'));

    facade.addEventListener('click', function () {
      var frame = document.createElement('iframe');
      frame.className = 'yt_frame';
      frame.src = 'https://www.youtube-nocookie.com/embed/' + info.id +
        '?autoplay=1&rel=0' + (info.start ? '&start=' + info.start : '');
      frame.title = 'YouTube video player';
      frame.allow = 'accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share';
      frame.allowFullscreen = true;
      frame.referrerPolicy = 'strict-origin-when-cross-origin';
      wrap.replaceChild(frame, facade);
    });

    wrap.appendChild(facade);

    var caption = el('div', 'yt_caption');
    var link = el('a', null, 'Watch on YouTube');
    link.href = info.url;
    link.rel = 'noopener noreferrer';
    link.target = '_blank';
    caption.appendChild(link);
    wrap.appendChild(caption);

    return wrap;
  }

  // Appends one embed per distinct YouTube link found in `text`.
  function appendYoutubeEmbeds(container, text) {
    var re = /https?:\/\/[^\s<>"')]+/g, seen = {}, m, added = 0;
    while ((m = re.exec(String(text || ''))) !== null) {
      var info = youtubeInfo(m[0]);
      if (info && !seen[info.id]) {
        seen[info.id] = true;
        container.appendChild(youtubeEmbed(info));
        added++;
      }
    }
    return added;
  }

  /* ------------------------------------------------------------------ *
   * Relay pool
   * ------------------------------------------------------------------ */

  /*
   * One WebSocket per relay, shared by every subscription. Opening a separate
   * socket per category meant seven relays x four subscriptions = 28 connections,
   * and relays that cap connections per client silently dropped some of them,
   * so the feed came back short.
   */
  function RelayPool(urls) {
    this.urls = urls;
    this.conns = {};
    this.status = {};
    this.listeners = [];
  }

  RelayPool.prototype.onStatus = function (fn) { this.listeners.push(fn); };

  RelayPool.prototype.setStatus = function (url, state) {
    this.status[url] = state;
    var self = this;
    this.listeners.forEach(function (fn) { fn(url, state, self.status); });
  };

  RelayPool.prototype.conn = function (url) {
    if (this.conns[url]) return this.conns[url];

    var self = this;
    var conn = { ws: null, ready: false, dead: false, queue: [], subs: {}, idleTimer: null };
    this.conns[url] = conn;

    function killAll() {
      if (conn.dead) return;
      conn.dead = true;
      clearTimeout(conn.idleTimer);
      Object.keys(conn.subs).forEach(function (id) {
        var sub = conn.subs[id];
        delete conn.subs[id];
        sub.done();
      });
      conn.queue.length = 0;
    }

    try { conn.ws = new WebSocket(url); }
    catch (e) { this.setStatus(url, 'error'); killAll(); return conn; }

    this.setStatus(url, 'connecting');
    var connectTimer = setTimeout(function () {
      if (!conn.ready) { self.setStatus(url, 'error'); try { conn.ws.close(); } catch (e) {} killAll(); }
    }, CONNECT_TIMEOUT);

    conn.ws.onopen = function () {
      clearTimeout(connectTimer);
      conn.ready = true;
      self.setStatus(url, 'connected');
      conn.queue.splice(0).forEach(function (msg) { conn.ws.send(msg); });
    };

    conn.ws.onerror = function () {
      clearTimeout(connectTimer);
      self.setStatus(url, 'error');
      killAll();
    };

    conn.ws.onclose = function () {
      clearTimeout(connectTimer);
      killAll();
    };

    conn.ws.onmessage = function (msg) {
      var data;
      try { data = JSON.parse(msg.data); } catch (e) { return; }
      if (!Array.isArray(data)) return;

      var sub = conn.subs[data[1]];
      if (!sub) return;

      if (data[0] === 'EVENT' && data[2]) {
        sub.onEvent(data[2], url);
      } else if (data[0] === 'EOSE') {
        // Stored events are in; hold briefly for stragglers, then drop the sub.
        clearTimeout(sub.graceTimer);
        sub.graceTimer = setTimeout(function () { self.closeSub(url, data[1]); }, EOSE_GRACE);
      } else if (data[0] === 'CLOSED') {
        self.closeSub(url, data[1]);
      }
    };

    return conn;
  };

  RelayPool.prototype.send = function (conn, msg) {
    if (conn.dead) return;
    if (conn.ready) { try { conn.ws.send(msg); } catch (e) {} }
    else conn.queue.push(msg);
  };

  RelayPool.prototype.closeSub = function (url, subId) {
    var conn = this.conns[url];
    if (!conn) return;
    var sub = conn.subs[subId];
    if (!sub) return;
    clearTimeout(sub.graceTimer);
    delete conn.subs[subId];
    this.send(conn, JSON.stringify(['CLOSE', subId]));
    sub.done();
    this.maybeIdle(url);
  };

  // Nothing left to listen for: close the socket, but give later subscriptions
  // a moment to reuse it first.
  RelayPool.prototype.maybeIdle = function (url) {
    var conn = this.conns[url];
    if (!conn || conn.dead) return;
    clearTimeout(conn.idleTimer);
    conn.idleTimer = setTimeout(function () {
      if (!Object.keys(conn.subs).length) { try { conn.ws.close(); } catch (e) {} }
    }, 3000);
  };

  /*
   * Runs one subscription across every relay. onEvent fires per event (possibly
   * the same event from several relays -- the store dedupes), onDone fires once
   * every relay has finished or failed.
   */
  RelayPool.prototype.subscribe = function (subId, filter, onEvent, onDone) {
    var self = this;
    var pending = this.urls.length;
    if (!pending) { onDone(); return; }

    var settle = function () { if (--pending === 0) onDone(); };

    this.urls.forEach(function (url) {
      var conn = self.conn(url);
      if (conn.dead) { settle(); return; }

      var finished = false;
      conn.subs[subId] = {
        onEvent: onEvent,
        graceTimer: null,
        done: function () { if (!finished) { finished = true; settle(); } }
      };
      clearTimeout(conn.idleTimer);
      self.send(conn, JSON.stringify(['REQ', subId, filter]));
    });
  };

  /* ------------------------------------------------------------------ *
   * Rendering: ebooks
   * ------------------------------------------------------------------ */

  function coverNode(imageUrl, title, href) {
    var url = safeUrl(imageUrl);
    if (!url) return null;
    var wrap = el(href ? 'a' : 'div', 'card_cover');
    if (href) { wrap.href = href; wrap.rel = 'noopener noreferrer'; wrap.target = '_blank'; }
    var img = document.createElement('img');
    img.src = url;
    img.alt = title ? 'Cover of ' + title : '';
    img.loading = 'lazy';
    img.referrerPolicy = 'no-referrer';
    img.addEventListener('error', function () { wrap.remove(); });
    wrap.appendChild(img);
    return wrap;
  }

  function metaSpan(parent, text) {
    if (text) parent.appendChild(el('span', 'pale', text));
  }

  function ebookCard(ev, seriesByAddr, pubkey) {
    var title = tagValue(ev, 'title') || tagValue(ev, 'd') || 'Untitled';
    var fileUrls = tagValues(ev, 'url').map(safeUrl).filter(Boolean);
    var primary = fileUrls[0] || null;
    var identifier = tagValue(ev, 'd');

    var item = el('li', 'note_item');
    var layout = el('div', 'card_layout');

    var cover = coverNode(tagValue(ev, 'image'), title, primary);
    if (cover) layout.appendChild(cover);
    else layout.classList.add('card_layout_nocover');

    var main = el('div', 'card_main');

    // Title
    var header = el('div', 'note_header');
    var h3 = el('h3', 'note_title');
    var titleLink = el('a', null, title);
    if (identifier) {
      titleLink.href = 'https://njump.me/' + encodeNaddr(ev.kind, pubkey, identifier);
      titleLink.rel = 'noopener noreferrer';
      titleLink.target = '_blank';
    } else if (primary) {
      titleLink.href = primary;
      titleLink.rel = 'noopener noreferrer';
      titleLink.target = '_blank';
    }
    h3.appendChild(titleLink);
    header.appendChild(h3);

    // Meta line: date, author, series/issue, format, size, language
    var meta = el('div', 'note_meta');
    metaSpan(meta, formatDate(published(ev)));

    var author = tagValue(ev, 'author');
    if (author) metaSpan(meta, 'by ' + author);

    if (ev.kind === 39731) {
      var series = seriesByAddr[tagValue(ev, 'a')];
      var issue = tagValue(ev, 'issue');
      var label = series ? (tagValue(series, 'title') || 'Series') : null;
      if (label && issue) metaSpan(meta, label + ' · Issue ' + issue);
      else if (label) metaSpan(meta, label);
      else if (issue) metaSpan(meta, 'Issue ' + issue);
    } else if (ev.kind === 34609) {
      metaSpan(meta, 'Series');
    }

    var type = formatType(tagValue(ev, 'm'), primary);
    var size = formatSize(tagValue(ev, 'size'));
    if (type && size) metaSpan(meta, type + ' · ' + size);
    else if (type) metaSpan(meta, type);
    else if (size) metaSpan(meta, size);

    var lang = tagValue(ev, 'l');
    if (lang) metaSpan(meta, lang.toUpperCase());

    header.appendChild(meta);
    main.appendChild(header);

    // Body: summary tag, then the event content if it adds anything.
    var summary = tagValue(ev, 'summary');
    var content = (ev.content || '').trim();
    if (summary) {
      main.appendChild(el('div', 'note_body', summary));
    }
    if (content && content !== summary) {
      var body = el('div', 'note_body' + (summary ? ' note_body_secondary' : ''));
      linkify(body, content);
      main.appendChild(body);
    }
    var embedWrap = el('div', 'card_embeds');
    if (appendYoutubeEmbeds(embedWrap, content + ' ' + (summary || ''))) main.appendChild(embedWrap);

    // Footer: download + mirrors + topic tags
    var footer = el('div', 'note_footer');
    if (primary) {
      var dl = el('a', 'button', type ? 'Download ' + type : 'Download');
      dl.href = primary;
      dl.rel = 'noopener noreferrer';
      dl.target = '_blank';
      footer.appendChild(dl);
    }
    if (fileUrls.length > 1) {
      var mirrors = el('span', 'card_mirrors');
      mirrors.appendChild(document.createTextNode('Mirrors: '));
      fileUrls.slice(1).forEach(function (url, i) {
        var a = el('a', null, new URL(url).hostname);
        a.href = url;
        a.rel = 'noopener noreferrer';
        a.target = '_blank';
        if (i) mirrors.appendChild(document.createTextNode(', '));
        mirrors.appendChild(a);
      });
      footer.appendChild(mirrors);
    }

    var topics = tagValues(ev, 't');
    if (topics.length) {
      var tagWrap = el('div', 'card_tags');
      topics.slice(0, 8).forEach(function (t) {
        tagWrap.appendChild(el('span', 'button button_translucent', t));
      });
      footer.appendChild(tagWrap);
    }

    main.appendChild(footer);
    layout.appendChild(main);
    item.appendChild(layout);
    return item;
  }

  function renderEbooks(events, ctx) {
    // Index series (34609) so issues (39731) can name their parent.
    var seriesByAddr = {};
    events.forEach(function (ev) {
      if (ev.kind === 34609) {
        seriesByAddr['34609:' + ev.pubkey + ':' + (tagValue(ev, 'd') || '')] = ev;
      }
    });

    // A series with issues is represented by its issues, not by itself.
    var seriesWithIssues = {};
    events.forEach(function (ev) {
      if (ev.kind === 39731) {
        var a = tagValue(ev, 'a');
        if (a) seriesWithIssues[a] = true;
      }
    });

    var items = events.filter(function (ev) {
      if (ev.kind === 34609) {
        return !seriesWithIssues['34609:' + ev.pubkey + ':' + (tagValue(ev, 'd') || '')];
      }
      return true;
    });

    items.sort(function (a, b) { return published(b) - published(a); });

    var frag = document.createDocumentFragment();
    items.forEach(function (ev) { frag.appendChild(ebookCard(ev, seriesByAddr, ctx.pubkey)); });
    return { node: frag, count: items.length };
  }

  /* ------------------------------------------------------------------ *
   * Markdown (NIP-23 long-form content)
   *
   * A deliberately small subset: headings, paragraphs, lists, quotes, code,
   * rules, links and images. Everything is built with DOM nodes, so relay
   * content can never inject markup.
   * ------------------------------------------------------------------ */

  var INLINE_SRC = [
    '\\\\([!-\\/:-@\\[-`{-~])',                 // 1    backslash escape
    '!\\[([^\\]]*)\\]\\(([^)\\s]+)[^)]*\\)',   // 2,3  image
    '\\[([^\\]]*)\\]\\(([^)\\s]+)[^)]*\\)',    // 4,5  link
    '`([^`]+)`',                               // 6    code
    '\\*\\*([^*]+)\\*\\*',                     // 7    bold
    '__([^_]+)__',                             // 8    bold
    '\\*([^*\\n]+)\\*',                        // 9    italic
    '(https?://[^\\s<>"\')]+)'                 // 10   bare url
  ].join('|');

  // Strips backslash escapes for places that take plain text (alt, title).
  function unescapeMd(text) {
    return String(text == null ? '' : text).replace(/\\([!-\/:-@\[-`{-~])/g, '$1');
  }

  /*
   * inline=true parses the label as markdown, so escapes and emphasis inside
   * [a \"quoted\" label](url) render properly. Bare urls pass inline=false --
   * running the parser over the url text would nest a link inside the link.
   */
  function externalLink(href, text, inline) {
    var url = safeUrl(href);
    if (!url) {
      if (!inline) return document.createTextNode(text);
      var span = el('span');
      mdInline(span, text, true);
      return span;
    }
    var a = el('a');
    if (inline) mdInline(a, text, true);   // true: no links nested inside a link
    else a.textContent = text;
    a.href = url;
    a.rel = 'noopener noreferrer nofollow';
    a.target = '_blank';
    return a;
  }

  /*
   * A trailing backslash is markdown's hard line break. Lines inside a
   * paragraph are already joined with <br>, so the marker itself is dropped --
   * but "\\" at the end is an escaped backslash and stays for mdInline.
   */
  function isHardBreak(line) {
    return /(?:^|[^\\])\\$/.test(line) || /\s{2,}$/.test(line);
  }

  function stripHardBreak(line) {
    return /(?:^|[^\\])\\$/.test(line) ? line.slice(0, -1) : line;
  }

  function mdInline(parent, text, inLink) {
    // Each call gets its own regex: mdInline recurses for bold/italic, and a
    // shared /g/ regex would have its lastIndex reset by the inner call,
    // restarting the outer scan from zero -- an infinite loop.
    var re = new RegExp(INLINE_SRC, 'g');
    var last = 0, m;
    while ((m = re.exec(text)) !== null) {
      if (m[0] === '') { re.lastIndex++; continue; }
      if (m.index > last) parent.appendChild(document.createTextNode(text.slice(last, m.index)));
      last = m.index + m[0].length;

      if (m[1] !== undefined) {                       // \" \' \[ \* ...
        parent.appendChild(document.createTextNode(m[1]));
      } else if (m[3] !== undefined) {                // image
        var src = safeUrl(m[3]);
        if (src) {
          var img = document.createElement('img');
          img.className = 'md_img';
          img.src = src;
          img.alt = unescapeMd(m[2]);
          img.loading = 'lazy';
          img.referrerPolicy = 'no-referrer';
          parent.appendChild(img);
        } else {
          parent.appendChild(document.createTextNode(unescapeMd(m[2])));
        }
      } else if (m[5] !== undefined) {                // link
        if (inLink) mdInline(parent, m[4] || m[5], true);
        else parent.appendChild(externalLink(m[5], m[4] || m[5], !!m[4]));
      } else if (m[6] !== undefined) {                // inline code
        parent.appendChild(el('code', null, m[6]));
      } else if (m[7] !== undefined || m[8] !== undefined) {
        var strong = el('strong');
        mdInline(strong, m[7] !== undefined ? m[7] : m[8], inLink);
        parent.appendChild(strong);
      } else if (m[9] !== undefined) {
        var em = el('em');
        mdInline(em, m[9], inLink);
        parent.appendChild(em);
      } else if (m[10] !== undefined) {               // bare url
        if (inLink) parent.appendChild(document.createTextNode(m[10]));
        else parent.appendChild(externalLink(m[10], m[10], false));
      }
    }
    if (last < text.length) parent.appendChild(document.createTextNode(text.slice(last)));
  }

  function isBlockStart(line) {
    return /^\s*(#{1,6}\s|>|[-*+]\s|\d+[.)]\s|```|([-*_])\s*\2\s*\2)/.test(line);
  }

  function mdBlocks(text) {
    var lines = String(text || '').replace(/\r\n/g, '\n').split('\n');
    var frag = document.createDocumentFragment();
    var i = 0, guard = -1;

    while (i < lines.length) {
      // Safety net: every branch below must consume at least one line. If one
      // ever fails to, force progress rather than hang the tab on a bad post.
      if (i === guard) { i++; continue; }
      guard = i;

      var line = lines[i];

      if (/^\s*$/.test(line)) { i++; continue; }

      // fenced code
      if (/^\s*```/.test(line)) {
        var lang = line.replace(/^\s*```/, '').trim();
        var buf = [];
        i++;
        while (i < lines.length && !/^\s*```/.test(lines[i])) { buf.push(lines[i]); i++; }
        i++; // closing fence
        var pre = el('pre');
        var code = el('code', lang ? 'language-' + lang : null, buf.join('\n'));
        pre.appendChild(code);
        frag.appendChild(pre);
        continue;
      }

      // heading -- the post title is the h1, so # starts at h2
      var h = /^\s*(#{1,6})\s+(.*)$/.exec(line);
      if (h) {
        var level = Math.min(h[1].length + 1, 6);
        var node = el('h' + level);
        mdInline(node, stripHardBreak(h[2].trim()));
        frag.appendChild(node);
        i++;
        continue;
      }

      // horizontal rule
      if (/^\s*([-*_])\s*\1\s*\1[\s\-*_]*$/.test(line)) {
        frag.appendChild(el('hr'));
        i++;
        continue;
      }

      // blockquote
      if (/^\s*>/.test(line)) {
        var quoted = [];
        while (i < lines.length && /^\s*>/.test(lines[i])) {
          quoted.push(lines[i].replace(/^\s*>\s?/, ''));
          i++;
        }
        var bq = el('blockquote');
        bq.appendChild(mdBlocks(quoted.join('\n')));
        frag.appendChild(bq);
        continue;
      }

      // lists
      var ordered = /^\s*\d+[.)]\s+/.test(line);
      if (ordered || /^\s*[-*+]\s+/.test(line)) {
        var marker = ordered ? /^\s*\d+[.)]\s+/ : /^\s*[-*+]\s+/;
        var list = el(ordered ? 'ol' : 'ul', 'md_list');
        while (i < lines.length && marker.test(lines[i])) {
          var item = stripHardBreak(lines[i].replace(marker, ''));
          i++;
          // continuation lines belong to the same item
          while (i < lines.length && !/^\s*$/.test(lines[i]) && !isBlockStart(lines[i])) {
            item += ' ' + stripHardBreak(lines[i].trim());
            i++;
          }
          var li = el('li');
          mdInline(li, item);
          list.appendChild(li);
        }
        frag.appendChild(list);
        continue;
      }

      // paragraph
      var para = [line];
      i++;
      while (i < lines.length && !/^\s*$/.test(lines[i]) && !isBlockStart(lines[i])) {
        para.push(lines[i]);
        i++;
      }
      /*
       * A plain newline inside a paragraph is a soft break: it reflows as a
       * space. Only a line ending in a backslash or two spaces is a hard break.
       * Treating every newline as <br> froze hard-wrapped posts at their
       * authored column width and made them unreadable on narrow screens.
       */
      // A link sitting alone in its own paragraph is the video, not prose.
      if (para.length === 1) {
        var lone = para[0].trim();
        var loneInfo = /^<?https?:\/\/\S+>?$/.test(lone) ? youtubeInfo(lone.replace(/^<|>$/g, '')) : null;
        if (loneInfo) {
          frag.appendChild(youtubeEmbed(loneInfo));
          continue;
        }
      }

      var p = el('p');
      para.forEach(function (text, idx) {
        var hard = isHardBreak(text);
        if (idx) p.appendChild(document.createTextNode(' '));
        mdInline(p, stripHardBreak(text).replace(/\s+$/, ''));
        if (hard && idx < para.length - 1) p.appendChild(document.createElement('br'));
      });
      frag.appendChild(p);
    }

    return frag;
  }

  /* ------------------------------------------------------------------ *
   * Lightbox -- full-screen images, with arrows when a post has several
   * ------------------------------------------------------------------ */

  /*
   * Closing an overlay unwinds the history entry it pushed, which fires a
   * popstate of our own making. Without this guard the reader would read the
   * lightbox's unwind as "back was pressed" and close itself too.
   */
  var historyGuard = 0;

  function unwindHistory() {
    historyGuard++;
    try { history.back(); } catch (e) { historyGuard--; }
  }

  var lightbox = {
    root: null,
    img: null,
    group: [],
    index: 0,
    opener: null,
    pushedState: false,

    init: function () {
      this.root = document.getElementById('lightbox');
      if (!this.root) return;
      var self = this;

      this.img = document.getElementById('lightbox_img');
      this.prevBtn = document.getElementById('lightbox_prev');
      this.nextBtn = document.getElementById('lightbox_next');
      this.count = document.getElementById('lightbox_count');

      document.getElementById('lightbox_close').addEventListener('click', function () { self.close(); });
      this.prevBtn.addEventListener('click', function (e) { e.stopPropagation(); self.step(-1); });
      this.nextBtn.addEventListener('click', function (e) { e.stopPropagation(); self.step(1); });

      // Clicking the backdrop (but not the image) closes.
      this.root.addEventListener('click', function (e) {
        if (e.target === self.root || e.target.id === 'lightbox_stage') self.close();
      });

      // Swipe between images on touch screens.
      var startX = null;
      this.root.addEventListener('touchstart', function (e) {
        startX = e.touches.length === 1 ? e.touches[0].clientX : null;
      }, { passive: true });
      this.root.addEventListener('touchend', function (e) {
        if (startX === null) return;
        var dx = e.changedTouches[0].clientX - startX;
        startX = null;
        if (Math.abs(dx) > 50) self.step(dx < 0 ? 1 : -1);
      });
    },

    isOpen: function () { return !!this.root && !this.root.hidden; },

    open: function (group, index, opener) {
      if (!this.root || !group.length) return;
      this.group = group;
      this.index = index || 0;
      this.opener = opener || null;

      this.show();
      this.root.hidden = false;
      this.root.setAttribute('aria-hidden', 'false');
      document.body.classList.add('viewing');
      document.getElementById('lightbox_close').focus();

      try {
        history.pushState({ lightbox: true }, '');
        this.pushedState = true;
      } catch (e) { this.pushedState = false; }
    },

    show: function () {
      var item = this.group[this.index];
      this.img.src = item.url;
      this.img.alt = item.alt || '';
      var many = this.group.length > 1;
      this.prevBtn.hidden = !many;
      this.nextBtn.hidden = !many;
      this.count.textContent = many ? (this.index + 1) + ' / ' + this.group.length : '';
    },

    step: function (delta) {
      if (this.group.length < 2) return;
      this.index = (this.index + delta + this.group.length) % this.group.length;
      this.show();
    },

    close: function (fromHistory) {
      if (!this.isOpen()) return;
      this.root.hidden = true;
      this.root.setAttribute('aria-hidden', 'true');
      this.img.removeAttribute('src');
      document.body.classList.remove('viewing');
      if (this.opener) { this.opener.focus(); this.opener = null; }
      if (this.pushedState) {
        this.pushedState = false;
        if (!fromHistory) unwindHistory();
      }
    }
  };

  /* ------------------------------------------------------------------ *
   * Reader overlay
   * ------------------------------------------------------------------ */

  var reader = {
    root: null,
    opener: null,
    pushedState: false,

    init: function () {
      this.root = document.getElementById('reader');
      if (!this.root) return;
      var self = this;

      var closeBtn = document.getElementById('reader_close');
      if (closeBtn) closeBtn.addEventListener('click', function () { self.close(); });

      // Click on the empty margin around the article closes it.
      var scroll = this.root.querySelector('.reader_scroll');
      if (scroll) {
        scroll.addEventListener('click', function (e) { if (e.target === scroll) self.close(); });
      }

      document.addEventListener('keydown', function (e) {
        if (lightbox.isOpen()) {
          if (e.key === 'Escape') lightbox.close();
          else if (e.key === 'ArrowLeft') lightbox.step(-1);
          else if (e.key === 'ArrowRight') lightbox.step(1);
          return;                       // the lightbox sits on top of the reader
        }
        if (e.key === 'Escape' && !self.root.hidden) self.close();
      });

      // Back gesture / browser back dismisses the topmost layer, not the page.
      window.addEventListener('popstate', function () {
        if (historyGuard > 0) { historyGuard--; return; }   // our own unwind
        if (lightbox.isOpen()) { lightbox.close(true); return; }
        if (!self.root.hidden) { self.pushedState = false; self.close(); }
      });
    },

    /*
     * opts: { title, meta: [strings], heroUrl, build: fn(container),
     *         link: {href, label}, opener: element }
     */
    open: function (opts) {
      if (!this.root) return;
      this.opener = opts.opener || null;

      document.getElementById('reader_title').textContent = opts.title || '';

      var meta = document.getElementById('reader_meta');
      meta.textContent = '';
      (opts.meta || []).forEach(function (text) { metaSpan(meta, text); });

      var hero = document.getElementById('reader_hero');
      hero.textContent = '';
      var heroUrl = safeUrl(opts.heroUrl);
      if (heroUrl) {
        var img = document.createElement('img');
        img.src = heroUrl;
        img.alt = '';
        img.referrerPolicy = 'no-referrer';
        hero.appendChild(img);
      }

      var body = document.getElementById('reader_body');
      body.textContent = '';
      body.className = 'reader_body' + (opts.bodyClass ? ' ' + opts.bodyClass : '');
      if (opts.build) opts.build(body);

      var footer = document.getElementById('reader_footer');
      footer.textContent = '';
      if (opts.link && opts.link.href) {
        var link = el('a', 'button', opts.link.label || 'Open on Nostr');
        link.href = opts.link.href;
        link.rel = 'noopener noreferrer';
        link.target = '_blank';
        footer.appendChild(link);
      }

      this.root.hidden = false;
      this.root.setAttribute('aria-hidden', 'false');
      document.body.classList.add('reading');
      this.root.querySelector('.reader_scroll').scrollTop = 0;
      var closeBtn = document.getElementById('reader_close');
      if (closeBtn) closeBtn.focus();

      try {
        history.pushState({ reader: true }, '');
        this.pushedState = true;
      } catch (e) { this.pushedState = false; }
    },

    close: function () {
      if (!this.root || this.root.hidden) return;
      this.root.hidden = true;
      this.root.setAttribute('aria-hidden', 'true');
      document.body.classList.remove('reading');
      document.getElementById('reader_body').textContent = '';
      if (this.opener) { this.opener.focus(); this.opener = null; }
      if (this.pushedState) {
        this.pushedState = false;
        unwindHistory();
      }
    }
  };

  /* ------------------------------------------------------------------ *
   * Rendering: longform (NIP-23)
   * ------------------------------------------------------------------ */

  function readingTime(content) {
    var words = String(content || '').trim().split(/\s+/).length;
    return words > 1 ? Math.max(1, Math.round(words / 200)) : 0;
  }

  function excerpt(ev) {
    var summary = tagValue(ev, 'summary');
    if (summary && summary.trim()) return summary.trim();
    // Fall back to the opening prose, minus markdown furniture.
    var text = String(ev.content || '')
      .replace(/```[\s\S]*?```/g, ' ')
      .replace(/!\[[^\]]*\]\([^)]*\)/g, ' ')
      .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
      .replace(/^\s*#{1,6}\s+.*$/gm, ' ')
      .replace(/[*_`>#]/g, '')
      .replace(/\s+/g, ' ')
      .trim();
    if (text.length <= 280) return text;
    var cut = text.slice(0, 280);
    var stop = cut.lastIndexOf(' ');
    return (stop > 200 ? cut.slice(0, stop) : cut) + '…';
  }

  function longformCard(ev, pubkey) {
    var title = tagValue(ev, 'title') || tagValue(ev, 'd') || 'Untitled';
    var identifier = tagValue(ev, 'd');

    var item = el('li', 'note_item');
    var layout = el('div', 'card_layout');

    var cover = coverNode(tagValue(ev, 'image'), title, null);
    if (cover) layout.appendChild(cover);
    else layout.classList.add('card_layout_nocover');

    var main = el('div', 'card_main');

    var header = el('div', 'note_header');
    var h3 = el('h3', 'note_title');
    var titleLink = el('a', null, title);
    titleLink.href = '#';
    h3.appendChild(titleLink);
    header.appendChild(h3);

    var meta = el('div', 'note_meta');
    metaSpan(meta, formatDate(published(ev)));
    var mins = readingTime(ev.content);
    if (mins) metaSpan(meta, mins + ' min read');
    header.appendChild(meta);
    main.appendChild(header);

    var body = excerpt(ev);
    if (body) main.appendChild(el('div', 'note_body', body));

    var footer = el('div', 'note_footer');
    var more = el('button', 'button', 'Read More');
    more.type = 'button';
    footer.appendChild(more);

    function openReader(e) {
      e.preventDefault();
      var meta = [formatDate(published(ev))];
      if (mins) meta.push(mins + ' min read');
      reader.open({
        title: title,
        meta: meta,
        heroUrl: tagValue(ev, 'image'),
        build: function (container) { container.appendChild(mdBlocks(ev.content)); },
        link: identifier ? { href: 'https://njump.me/' + encodeNaddr(ev.kind, pubkey, identifier) } : null,
        opener: more
      });
    }
    more.addEventListener('click', openReader);
    titleLink.addEventListener('click', openReader);
    if (cover && cover.tagName === 'DIV') {
      cover.classList.add('card_cover_clickable');
      cover.addEventListener('click', openReader);
    }

    main.appendChild(footer);
    layout.appendChild(main);
    item.appendChild(layout);
    return item;
  }

  function renderLongform(events, ctx) {
    var items = events.slice().sort(function (a, b) { return published(b) - published(a); });
    var frag = document.createDocumentFragment();
    items.forEach(function (ev) { frag.appendChild(longformCard(ev, ctx.pubkey)); });
    return { node: frag, count: items.length };
  }

  /* ------------------------------------------------------------------ *
   * Rendering: shortform (kind 1 notes)
   * ------------------------------------------------------------------ */

  // Replies aimed at someone else are conversation, not posts, so they are left
  // out of this feed. Replies within your own thread are kept. Set this to true
  // to show everything.
  var SHOW_REPLIES = false;

  // Notes longer than this are clipped on the card, with Read More for the rest.
  var NOTE_CLAMP = 700;

  var IMAGE_EXT = /\.(jpe?g|png|gif|webp|avif|bmp|svg)(?:[?#]|$)/i;
  var VIDEO_EXT = /\.(mp4|webm|ogv|mov|m4v)(?:[?#]|$)/i;

  function isReplyToOthers(ev) {
    var replies = ev.tags.some(function (t) { return t[0] === 'e'; });
    if (!replies) return false;
    // A note that tags another pubkey is answering that person.
    return ev.tags.some(function (t) {
      return t[0] === 'p' && t.length > 1 && t[1] !== ev.pubkey;
    });
  }

  // Media urls advertised by imeta tags, keyed by url.
  function imetaUrls(ev) {
    var urls = {};
    ev.tags.forEach(function (t) {
      if (t[0] !== 'imeta') return;
      var entry = {};
      t.slice(1).forEach(function (field) {
        var space = field.indexOf(' ');
        if (space > 0) entry[field.slice(0, space)] = field.slice(space + 1);
      });
      var url = safeUrl(entry.url);
      if (url) urls[url] = entry;
    });
    return urls;
  }

  function mediaNode(url, meta, group) {
    if (VIDEO_EXT.test(url) || (meta && /^video\//.test(meta.m || ''))) {
      var video = document.createElement('video');
      video.className = 'note_media';
      video.src = url;
      video.controls = true;
      video.preload = 'metadata';
      video.playsInline = true;
      return video;
    }
    if (IMAGE_EXT.test(url) || (meta && /^image\//.test(meta.m || ''))) {
      var alt = (meta && meta.alt) || '';
      var link = el('a', 'note_media_link');
      link.href = url;              // still a real link: middle-click and
      link.rel = 'noopener noreferrer';   // ctrl-click open the file directly
      link.target = '_blank';

      var img = document.createElement('img');
      img.className = 'note_media';
      img.src = url;
      img.alt = alt;
      img.loading = 'lazy';
      img.referrerPolicy = 'no-referrer';
      img.addEventListener('error', function () {
        var at = group ? group.indexOf(entry) : -1;
        if (at > -1) group.splice(at, 1);   // keep the arrows honest
        link.remove();
      });
      link.appendChild(img);

      var entry = { url: url, alt: alt };
      if (group) {
        group.push(entry);
        link.addEventListener('click', function (e) {
          // Leave modified clicks to the browser.
          if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return;
          e.preventDefault();
          lightbox.open(group, group.indexOf(entry), link);
        });
      }
      return link;
    }
    return null;
  }

  var NOTE_TOKEN_RE = /(https?:\/\/[^\s<>"')]+)|(?:nostr:)?((?:npub|nprofile|note|nevent|naddr)1[023456789acdefghjklmnpqrstuvwxyz]{20,})|(^|\s)(#[^\s#.,!?;:()\[\]]+)/g;

  /*
   * Renders note text: links, nostr: references, hashtags, and any media urls.
   * Media found in the text is pulled out and shown below the text instead of
   * being left as a bare url. Returns the media urls it consumed.
   */
  function noteContent(container, ev, opts) {
    opts = opts || {};
    var text = String(ev.content || '');
    var meta = imetaUrls(ev);
    var media = [];
    var embeds = [];
    var textNode = el('div', 'note_text');

    var re = new RegExp(NOTE_TOKEN_RE.source, 'g');
    var last = 0, m;
    while ((m = re.exec(text)) !== null) {
      if (m[0] === '') { re.lastIndex++; continue; }
      if (m.index > last) textNode.appendChild(document.createTextNode(text.slice(last, m.index)));
      last = m.index + m[0].length;

      if (m[1]) {                                   // plain url
        var url = safeUrl(m[1]);
        var yt = url && youtubeInfo(url);
        var isMedia = url && (IMAGE_EXT.test(url) || VIDEO_EXT.test(url) || meta[url]);
        if (yt) {
          if (!embeds.some(function (e) { return e.id === yt.id; })) embeds.push(yt);
        } else if (isMedia) {
          media.push(url);                          // shown below, not inline
        } else if (url) {
          var a = el('a', null, m[1].replace(/^https?:\/\//, ''));
          a.href = url;
          a.rel = 'noopener noreferrer nofollow';
          a.target = '_blank';
          textNode.appendChild(a);
        } else {
          textNode.appendChild(document.createTextNode(m[1]));
        }
      } else if (m[2]) {                            // nostr: reference
        var ref = el('a', 'note_ref', m[2].slice(0, 12) + '…');
        ref.href = 'https://njump.me/' + m[2];
        ref.title = m[2];
        ref.rel = 'noopener noreferrer';
        ref.target = '_blank';
        textNode.appendChild(ref);
      } else if (m[4]) {                            // hashtag
        if (m[3]) textNode.appendChild(document.createTextNode(m[3]));
        textNode.appendChild(el('span', 'note_hashtag', m[4]));
      }
    }
    if (last < text.length) textNode.appendChild(document.createTextNode(text.slice(last)));

    // Media attached via imeta but never mentioned in the text.
    Object.keys(meta).forEach(function (url) {
      if (media.indexOf(url) === -1) media.push(url);
    });

    tidyText(textNode);

    if (textNode.textContent.trim() || textNode.querySelector('a')) {
      if (opts.clamp) textNode.classList.add('note_text_clamped');
      container.appendChild(textNode);
    }

    if (!opts.textOnly && media.length) {
      var wrap = el('div', 'note_media_wrap' + (media.length > 1 ? ' note_media_grid' : ''));
      var group = [];   // images in this note, shared by the lightbox arrows
      media.forEach(function (url) {
        var node = mediaNode(url, meta[url], group);
        if (node) wrap.appendChild(node);
      });
      if (wrap.children.length) container.appendChild(wrap);
    }

    if (!opts.textOnly) {
      embeds.forEach(function (info) { container.appendChild(youtubeEmbed(info)); });
    }

    return media;
  }

  /*
   * Pulling a media url out of the text can leave the blank line it sat on.
   * Trim the ends and collapse runs of blank lines so cards start at the text.
   */
  function tidyText(node) {
    var kids = node.childNodes;
    for (var i = 0; i < kids.length; i++) {
      if (kids[i].nodeType === 3) kids[i].data = kids[i].data.replace(/\n{3,}/g, '\n\n');
    }
    while (node.firstChild && node.firstChild.nodeType === 3) {
      node.firstChild.data = node.firstChild.data.replace(/^\s+/, '');
      if (node.firstChild.data === '') node.removeChild(node.firstChild);
      else break;
    }
    while (node.lastChild && node.lastChild.nodeType === 3) {
      node.lastChild.data = node.lastChild.data.replace(/\s+$/, '');
      if (node.lastChild.data === '') node.removeChild(node.lastChild);
      else break;
    }
  }

  function shortformCard(ev) {
    var item = el('li', 'note_item');
    var noteId = encodeNote(ev.id);
    var njump = 'https://njump.me/' + noteId;

    var header = el('div', 'note_header');
    var meta = el('div', 'note_meta');
    meta.appendChild(el('span', 'note_date', formatDateTime(ev.created_at)));
    var idLink = el('a', 'button button_translucent', noteId.slice(0, 12) + '…');
    idLink.href = njump;
    idLink.rel = 'noopener noreferrer';
    idLink.target = '_blank';
    meta.appendChild(idLink);
    header.appendChild(meta);
    item.appendChild(header);

    var body = el('div', 'note_body');
    var long = (ev.content || '').length > NOTE_CLAMP;
    noteContent(body, ev, { clamp: long });
    item.appendChild(body);

    // The note id at the top already links to njump, so the only footer control
    // a card needs is Read More -- and only when there is more to read.
    if (long) {
      var footer = el('div', 'note_footer');
      var more = el('button', 'button', 'Read More');
      more.type = 'button';
      more.addEventListener('click', function () {
        reader.open({
          title: 'Note',
          meta: [formatDateTime(ev.created_at)],
          bodyClass: 'reader_body_note',
          build: function (container) { noteContent(container, ev); },
          link: { href: njump },
          opener: more
        });
      });
      footer.appendChild(more);
      item.appendChild(footer);
    }

    return item;
  }

  function hasMediaTag(ev) {
    return ev.tags.some(function (t) {
      return t[0] === 't' && t.length > 1 &&
        MEDIA_TAGS.indexOf(String(t[1]).toLowerCase()) !== -1;
    });
  }

  /*
   * Media is a lens over the shortform feed rather than a separate kind: the
   * same notes, narrowed to the ones tagged meme / photography / video. Replies
   * are kept here -- a meme posted as a reply is still a media post.
   */
  function renderMedia(events) {
    var items = events.filter(hasMediaTag);
    items.sort(function (a, b) { return b.created_at - a.created_at; });

    var frag = document.createDocumentFragment();
    items.forEach(function (ev) { frag.appendChild(shortformCard(ev)); });
    return { node: frag, count: items.length };
  }

  function renderShortform(events) {
    var items = events.filter(function (ev) {
      return SHOW_REPLIES || !isReplyToOthers(ev);
    });
    items.sort(function (a, b) { return b.created_at - a.created_at; });

    var frag = document.createDocumentFragment();
    items.forEach(function (ev) { frag.appendChild(shortformCard(ev)); });
    return { node: frag, count: items.length };
  }

  /* ------------------------------------------------------------------ *
   * Rendering: bookmarks
   *
   * Two kinds share this tab. A web bookmark (NIP-B0, kind 39701) is a link
   * the author saved: the "d" tag holds the url with its scheme stripped, and
   * the content is an optional note about it. A highlight (NIP-84, kind 9802)
   * is a passage the author marked in something they were reading, with the
   * source in an "r" (url), "a" (article) or "e" (event) tag.
   * ------------------------------------------------------------------ */

  var BOOKMARK_KIND = 39701;
  var HIGHLIGHT_KIND = 9802;

  var HEX64 = /^[0-9a-f]{64}$/i;

  // NIP-B0 stores the url without its scheme, so https is put back on.
  function bookmarkUrl(ev) {
    var d = tagValue(ev, 'd');
    if (!d) return null;
    return safeUrl(/^https?:\/\//i.test(d) ? d : 'https://' + d);
  }

  function hostOf(url) {
    try { return new URL(url).hostname.replace(/^www\./, ''); } catch (e) { return url; }
  }

  function prettyUrl(url) {
    var text = String(url).replace(/^https?:\/\//i, '').replace(/\/+$/, '');
    return text.length > 64 ? text.slice(0, 63) + '…' : text;
  }

  function externalButton(parent, className, label, href) {
    var a = el('a', className, label);
    a.href = href;
    a.rel = 'noopener noreferrer nofollow';
    a.target = '_blank';
    parent.appendChild(a);
    return a;
  }

  function nostrButton(parent, className, label, href) {
    var a = el('a', className, label);
    a.href = href;
    a.rel = 'noopener noreferrer';
    a.target = '_blank';
    parent.appendChild(a);
    return a;
  }

  function topicTags(parent, ev) {
    var topics = tagValues(ev, 't');
    if (!topics.length) return;
    var wrap = el('div', 'card_tags');
    topics.slice(0, 8).forEach(function (t) {
      wrap.appendChild(el('span', 'button button_translucent', t));
    });
    parent.appendChild(wrap);
  }

  /* ---- Web bookmarks (kind 39701) ---- */

  function bookmarkCard(ev, pubkey) {
    var url = bookmarkUrl(ev);
    var identifier = tagValue(ev, 'd');
    var title = tagValue(ev, 'title') || (url ? prettyUrl(url) : identifier) || 'Untitled';

    var item = el('li', 'note_item');
    var layout = el('div', 'card_layout');

    // Not part of NIP-B0, but clients that save a preview image use "image".
    var cover = coverNode(tagValue(ev, 'image'), title, url);
    if (cover) layout.appendChild(cover);
    else layout.classList.add('card_layout_nocover');

    var main = el('div', 'card_main');

    var header = el('div', 'note_header');
    var h3 = el('h3', 'note_title');
    if (url) {
      externalButton(h3, null, title, url);
    } else {
      h3.appendChild(document.createTextNode(title));
    }
    header.appendChild(h3);

    var meta = el('div', 'note_meta');
    meta.appendChild(el('span', 'type_badge', 'Bookmark'));
    metaSpan(meta, formatDate(published(ev)));
    if (url) externalButton(meta, 'bookmark_host', hostOf(url), url);
    header.appendChild(meta);
    main.appendChild(header);

    var content = (ev.content || '').trim();
    if (content) {
      var body = el('div', 'note_body');
      linkify(body, content);
      main.appendChild(body);
    }

    var embedWrap = el('div', 'card_embeds');
    if (appendYoutubeEmbeds(embedWrap, content)) main.appendChild(embedWrap);

    var footer = el('div', 'note_footer');
    if (url) externalButton(footer, 'button', 'Visit Link', url);
    if (identifier) {
      nostrButton(footer, 'button button_translucent', 'On Nostr',
        'https://njump.me/' + encodeNaddr(ev.kind, pubkey, identifier));
    }
    topicTags(footer, ev);
    main.appendChild(footer);

    layout.appendChild(main);
    item.appendChild(layout);
    return item;
  }

  /* ---- Highlights (kind 9802) ---- */

  // Where the passage was read: an external page, or another nostr event.
  function highlightSource(ev) {
    var r = safeUrl(tagValue(ev, 'r'));
    if (r) return { href: r, label: hostOf(r), title: prettyUrl(r), external: true };

    var a = tagValue(ev, 'a');
    if (a) {
      var parts = a.split(':');
      var kind = parseInt(parts[0], 10);
      if (parts.length >= 2 && isFinite(kind) && HEX64.test(parts[1])) {
        return {
          href: 'https://njump.me/' + encodeNaddr(kind, parts[1], parts.slice(2).join(':')),
          label: 'Nostr article'
        };
      }
    }

    var e = tagValue(ev, 'e');
    if (e && HEX64.test(e)) {
      return { href: 'https://njump.me/' + encodeNote(e), label: 'Nostr note' };
    }
    return null;
  }

  // "p" tags credit whoever wrote the passage; the 4th element carries the
  // role, and anything explicitly not an author (editor, mention) is skipped.
  function highlightAuthors(ev) {
    var out = [];
    ev.tags.forEach(function (t) {
      if (t[0] !== 'p' || t.length < 2 || !HEX64.test(t[1])) return;
      if (t.length > 3 && t[3] && t[3] !== 'author') return;
      if (out.indexOf(t[1]) === -1) out.push(t[1]);
    });
    return out;
  }

  /*
   * The content is the marked run of text; the optional "context" tag carries
   * the sentences around it. When the context contains the run, the card shows
   * the whole passage with the marked part standing out.
   */
  function highlightPassage(ev) {
    var quote = String(ev.content || '').trim();
    var context = String(tagValue(ev, 'context') || '').trim();
    if (quote && context && context !== quote) {
      var at = context.indexOf(quote);
      if (at !== -1) {
        return {
          before: context.slice(0, at),
          mark: quote,
          after: context.slice(at + quote.length)
        };
      }
    }
    return { before: '', mark: quote || context, after: '' };
  }

  function passageLength(passage) {
    return passage.before.length + passage.mark.length + passage.after.length;
  }

  function passageNode(passage, clamp) {
    var quote = el('blockquote', 'highlight_quote' + (clamp ? ' note_text_clamped' : ''));
    if (passage.before) quote.appendChild(el('span', 'highlight_context', passage.before));
    quote.appendChild(el('mark', 'highlight_mark', passage.mark));
    if (passage.after) quote.appendChild(el('span', 'highlight_context', passage.after));
    return quote;
  }

  function highlightCard(ev) {
    var noteId = encodeNote(ev.id);
    var njump = 'https://njump.me/' + noteId;
    var source = highlightSource(ev);
    var passage = highlightPassage(ev);
    var comment = String(tagValue(ev, 'comment') || '').trim();
    var long = passageLength(passage) > NOTE_CLAMP;

    var item = el('li', 'note_item');

    var header = el('div', 'note_header');
    var meta = el('div', 'note_meta');
    meta.appendChild(el('span', 'type_badge', 'Highlight'));
    meta.appendChild(el('span', 'note_date', formatDate(published(ev))));
    highlightAuthors(ev).slice(0, 2).forEach(function (hex) {
      var npub = encodeNpub(hex);
      if (npub) nostrButton(meta, 'button button_translucent', 'by ' + shortNpub(npub),
        'https://njump.me/' + npub);
    });
    header.appendChild(meta);
    item.appendChild(header);

    // NIP-84 allows an empty content for highlights of non-text media, which
    // leaves nothing to quote -- such a card is just its source and date.
    var body = el('div', 'note_body');
    if (passage.mark) body.appendChild(passageNode(passage, long));
    if (comment) {
      var note = el('div', 'highlight_comment');
      linkify(note, comment);
      body.appendChild(note);
    }
    if (body.firstChild) item.appendChild(body);

    var footer = el('div', 'note_footer');
    if (long && passage.mark) {
      var more = el('button', 'button', 'Read More');
      more.type = 'button';
      more.addEventListener('click', function () {
        reader.open({
          title: 'Highlight',
          meta: [formatDate(published(ev))].concat(source ? [source.title || source.label] : []),
          bodyClass: 'reader_body_note',
          build: function (container) {
            container.appendChild(passageNode(passage, false));
            if (comment) {
              var full = el('div', 'highlight_comment');
              linkify(full, comment);
              container.appendChild(full);
            }
          },
          link: { href: njump },
          opener: more
        });
      });
      footer.appendChild(more);
    }
    if (source) {
      var cls = long ? 'button button_translucent' : 'button';
      var label = 'Source · ' + source.label;
      var btn = source.external
        ? externalButton(footer, cls, label, source.href)
        : nostrButton(footer, cls, label, source.href);
      if (source.title) btn.title = source.title;
    }
    nostrButton(footer, 'button button_translucent', noteId.slice(0, 12) + '…', njump);
    topicTags(footer, ev);
    item.appendChild(footer);

    return item;
  }

  /*
   * Saved links and marked passages are the same activity seen from two angles,
   * so the tab interleaves both kinds on one timeline.
   */
  function renderBookmarks(events, ctx) {
    var items = events.filter(function (ev) {
      return ev.kind === BOOKMARK_KIND || ev.kind === HIGHLIGHT_KIND;
    });
    items.sort(function (a, b) { return published(b) - published(a); });

    var frag = document.createDocumentFragment();
    items.forEach(function (ev) {
      frag.appendChild(ev.kind === BOOKMARK_KIND ? bookmarkCard(ev, ctx.pubkey) : highlightCard(ev));
    });
    return { node: frag, count: items.length };
  }

  /* ------------------------------------------------------------------ *
   * Panels
   * ------------------------------------------------------------------ */

  function setPanelState(kind, state) {
    var panel = document.getElementById('notes_' + kind);
    if (panel) panel.dataset.state = state;
  }

  function showMessage(kind, message) {
    var panel = document.getElementById('notes_' + kind);
    if (!panel) return;
    panel.textContent = '';
    var li = el('li', 'empty', message);
    panel.appendChild(li);
  }

  function paint(kind, events, ctx) {
    var panel = document.getElementById('notes_' + kind);
    var cat = CATEGORIES[kind];
    if (!panel || !cat || !cat.render) return;

    var result = cat.render(events, ctx);
    panel.textContent = '';
    if (result.count === 0) {
      showMessage(kind, 'Nothing here yet.');
    } else {
      panel.appendChild(result.node);
    }
    setPanelState(kind, 'ready');
  }

  /* ------------------------------------------------------------------ *
   * Sidebar
   * ------------------------------------------------------------------ */

  function shortNpub(npub) {
    return npub.length > 20 ? npub.slice(0, 12) + '…' + npub.slice(-6) : npub;
  }

  function fillProfile(npub, profileEvent) {
    var npubNode = document.getElementById('npub');
    if (npubNode) {
      npubNode.textContent = '';
      npubNode.classList.remove('pale');
      var a = el('a', null, shortNpub(npub));
      a.href = 'https://njump.me/' + npub;
      a.title = npub;
      a.rel = 'noopener noreferrer';
      a.target = '_blank';
      npubNode.appendChild(a);
    }

    var nip05Node = document.getElementById('nip05');
    if (!nip05Node) return;
    var meta = {};
    if (profileEvent) { try { meta = JSON.parse(profileEvent.content) || {}; } catch (e) { meta = {}; } }
    if (typeof meta.nip05 === 'string' && meta.nip05) {
      nip05Node.textContent = meta.nip05;
      nip05Node.classList.remove('pale');
    } else {
      nip05Node.textContent = 'none published';
    }
  }

  function renderRelays(urls, status) {
    var list = document.getElementById('relays');
    if (!list) return;
    list.textContent = '';
    urls.forEach(function (url) {
      var li = el('li', 'relay_item');
      var state = status[url] || 'idle';
      var dot = el('span', 'relay_dot relay_' + state);
      dot.title = state;
      li.appendChild(dot);
      li.appendChild(document.createTextNode(url.replace(/^wss?:\/\//, '')));
      list.appendChild(li);
    });
  }

  /* ------------------------------------------------------------------ *
   * Light/dark switch
   * ------------------------------------------------------------------ */

  function initTheme() {
    var box = document.getElementById('mode');
    if (!box) return;

    var root = document.documentElement;

    function systemPrefersDark() {
      return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    }

    function isDim() {
      var mode = root.getAttribute('data-mode');
      if (mode === 'dim') return true;
      if (mode === 'lit') return false;
      return systemPrefersDark();
    }

    // The knob reflects the mode actually showing, including the system default.
    box.checked = isDim();

    box.addEventListener('change', function () {
      var mode = box.checked ? 'dim' : 'lit';
      root.setAttribute('data-mode', mode);
      try { localStorage.setItem('color-mode', mode); } catch (e) {}
    });

    // Follow the system while the reader has not made an explicit choice.
    if (window.matchMedia) {
      var mq = window.matchMedia('(prefers-color-scheme: dark)');
      var onChange = function () { if (!root.hasAttribute('data-mode')) box.checked = isDim(); };
      if (mq.addEventListener) mq.addEventListener('change', onChange);
      else if (mq.addListener) mq.addListener(onChange);
    }
  }

  /* ------------------------------------------------------------------ *
   * Tabs
   * ------------------------------------------------------------------ */

  function initTabs() {
    var tabs = Array.prototype.slice.call(document.querySelectorAll('.type_option'));

    function select(kind) {
      tabs.forEach(function (tab) {
        var on = tab.dataset.kind === kind;
        tab.setAttribute('aria-selected', on ? 'true' : 'false');
        var panel = document.getElementById(tab.getAttribute('aria-controls'));
        if (panel) panel.hidden = !on;
      });
    }

    tabs.forEach(function (tab) {
      tab.addEventListener('click', function () { select(tab.dataset.kind); });
    });

    select('shortform');
  }

  /* ------------------------------------------------------------------ *
   * Start
   * ------------------------------------------------------------------ */

  function setStatus(message) {
    var node = document.getElementById('status');
    if (!node) return;
    if (!message) { node.hidden = true; return; }
    node.hidden = false;
    node.textContent = message;
  }

  function start() {
    initTheme();
    initTabs();
    lightbox.init();
    reader.init();

    fetch(BOOTSTRAP, { cache: 'no-cache' })
      .then(function (res) {
        if (!res.ok) throw new Error(BOOTSTRAP + ' returned HTTP ' + res.status);
        return res.text();
      })
      .then(function (text) {
        var cfg = parseBootstrap(text);
        if (!cfg.npub) throw new Error('no npub in ' + BOOTSTRAP);
        if (!cfg.relays.length) throw new Error('no relays in ' + BOOTSTRAP);

        var pubkey = npubToHex(cfg.npub);
        if (!pubkey) throw new Error('could not decode npub');

        var pool = new RelayPool(cfg.relays);
        renderRelays(cfg.relays, pool.status);
        pool.onStatus(function (_url, _state, status) { renderRelays(cfg.relays, status); });

        fillProfile(cfg.npub, null);
        setStatus('Loading from ' + cfg.relays.length + ' relays…');

        // Profile (kind 0), newest wins.
        var newestProfile = null;
        pool.subscribe('profile', { authors: [pubkey], kinds: [0], limit: 1 }, function (ev) {
          if (!newestProfile || ev.created_at > newestProfile.created_at) newestProfile = ev;
        }, function () {
          fillProfile(cfg.npub, newestProfile);
        });

        // Every wired-up category starts fetching now, in parallel, regardless
        // of which tab is currently visible.
        var ctx = { pubkey: pubkey, npub: cfg.npub };
        var live = Object.keys(CATEGORIES).filter(function (k) { return CATEGORIES[k].filter; });
        var remaining = live.length;

        live.forEach(function (kind) {
          var store = {};
          setPanelState(kind, 'loading');
          showMessage(kind, 'Loading…');

          var filter = Object.assign({ authors: [pubkey] }, CATEGORIES[kind].filter);
          var repaint = null;

          pool.subscribe(kind, filter, function (ev) {
            var key = eventKey(ev);
            var seen = store[key];
            if (seen && seen.created_at >= ev.created_at) return;
            store[key] = ev;
            // Coalesce bursts of events into one repaint.
            if (!repaint) {
              repaint = setTimeout(function () {
                repaint = null;
                paint(kind, Object.keys(store).map(function (k) { return store[k]; }), ctx);
              }, 120);
            }
          }, function () {
            clearTimeout(repaint);
            repaint = null;
            var events = Object.keys(store).map(function (k) { return store[k]; });
            paint(kind, events, ctx);
            if (!events.length) {
              showMessage(kind, 'No ' + kind + ' found on these relays.');
              setPanelState(kind, 'empty');
            }
            if (--remaining === 0) setStatus('');
          });
        });

        if (!live.length) setStatus('');
      })
      .catch(function (err) {
        setStatus('Could not start: ' + err.message);
        Object.keys(CATEGORIES).forEach(function (kind) {
          if (CATEGORIES[kind].filter) {
            showMessage(kind, 'Unavailable — ' + err.message);
            setPanelState(kind, 'error');
          }
        });
      });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();
