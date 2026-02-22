/**
 * PRECINCT -- Main Site JavaScript
 * https://precinct.dev
 *
 * Vanilla JS -- no frameworks.
 * Handles: theme toggle, mobile menu, sidebar, code copy, nav highlighting,
 * smooth scroll, mermaid init, table filtering.
 */

(function () {
  "use strict";

  // =========================================================================
  // 1. THEME TOGGLE (dark / light) with localStorage persistence
  // =========================================================================

  const THEME_KEY = "precinct-theme";

  /**
   * Determine the initial theme.
   * Priority: localStorage > OS preference > dark (default).
   */
  function getInitialTheme() {
    const stored = localStorage.getItem(THEME_KEY);
    if (stored === "light" || stored === "dark") {
      return stored;
    }
    // Default to dark -- this is a security infrastructure site
    return "dark";
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem(THEME_KEY, theme);

    // Update aria-label on toggle buttons
    document.querySelectorAll(".theme-toggle").forEach(function (btn) {
      btn.setAttribute(
        "aria-label",
        theme === "dark" ? "Switch to light mode" : "Switch to dark mode"
      );
    });
  }

  function toggleTheme() {
    var current = document.documentElement.getAttribute("data-theme") || "dark";
    applyTheme(current === "dark" ? "light" : "dark");

    // Re-initialize mermaid with the correct theme if diagrams are present
    reinitMermaid();
  }

  // Apply immediately (before DOMContentLoaded) to prevent flash of wrong theme
  applyTheme(getInitialTheme());

  // =========================================================================
  // 2. DOM READY
  // =========================================================================

  document.addEventListener("DOMContentLoaded", function () {
    initThemeToggle();
    initMobileMenu();
    initNavDropdowns();
    initActiveNavLinks();
    initSmoothScroll();
    initSidebar();
    initCodeCopyButtons();
    initMermaid();
    initTableFilter();
  });

  // =========================================================================
  // 3. NAV DROPDOWNS
  // =========================================================================

  function initNavDropdowns() {
    var dropdowns = document.querySelectorAll(".nav-dropdown");

    dropdowns.forEach(function (dropdown) {
      var toggle = dropdown.querySelector(".dropdown-toggle");
      if (!toggle) return;

      toggle.addEventListener("click", function (e) {
        e.stopPropagation();
        var isOpen = dropdown.classList.contains("open");

        // Close all other dropdowns first
        dropdowns.forEach(function (d) {
          d.classList.remove("open");
          var btn = d.querySelector(".dropdown-toggle");
          if (btn) btn.setAttribute("aria-expanded", "false");
        });

        // Toggle this one
        if (!isOpen) {
          dropdown.classList.add("open");
          toggle.setAttribute("aria-expanded", "true");
        }
      });
    });

    // Close all dropdowns when clicking outside
    document.addEventListener("click", function () {
      dropdowns.forEach(function (d) {
        d.classList.remove("open");
        var btn = d.querySelector(".dropdown-toggle");
        if (btn) btn.setAttribute("aria-expanded", "false");
      });
    });

    // Close on Escape
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") {
        dropdowns.forEach(function (d) {
          d.classList.remove("open");
          var btn = d.querySelector(".dropdown-toggle");
          if (btn) btn.setAttribute("aria-expanded", "false");
        });
      }
    });
  }

  // =========================================================================
  // 4. THEME TOGGLE -- bind click handlers
  // =========================================================================

  function initThemeToggle() {
    document.querySelectorAll(".theme-toggle").forEach(function (btn) {
      btn.addEventListener("click", toggleTheme);
    });
  }

  // =========================================================================
  // 4. MOBILE MENU TOGGLE
  // =========================================================================

  function initMobileMenu() {
    var btn = document.querySelector(".nav-toggle");
    var menu = document.querySelector(".nav-links");

    if (!btn || !menu) return;

    btn.addEventListener("click", function () {
      var isOpen = menu.classList.toggle("mobile-open");
      btn.classList.toggle("active", isOpen);
      btn.setAttribute("aria-expanded", String(isOpen));

      // Prevent body scroll when menu is open
      document.body.style.overflow = isOpen ? "hidden" : "";
    });

    // Close on link click
    menu.querySelectorAll("a").forEach(function (link) {
      link.addEventListener("click", function () {
        menu.classList.remove("mobile-open");
        btn.classList.remove("active");
        btn.setAttribute("aria-expanded", "false");
        document.body.style.overflow = "";
      });
    });

    // Close on Escape
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && menu.classList.contains("mobile-open")) {
        menu.classList.remove("mobile-open");
        btn.classList.remove("active");
        btn.setAttribute("aria-expanded", "false");
        document.body.style.overflow = "";
      }
    });
  }

  // =========================================================================
  // 5. ACTIVE NAV LINK HIGHLIGHTING
  // =========================================================================

  function initActiveNavLinks() {
    // Determine current page from pathname
    var path = window.location.pathname;

    // Normalize: strip trailing slash, default to index
    if (path.endsWith("/")) {
      path = path + "index.html";
    }

    var selectors = [".nav-links a", ".mobile-menu a", ".sidebar-nav a"];

    selectors.forEach(function (sel) {
      document.querySelectorAll(sel).forEach(function (link) {
        var href = link.getAttribute("href");
        if (!href) return;

        // Resolve href relative to current page
        var linkUrl;
        try {
          linkUrl = new URL(href, window.location.href).pathname;
        } catch (_) {
          return;
        }

        if (linkUrl.endsWith("/")) {
          linkUrl = linkUrl + "index.html";
        }

        // Exact match or match without .html extension
        if (
          path === linkUrl ||
          path.replace(/\.html$/, "") === linkUrl.replace(/\.html$/, "")
        ) {
          link.classList.add("active");
        }
      });
    });
  }

  // =========================================================================
  // 6. SMOOTH SCROLL FOR ANCHOR LINKS
  // =========================================================================

  function initSmoothScroll() {
    document.querySelectorAll('a[href^="#"]').forEach(function (anchor) {
      anchor.addEventListener("click", function (e) {
        var targetId = this.getAttribute("href");
        if (targetId === "#") return;

        var target = document.querySelector(targetId);
        if (!target) return;

        e.preventDefault();

        var headerHeight = getHeaderHeight();
        var targetPosition = target.getBoundingClientRect().top + window.pageYOffset - headerHeight - 16;

        window.scrollTo({
          top: targetPosition,
          behavior: "smooth",
        });

        // Update URL hash without jumping
        if (history.pushState) {
          history.pushState(null, null, targetId);
        }
      });
    });
  }

  function getHeaderHeight() {
    var header = document.querySelector(".site-header");
    return header ? header.offsetHeight : 0;
  }

  // =========================================================================
  // 7. SIDEBAR TOGGLE (mobile)
  // =========================================================================

  function initSidebar() {
    var toggleBtn = document.querySelector(".sidebar-toggle");
    var sidebar = document.querySelector(".sidebar-mobile");
    var overlay = document.querySelector(".sidebar-overlay");

    if (!toggleBtn || !sidebar) return;

    function openSidebar() {
      sidebar.classList.add("open");
      if (overlay) overlay.classList.add("open");
      document.body.style.overflow = "hidden";
    }

    function closeSidebar() {
      sidebar.classList.remove("open");
      if (overlay) overlay.classList.remove("open");
      document.body.style.overflow = "";
    }

    toggleBtn.addEventListener("click", function () {
      if (sidebar.classList.contains("open")) {
        closeSidebar();
      } else {
        openSidebar();
      }
    });

    if (overlay) {
      overlay.addEventListener("click", closeSidebar);
    }

    // Close on Escape
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && sidebar.classList.contains("open")) {
        closeSidebar();
      }
    });

    // Close on link click (mobile)
    sidebar.querySelectorAll("a").forEach(function (link) {
      link.addEventListener("click", closeSidebar);
    });
  }

  // =========================================================================
  // 8. COPY-TO-CLIPBOARD FOR CODE BLOCKS
  // =========================================================================

  function initCodeCopyButtons() {
    document.querySelectorAll("pre").forEach(function (block) {
      // Skip if button already present
      if (block.querySelector(".code-copy-btn")) return;

      var btn = document.createElement("button");
      btn.className = "code-copy-btn";
      btn.setAttribute("aria-label", "Copy code to clipboard");
      btn.setAttribute("title", "Copy");

      // Clipboard icon (SVG)
      btn.innerHTML =
        '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" ' +
        'fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
        '<rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>' +
        '<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>';

      btn.addEventListener("click", function () {
        var code = block.querySelector("code");
        var text = code ? code.textContent : block.textContent;

        navigator.clipboard
          .writeText(text)
          .then(function () {
            btn.classList.add("copied");
            btn.innerHTML =
              '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" ' +
              'fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
              '<polyline points="20 6 9 17 4 12"></polyline></svg>';

            setTimeout(function () {
              btn.classList.remove("copied");
              btn.innerHTML =
                '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" ' +
                'fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
                '<rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>' +
                '<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>';
            }, 2000);
          })
          .catch(function () {
            // Fallback for older browsers
            fallbackCopy(text);
            btn.classList.add("copied");
            setTimeout(function () {
              btn.classList.remove("copied");
            }, 2000);
          });
      });

      // Make pre position: relative for absolute button placement
      block.style.position = "relative";
      block.appendChild(btn);
    });
  }

  /**
   * Fallback copy using a temporary textarea (for environments where
   * navigator.clipboard is not available).
   */
  function fallbackCopy(text) {
    var textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.style.position = "fixed";
    textarea.style.left = "-9999px";
    textarea.style.top = "-9999px";
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();
    try {
      document.execCommand("copy");
    } catch (_) {
      // silent fail
    }
    document.body.removeChild(textarea);
  }

  // =========================================================================
  // 9. MERMAID INITIALIZATION
  // =========================================================================

  /**
   * Mermaid is loaded as an ES module from CDN.
   * We look for <pre class="mermaid"> or <div class="mermaid"> blocks.
   */
  function initMermaid() {
    var mermaidBlocks = document.querySelectorAll(".mermaid");
    if (mermaidBlocks.length === 0) return;

    loadMermaid().then(function (mermaid) {
      if (!mermaid) return;
      var theme = getCurrentMermaidTheme();
      mermaid.initialize({
        startOnLoad: false,
        theme: theme,
        securityLevel: "loose",
        fontFamily: "Inter, sans-serif",
      });
      mermaid.run({ nodes: mermaidBlocks });
    });
  }

  function reinitMermaid() {
    var mermaidBlocks = document.querySelectorAll(".mermaid");
    if (mermaidBlocks.length === 0) return;

    loadMermaid().then(function (mermaid) {
      if (!mermaid) return;
      var theme = getCurrentMermaidTheme();

      // Reset each mermaid block to its original source so it can be re-rendered
      mermaidBlocks.forEach(function (block) {
        var original = block.getAttribute("data-mermaid-src");
        if (original) {
          block.removeAttribute("data-processed");
          block.innerHTML = original;
        }
      });

      mermaid.initialize({
        startOnLoad: false,
        theme: theme,
        securityLevel: "loose",
        fontFamily: "Inter, sans-serif",
      });
      mermaid.run({ nodes: mermaidBlocks });
    });
  }

  function getCurrentMermaidTheme() {
    var siteTheme = document.documentElement.getAttribute("data-theme") || "dark";
    return siteTheme === "dark" ? "dark" : "default";
  }

  /**
   * Dynamically import mermaid ESM from CDN.
   * Caches the module after first load.
   */
  var _mermaidModule = null;

  function loadMermaid() {
    if (_mermaidModule) {
      return Promise.resolve(_mermaidModule);
    }

    // Store original source before mermaid processes it
    document.querySelectorAll(".mermaid").forEach(function (block) {
      if (!block.getAttribute("data-mermaid-src")) {
        block.setAttribute("data-mermaid-src", block.textContent.trim());
      }
    });

    return import("https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs")
      .then(function (mod) {
        _mermaidModule = mod.default || mod;
        return _mermaidModule;
      })
      .catch(function (err) {
        console.warn("PRECINCT: Failed to load mermaid from CDN:", err);
        return null;
      });
  }

  // =========================================================================
  // 10. TABLE FILTER / SEARCH
  // =========================================================================

  /**
   * For each element with class "table-filter", find its associated table
   * and wire up live filtering.
   *
   * Expected markup:
   *   <div class="table-filter">
   *     <input type="text" data-filter-target="my-table" placeholder="Filter...">
   *   </div>
   *   <div class="table-wrapper">
   *     <table id="my-table"> ... </table>
   *   </div>
   */
  function initTableFilter() {
    document.querySelectorAll(".table-filter input[data-filter-target]").forEach(function (input) {
      var tableId = input.getAttribute("data-filter-target");
      var table = document.getElementById(tableId);
      if (!table) return;

      var tbody = table.querySelector("tbody");
      if (!tbody) return;

      input.addEventListener("input", function () {
        var query = this.value.toLowerCase().trim();
        var rows = tbody.querySelectorAll("tr");

        rows.forEach(function (row) {
          var text = row.textContent.toLowerCase();
          row.style.display = query === "" || text.indexOf(query) !== -1 ? "" : "none";
        });
      });
    });
  }

  // =========================================================================
  // 11. SCROLL-AWARE HEADER SHADOW
  // =========================================================================

  // Add a subtle shadow to the header once the user scrolls down
  (function () {
    var header = null;
    var ticking = false;

    function onScroll() {
      if (!header) {
        header = document.querySelector(".site-header");
      }
      if (!header) return;

      if (!ticking) {
        window.requestAnimationFrame(function () {
          if (window.scrollY > 10) {
            header.style.boxShadow = "0 1px 8px rgba(0,0,0,0.15)";
          } else {
            header.style.boxShadow = "none";
          }
          ticking = false;
        });
        ticking = true;
      }
    }

    window.addEventListener("scroll", onScroll, { passive: true });
  })();
})();
