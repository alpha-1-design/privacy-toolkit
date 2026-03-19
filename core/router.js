/**
 * Privacy First Security Toolkit
 * Router — core/router.js
 *
 * Handles navigation between tools.
 * Hash-based routing — no server needed.
 */

export class Router {
  constructor() {
    this.routes = new Map();
    this.currentRoute = null;
    this.onNavigate = null;
  }

  /**
   * Register a route
   * @param {string} path - Route hash (e.g. 'link-analyzer')
   * @param {Function} handler - Called when route is activated
   */
  register(path, handler) {
    this.routes.set(path, handler);
  }

  /**
   * Navigate to a route
   */
  navigate(path) {
    window.location.hash = path;
  }

  /**
   * Initialize router and listen for hash changes
   */
  init() {
    window.addEventListener('hashchange', () => this._handleRoute());
    this._handleRoute();
  }

  _handleRoute() {
    const hash = window.location.hash.replace('#', '') || 'dashboard';

    // Update sidebar active state
    document.querySelectorAll('.nav-item').forEach(el => {
      el.classList.toggle('active', el.dataset.route === hash);
    });

    // Hide all tool views
    document.querySelectorAll('.tool-view').forEach(el => {
      el.classList.remove('active');
    });

    // Show target view
    const view = document.getElementById(`view-${hash}`);
    if (view) {
      view.classList.add('active');
    }

    this.currentRoute = hash;

    // Run handler if registered
    if (this.routes.has(hash)) {
      this.routes.get(hash)();
    }

    if (this.onNavigate) {
      this.onNavigate(hash);
    }

    // Scroll to top of main
    const main = document.getElementById('main');
    if (main) main.scrollTop = 0;
  }
}

export const router = new Router();
