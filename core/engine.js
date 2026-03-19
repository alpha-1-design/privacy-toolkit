/**
 * Privacy First Security Toolkit
 * Plugin Engine — core/engine.js
 *
 * Loads and executes security analysis plugins.
 * All processing happens client-side.
 * No data leaves the browser.
 */

export class PluginEngine {
  constructor() {
    this.plugins = new Map();
    this.pluginTypes = [
      'LINK_ANALYSIS',
      'QR_ANALYSIS',
      'SCAM_PATTERN',
      'FILE_ANALYSIS',
      'DOMAIN_ANALYSIS',
      'TRACKING_CLEANER'
    ];
  }

  /**
   * Register a plugin
   * @param {Object} plugin - { name, version, type, description, run(input) }
   */
  register(plugin) {
    if (!plugin.name || !plugin.type || typeof plugin.run !== 'function') {
      console.warn('[Engine] Invalid plugin structure:', plugin.name);
      return false;
    }

    if (!this.pluginTypes.includes(plugin.type)) {
      console.warn(`[Engine] Unknown plugin type: ${plugin.type}`);
      return false;
    }

    this.plugins.set(plugin.name, plugin);
    console.log(`[Engine] Plugin registered: ${plugin.name} v${plugin.version || '1.0'}`);
    return true;
  }

  /**
   * Unregister a plugin by name
   */
  unregister(name) {
    return this.plugins.delete(name);
  }

  /**
   * Run all plugins of a specific type against input
   * @param {string} type - Plugin type constant
   * @param {*} input - Input data
   * @returns {Array} Combined results from all matching plugins
   */
  async runPlugins(type, input) {
    const results = [];
    const matching = [...this.plugins.values()].filter(p => p.type === type);

    if (matching.length === 0) {
      return results;
    }

    for (const plugin of matching) {
      try {
        const result = await plugin.run(input);
        if (result) {
          results.push({
            plugin: plugin.name,
            version: plugin.version || '1.0',
            result
          });
        }
      } catch (err) {
        console.warn(`[Engine] Plugin "${plugin.name}" failed:`, err.message);
      }
    }

    return results;
  }

  /**
   * Run all plugins (any type) against input
   */
  async runAll(input) {
    const results = [];
    for (const plugin of this.plugins.values()) {
      try {
        const result = await plugin.run(input);
        if (result) {
          results.push({ plugin: plugin.name, type: plugin.type, result });
        }
      } catch (err) {
        console.warn(`[Engine] Plugin "${plugin.name}" failed:`, err.message);
      }
    }
    return results;
  }

  /**
   * List all registered plugins
   */
  list() {
    return [...this.plugins.values()].map(p => ({
      name: p.name,
      version: p.version || '1.0',
      type: p.type,
      description: p.description || ''
    }));
  }

  /**
   * Load a plugin from a remote module (optional, user-triggered)
   * Note: User must explicitly call this. Nothing loads automatically.
   */
  async loadFromModule(moduleURL) {
    try {
      const mod = await import(moduleURL);
      if (mod.default && typeof mod.default === 'object') {
        return this.register(mod.default);
      }
      console.warn('[Engine] Module does not export a valid plugin as default export');
      return false;
    } catch (err) {
      console.error('[Engine] Failed to load plugin module:', err);
      return false;
    }
  }
}

// Singleton engine instance
export const engine = new PluginEngine();
