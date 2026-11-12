// SPDX-License-Identifier: Apache-2.0

// Reuses the web app's lint rules so both UIs follow one standard. The config's plugins resolve
// from web/node_modules, so linting here needs no install in this package.
import webConfig from '../../../web/eslint.config.js';

export default [{ ignores: ['playwright-report/', 'test-results/', '.auth/'] }, ...webConfig];
