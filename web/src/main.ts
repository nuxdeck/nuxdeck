// SPDX-License-Identifier: AGPL-3.0-only

import { mount } from 'svelte';
import App from './App.svelte';
import './lib/ui/tokens.css';
import './lib/ui/global.css';

const target = document.getElementById('app');
if (!target) throw new Error('missing #app element');

export default mount(App, { target });
