// SPDX-License-Identifier: AGPL-3.0-only

import type { IconName } from './ui/icons';

export interface RouteDef {
  path: string;
  title: string;
  icon: IconName;
  /** The question this screen answers (docs/06-ux.md, Key screens). */
  question: string;
}

/** The seven sidebar sections, in the order the UX spec lists them. */
export const sections: readonly RouteDef[] = [
  {
    path: '/',
    title: 'Overview',
    icon: 'layoutDashboard',
    question: 'Is anything wrong right now?',
  },
  { path: '/inventory', title: 'Inventory', icon: 'server', question: 'What do I run, and where?' },
  { path: '/checks', title: 'Checks', icon: 'activity', question: 'Are my endpoints up?' },
  {
    path: '/alerts',
    title: 'Alerts',
    icon: 'bell',
    question: 'What fired and who is handling it?',
  },
  {
    path: '/status-pages',
    title: 'Status pages',
    icon: 'globe',
    question: 'What do customers see?',
  },
  { path: '/settings', title: 'Settings', icon: 'settings', question: 'How is Nux Deck set up?' },
  { path: '/audit', title: 'Audit log', icon: 'scrollText', question: 'Who changed what?' },
];

export function findSection(path: string): RouteDef | undefined {
  return sections.find((s) => s.path === path);
}

class Router {
  path = $state(typeof window === 'undefined' ? '/' : window.location.pathname);

  constructor() {
    if (typeof window !== 'undefined') {
      window.addEventListener('popstate', () => {
        this.path = window.location.pathname;
      });
    }
  }

  navigate(to: string): void {
    if (to === this.path) return;
    window.history.pushState({}, '', to);
    this.path = to;
  }
}

export const router = new Router();
