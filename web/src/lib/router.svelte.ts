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

/** The pages inside the Alerts area. */
export type AlertsView = 'alerts' | 'rules' | 'silences' | 'channels' | 'routes';

export type Route =
  | { kind: 'section'; path: string }
  | { kind: 'alerts'; view: AlertsView }
  | { kind: 'alert'; id: string }
  | { kind: 'add-host' }
  | { kind: 'host'; id: string }
  | { kind: 'container'; id: string }
  | { kind: 'check-new' }
  | { kind: 'check'; id: string }
  | { kind: 'check-edit'; id: string }
  | { kind: 'account' }
  | { kind: 'users' }
  | { kind: 'setup' }
  | { kind: 'not-found' };

// Item IDs are ULIDs (26 Crockford base32 characters); anything else cannot name an item.
const ITEM_ID = /^[0-9A-HJKMNP-TV-Z]{26}$/;

/** Maps a pathname to the screen that serves it. */
export function resolveRoute(path: string): Route {
  if (findSection(path)) return { kind: 'section', path };
  if (path === '/account') return { kind: 'account' };
  if (path === '/settings/users') return { kind: 'users' };
  if (path === '/setup') return { kind: 'setup' };
  const [, alertsPage] = /^\/alerts\/(rules|silences|channels|routes)$/.exec(path) ?? [];
  if (alertsPage) return { kind: 'alerts', view: alertsPage as AlertsView };
  const [, alertId] = /^\/alerts\/([^/]+)$/.exec(path) ?? [];
  if (alertId && ITEM_ID.test(alertId)) return { kind: 'alert', id: alertId };
  if (path === '/inventory/add') return { kind: 'add-host' };
  const [, collection, id] = /^\/inventory\/(hosts|containers)\/([^/]+)$/.exec(path) ?? [];
  if (collection && id && ITEM_ID.test(id)) {
    return collection === 'hosts' ? { kind: 'host', id } : { kind: 'container', id };
  }
  if (path === '/checks/new') return { kind: 'check-new' };
  const [, checkId, edit] = /^\/checks\/([^/]+?)(\/edit)?$/.exec(path) ?? [];
  if (checkId && ITEM_ID.test(checkId)) {
    return edit ? { kind: 'check-edit', id: checkId } : { kind: 'check', id: checkId };
  }
  return { kind: 'not-found' };
}

/** The section a route belongs to in the sidebar, for highlighting. */
export function sectionOf(route: Route): string | undefined {
  switch (route.kind) {
    case 'section':
      return route.path;
    case 'add-host':
    case 'host':
    case 'container':
      return '/inventory';
    case 'check-new':
    case 'check':
    case 'check-edit':
      return '/checks';
    case 'alerts':
    case 'alert':
      return '/alerts';
    case 'users':
      return '/settings';
    default:
      return undefined;
  }
}

class Router {
  path = $state(typeof window === 'undefined' ? '/' : window.location.pathname);
  /** A page title that only the page knows, such as a host name; cleared on every navigation. */
  titleOverride = $state<string | null>(null);

  constructor() {
    if (typeof window !== 'undefined') {
      window.addEventListener('popstate', () => {
        this.path = window.location.pathname;
        this.titleOverride = null;
      });
    }
  }

  navigate(to: string): void {
    if (to === this.path) return;
    window.history.pushState({}, '', to);
    this.path = to;
    this.titleOverride = null;
  }
}

export const router = new Router();
