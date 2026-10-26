// SPDX-License-Identifier: ISC AND MIT
// Icon geometry from Lucide (ISC; server, monitor and moon derive from Feather, MIT).
// Stored as data and rendered element by element, so no HTML is ever injected.

export interface IconElement {
  tag: string;
  attrs: Record<string, string>;
}

export const icons = {
  layoutDashboard: [
    { tag: 'rect', attrs: { width: '7', height: '9', x: '3', y: '3', rx: '1' } },
    { tag: 'rect', attrs: { width: '7', height: '5', x: '14', y: '3', rx: '1' } },
    { tag: 'rect', attrs: { width: '7', height: '9', x: '14', y: '12', rx: '1' } },
    { tag: 'rect', attrs: { width: '7', height: '5', x: '3', y: '16', rx: '1' } },
  ] as IconElement[],
  server: [
    { tag: 'rect', attrs: { width: '20', height: '8', x: '2', y: '2', rx: '2', ry: '2' } },
    { tag: 'rect', attrs: { width: '20', height: '8', x: '2', y: '14', rx: '2', ry: '2' } },
    { tag: 'line', attrs: { x1: '6', x2: '6.01', y1: '6', y2: '6' } },
    { tag: 'line', attrs: { x1: '6', x2: '6.01', y1: '18', y2: '18' } },
  ] as IconElement[],
  activity: [
    {
      tag: 'path',
      attrs: {
        d: 'M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2',
      },
    },
  ] as IconElement[],
  bell: [
    { tag: 'path', attrs: { d: 'M10.268 21a2 2 0 0 0 3.464 0' } },
    {
      tag: 'path',
      attrs: {
        d: 'M3.262 15.326A1 1 0 0 0 4 17h16a1 1 0 0 0 .74-1.673C19.41 13.956 18 12.499 18 8A6 6 0 0 0 6 8c0 4.499-1.411 5.956-2.738 7.326',
      },
    },
  ] as IconElement[],
  globe: [
    { tag: 'circle', attrs: { cx: '12', cy: '12', r: '10' } },
    { tag: 'path', attrs: { d: 'M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20' } },
    { tag: 'path', attrs: { d: 'M2 12h20' } },
  ] as IconElement[],
  settings: [
    {
      tag: 'path',
      attrs: {
        d: 'M9.671 4.136a2.34 2.34 0 0 1 4.659 0 2.34 2.34 0 0 0 3.319 1.915 2.34 2.34 0 0 1 2.33 4.033 2.34 2.34 0 0 0 0 3.831 2.34 2.34 0 0 1-2.33 4.033 2.34 2.34 0 0 0-3.319 1.915 2.34 2.34 0 0 1-4.659 0 2.34 2.34 0 0 0-3.32-1.915 2.34 2.34 0 0 1-2.33-4.033 2.34 2.34 0 0 0 0-3.831A2.34 2.34 0 0 1 6.35 6.051a2.34 2.34 0 0 0 3.319-1.915',
      },
    },
    { tag: 'circle', attrs: { cx: '12', cy: '12', r: '3' } },
  ] as IconElement[],
  scrollText: [
    { tag: 'path', attrs: { d: 'M15 12h-5' } },
    { tag: 'path', attrs: { d: 'M15 8h-5' } },
    { tag: 'path', attrs: { d: 'M19 17V5a2 2 0 0 0-2-2H4' } },
    {
      tag: 'path',
      attrs: {
        d: 'M8 21h12a2 2 0 0 0 2-2v-1a1 1 0 0 0-1-1H11a1 1 0 0 0-1 1v1a2 2 0 1 1-4 0V5a2 2 0 1 0-4 0v2a1 1 0 0 0 1 1h3',
      },
    },
  ] as IconElement[],
  panelLeft: [
    { tag: 'rect', attrs: { width: '18', height: '18', x: '3', y: '3', rx: '2' } },
    { tag: 'path', attrs: { d: 'M9 3v18' } },
  ] as IconElement[],
  sun: [
    { tag: 'circle', attrs: { cx: '12', cy: '12', r: '4' } },
    { tag: 'path', attrs: { d: 'M12 2v2' } },
    { tag: 'path', attrs: { d: 'M12 20v2' } },
    { tag: 'path', attrs: { d: 'm4.93 4.93 1.41 1.41' } },
    { tag: 'path', attrs: { d: 'm17.66 17.66 1.41 1.41' } },
    { tag: 'path', attrs: { d: 'M2 12h2' } },
    { tag: 'path', attrs: { d: 'M20 12h2' } },
    { tag: 'path', attrs: { d: 'm6.34 17.66-1.41 1.41' } },
    { tag: 'path', attrs: { d: 'm19.07 4.93-1.41 1.41' } },
  ] as IconElement[],
  moon: [
    {
      tag: 'path',
      attrs: {
        d: 'M20.985 12.486a9 9 0 1 1-9.473-9.472c.405-.022.617.46.402.803a6 6 0 0 0 8.268 8.268c.344-.215.825-.004.803.401',
      },
    },
  ] as IconElement[],
  monitor: [
    { tag: 'rect', attrs: { width: '20', height: '14', x: '2', y: '3', rx: '2' } },
    { tag: 'line', attrs: { x1: '8', x2: '16', y1: '21', y2: '21' } },
    { tag: 'line', attrs: { x1: '12', x2: '12', y1: '17', y2: '21' } },
  ] as IconElement[],
  rows3: [
    { tag: 'rect', attrs: { width: '18', height: '18', x: '3', y: '3', rx: '2' } },
    { tag: 'path', attrs: { d: 'M21 9H3' } },
    { tag: 'path', attrs: { d: 'M21 15H3' } },
  ] as IconElement[],
  rows4: [
    { tag: 'rect', attrs: { width: '18', height: '18', x: '3', y: '3', rx: '2' } },
    { tag: 'path', attrs: { d: 'M21 7.5H3' } },
    { tag: 'path', attrs: { d: 'M21 12H3' } },
    { tag: 'path', attrs: { d: 'M21 16.5H3' } },
  ] as IconElement[],
  checkCircle: [
    { tag: 'circle', attrs: { cx: '12', cy: '12', r: '10' } },
    { tag: 'path', attrs: { d: 'm9 12 2 2 4-4' } },
  ] as IconElement[],
  xCircle: [
    { tag: 'circle', attrs: { cx: '12', cy: '12', r: '10' } },
    { tag: 'path', attrs: { d: 'm15 9-6 6' } },
    { tag: 'path', attrs: { d: 'm9 9 6 6' } },
  ] as IconElement[],
  alertTriangle: [
    {
      tag: 'path',
      attrs: {
        d: 'm21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3',
      },
    },
    { tag: 'path', attrs: { d: 'M12 9v4' } },
    { tag: 'path', attrs: { d: 'M12 17h.01' } },
  ] as IconElement[],
  pauseCircle: [
    { tag: 'circle', attrs: { cx: '12', cy: '12', r: '10' } },
    { tag: 'line', attrs: { x1: '10', x2: '10', y1: '15', y2: '9' } },
    { tag: 'line', attrs: { x1: '14', x2: '14', y1: '15', y2: '9' } },
  ] as IconElement[],
  circle: [{ tag: 'circle', attrs: { cx: '12', cy: '12', r: '10' } }] as IconElement[],
  refresh: [
    { tag: 'path', attrs: { d: 'M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8' } },
    { tag: 'path', attrs: { d: 'M21 3v5h-5' } },
    { tag: 'path', attrs: { d: 'M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16' } },
    { tag: 'path', attrs: { d: 'M8 16H3v5' } },
  ] as IconElement[],
  copy: [
    { tag: 'rect', attrs: { width: '14', height: '14', x: '8', y: '8', rx: '2', ry: '2' } },
    { tag: 'path', attrs: { d: 'M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2' } },
  ] as IconElement[],
  plus: [
    { tag: 'path', attrs: { d: 'M5 12h14' } },
    { tag: 'path', attrs: { d: 'M12 5v14' } },
  ] as IconElement[],
  box: [
    {
      tag: 'path',
      attrs: {
        d: 'M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z',
      },
    },
    { tag: 'path', attrs: { d: 'm3.3 7 8.7 5 8.7-5' } },
    { tag: 'path', attrs: { d: 'M12 22V12' } },
  ] as IconElement[],
} as const;

export type IconName = keyof typeof icons;
