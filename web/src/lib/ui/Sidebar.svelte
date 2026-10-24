<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { router, sections } from '../router.svelte';
  import Icon from './Icon.svelte';

  interface Props {
    id: string;
    collapsed: boolean;
  }

  let { id, collapsed }: Props = $props();
</script>

<nav {id} class="sidebar" class:collapsed aria-label="Main">
  <ul>
    {#each sections as section (section.path)}
      <li>
        <a
          href={section.path}
          aria-current={router.path === section.path ? 'page' : undefined}
          title={collapsed ? section.title : undefined}
        >
          <Icon name={section.icon} />
          <span class:visually-hidden={collapsed}>{section.title}</span>
        </a>
      </li>
    {/each}
  </ul>
</nav>

<style>
  .sidebar {
    width: var(--sidebar-width);
    flex: none;
    padding: var(--space-3) var(--space-2);
    border-right: 1px solid var(--color-border);
    background: var(--color-surface);
    transition: width var(--motion-fast);
  }

  .sidebar.collapsed {
    width: var(--sidebar-width-collapsed);
  }

  ul {
    margin: 0;
    padding: 0;
    list-style: none;
    display: grid;
    gap: var(--space-1);
  }

  a {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    min-height: var(--target-size);
    padding: var(--space-1) var(--space-3);
    border-radius: var(--radius-1);
    color: var(--color-text);
    text-decoration: none;
  }

  a:hover {
    background: var(--color-surface-sunken);
  }

  a[aria-current='page'] {
    background: var(--color-accent);
    color: var(--color-accent-text);
    font-weight: 600;
  }

  .visually-hidden {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip-path: inset(50%);
    white-space: nowrap;
  }
</style>
