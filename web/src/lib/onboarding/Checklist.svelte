<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../api/client';
  import { auth } from '../auth.svelte';
  import { inventory } from '../inventory.svelte';
  import Button from '../ui/Button.svelte';
  import Icon from '../ui/Icon.svelte';
  import {
    checklistItems,
    checklistOpen,
    dismissChecklist,
    isChecklistDismissed,
    type ChecklistFacts,
  } from './onboarding';

  type RemoteFacts = Omit<ChecklistFacts, 'hosts'>;

  let remote = $state<RemoteFacts | null>(null);
  let dismissed = $state(false);

  const userId = $derived(auth.user?.id ?? '');
  const isAdmin = $derived(auth.user?.roles.includes('admin') ?? false);

  // A count the user may not read is null, which leaves that item out of the list.
  async function countOf(load: () => Promise<unknown[]>): Promise<number | null> {
    try {
      return (await load()).length;
    } catch {
      return null;
    }
  }

  async function load(): Promise<void> {
    const [checks, channels, users, statusPages] = await Promise.all([
      countOf(() => api.checks()),
      countOf(() => api.channels()),
      isAdmin ? countOf(() => api.users()) : Promise.resolve(null),
      countOf(() => api.statusPages()),
    ]);
    remote = { checks, channels, users, statusPages };
  }

  onMount(() => {
    dismissed = userId !== '' && isChecklistDismissed(userId);
    void load();
  });

  // Hosts come from the live inventory, so the list waits until both sides are known.
  const items = $derived(
    remote && inventory.loaded ? checklistItems({ ...remote, hosts: inventory.hosts.length }) : [],
  );
  const doneCount = $derived(items.filter((i) => i.done).length);
  const visible = $derived(!dismissed && items.length > 0 && checklistOpen(items));

  function dismiss(): void {
    dismissChecklist(userId);
    dismissed = true;
  }
</script>

{#if visible}
  <section class="checklist" aria-labelledby="checklist-heading">
    <div class="head">
      <h2 id="checklist-heading">
        Next steps <span class="count">({doneCount} of {items.length} done)</span>
      </h2>
      <Button variant="secondary" onclick={dismiss}>Dismiss</Button>
    </div>
    <ul>
      {#each items as item (item.id)}
        <li>
          {#if item.done}
            <Icon name="checkCircle" size={16} />
            <span>{item.label}</span>
            <span class="state">Done</span>
          {:else}
            <Icon name="circle" size={16} />
            <a href={item.href}>{item.label}</a>
            <span class="state">To do</span>
          {/if}
        </li>
      {/each}
    </ul>
  </section>
{/if}

<style>
  .checklist {
    margin-bottom: var(--space-6);
    padding: var(--space-4);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-2);
    background: var(--color-surface);
  }

  .head {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-3);
  }

  h2 {
    font-size: var(--font-size-md);
  }

  .count {
    font-weight: 400;
    color: var(--color-text-muted);
  }

  ul {
    display: grid;
    gap: var(--space-2);
    margin: var(--space-3) 0 0;
    padding: 0;
    list-style: none;
  }

  li {
    display: flex;
    align-items: center;
    gap: var(--space-2);
  }

  .state {
    margin-left: auto;
    font-size: var(--font-size-sm);
    color: var(--color-text-muted);
  }
</style>
