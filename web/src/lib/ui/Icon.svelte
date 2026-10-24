<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { icons, type IconName } from './icons';

  interface Props {
    name: IconName;
    size?: 16 | 20;
  }

  let { name, size = 20 }: Props = $props();
</script>

<svg
  class="icon"
  width={size}
  height={size}
  viewBox="0 0 24 24"
  fill="none"
  stroke="currentColor"
  stroke-width="2"
  stroke-linecap="round"
  stroke-linejoin="round"
  aria-hidden="true"
  focusable="false"
>
  {#each icons[name] as el, i (i)}
    <svelte:element this={el.tag} {...el.attrs} />
  {/each}
</svg>

<style>
  .icon {
    flex: none;
  }
</style>
