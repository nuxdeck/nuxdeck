// SPDX-License-Identifier: AGPL-3.0-only

import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiRequestError } from '../api/client';

const setPublicUrl = vi.fn();
const setTelemetryEnabled = vi.fn();
const telemetryPreview = vi.fn();
vi.mock('../api/client', async (orig) => ({
  ...(await orig<typeof import('../api/client')>()),
  api: {
    setPublicUrl: (v: string) => setPublicUrl(v),
    setTelemetryEnabled: (v: boolean) => setTelemetryEnabled(v),
    telemetryPreview: () => telemetryPreview(),
  },
}));

import AddressStep from './AddressStep.svelte';
import DoneStep from './DoneStep.svelte';
import HostStep from './HostStep.svelte';
import TelemetryStep from './TelemetryStep.svelte';

describe('INS-3 step 2: server address', () => {
  beforeEach(() => {
    setPublicUrl.mockReset().mockResolvedValue({});
  });

  it('refuses an address with credentials, explains why and sends nothing', async () => {
    const onNext = vi.fn();
    render(AddressStep, { props: { initial: 'https://nux.example.com', onNext, onSkip: vi.fn() } });
    const field = screen.getByLabelText('Public address');
    await fireEvent.input(field, { target: { value: 'https://admin:pw@nux.example.com' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Save and continue' }));
    expect((await screen.findByRole('alert')).textContent).toContain('Credentials never belong');
    expect(field.getAttribute('aria-invalid')).toBe('true');
    expect(setPublicUrl).not.toHaveBeenCalled();
    expect(onNext).not.toHaveBeenCalled();
  });

  it('saves the normalised address and moves on', async () => {
    const onNext = vi.fn();
    render(AddressStep, {
      props: { initial: 'https://nux.example.com:8443/', onNext, onSkip: vi.fn() },
    });
    await fireEvent.click(screen.getByRole('button', { name: 'Save and continue' }));
    await waitFor(() => expect(onNext).toHaveBeenCalled());
    expect(setPublicUrl).toHaveBeenCalledWith('https://nux.example.com:8443');
  });

  it('shows a server refusal on the field and stays on the step', async () => {
    setPublicUrl.mockRejectedValue(
      new ApiRequestError({
        status: 422,
        code: 'API-VAL-001',
        message: 'Invalid request',
        hint: 'Use the address people open.',
        field: 'value',
      }),
    );
    const onNext = vi.fn();
    render(AddressStep, { props: { initial: 'https://nux.example.com', onNext, onSkip: vi.fn() } });
    await fireEvent.click(screen.getByRole('button', { name: 'Save and continue' }));
    expect(await screen.findByText(/Use the address people open/));
    expect(onNext).not.toHaveBeenCalled();
  });

  it('can be skipped without saving', async () => {
    const onSkip = vi.fn();
    render(AddressStep, { props: { initial: '', onNext: vi.fn(), onSkip } });
    await fireEvent.click(screen.getByRole('button', { name: 'Skip for now' }));
    expect(onSkip).toHaveBeenCalled();
    expect(setPublicUrl).not.toHaveBeenCalled();
  });
});

describe('INS-3 step 3: telemetry', () => {
  beforeEach(() => {
    setTelemetryEnabled.mockReset().mockResolvedValue({});
    telemetryPreview.mockReset().mockResolvedValue({ schema_version: 1 });
  });

  it('pre-selects off and shows the exact report', async () => {
    render(TelemetryStep, {
      props: {
        initialEnabled: false,
        locked: false,
        onNext: vi.fn(),
        onBack: vi.fn(),
        onSkip: vi.fn(),
      },
    });
    expect(
      (screen.getByLabelText('Send the daily diagnostic report') as HTMLInputElement).checked,
    ).toBe(false);
    expect(await screen.findByText(/"schema_version": 1/));
  });

  it('keeps telemetry off without calling the server when nothing changed', async () => {
    const onNext = vi.fn();
    render(TelemetryStep, {
      props: { initialEnabled: false, locked: false, onNext, onBack: vi.fn(), onSkip: vi.fn() },
    });
    await fireEvent.click(screen.getByRole('button', { name: 'Save and continue' }));
    await waitFor(() => expect(onNext).toHaveBeenCalled());
    expect(setTelemetryEnabled).not.toHaveBeenCalled();
  });

  it('turns telemetry on only when the administrator asks', async () => {
    const onNext = vi.fn();
    render(TelemetryStep, {
      props: { initialEnabled: false, locked: false, onNext, onBack: vi.fn(), onSkip: vi.fn() },
    });
    await fireEvent.click(screen.getByLabelText('Send the daily diagnostic report'));
    await fireEvent.click(screen.getByRole('button', { name: 'Save and continue' }));
    await waitFor(() => expect(setTelemetryEnabled).toHaveBeenCalledWith(true));
    expect(onNext).toHaveBeenCalled();
  });

  it('is read-only when NUX_TELEMETRY=off locks it', () => {
    render(TelemetryStep, {
      props: {
        initialEnabled: false,
        locked: true,
        onNext: vi.fn(),
        onBack: vi.fn(),
        onSkip: vi.fn(),
      },
    });
    expect(
      (screen.getByLabelText('Send the daily diagnostic report') as HTMLInputElement).disabled,
    ).toBe(true);
    expect(screen.getByText(/NUX_TELEMETRY=off/));
  });

  it('shows a message when the preview cannot load', async () => {
    telemetryPreview.mockRejectedValue(new Error('down'));
    render(TelemetryStep, {
      props: {
        initialEnabled: false,
        locked: false,
        onNext: vi.fn(),
        onBack: vi.fn(),
        onSkip: vi.fn(),
      },
    });
    expect(await screen.findByText(/could not be loaded/));
  });
});

describe('INS-4 step 4: first host and finish', () => {
  it('finishes from the host step and can go back', async () => {
    const onFinish = vi.fn();
    const onBack = vi.fn();
    render(HostStep, { props: { onFinish, onBack, busy: false } });
    expect(screen.getByRole('heading', { name: 'Add your first host' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Finish setup' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Back' }));
    expect(onFinish).toHaveBeenCalledOnce();
    expect(onBack).toHaveBeenCalledOnce();
  });

  it('disables finishing while the request is in flight', () => {
    render(HostStep, { props: { onFinish: vi.fn(), onBack: vi.fn(), busy: true } });
    expect((screen.getByRole('button', { name: 'Finishing…' }) as HTMLButtonElement).disabled).toBe(
      true,
    );
  });
});

describe('INS-4 step 5: done', () => {
  it('links to the Overview and reports a connected host', () => {
    render(DoneStep, { props: { hostsConnected: true } });
    expect(screen.getByRole('heading', { name: 'Setup is complete' }));
    expect(screen.getByText(/Your first host is connected and reporting/));
    expect(screen.getByRole('link', { name: 'Go to the Overview' }).getAttribute('href')).toBe('/');
  });
});
