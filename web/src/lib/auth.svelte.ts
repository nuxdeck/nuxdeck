// SPDX-License-Identifier: AGPL-3.0-only

import { router } from './router.svelte';
import { SETUP_PATH } from './onboarding/onboarding';
import {
  api,
  ApiRequestError,
  type ApiError,
  type PendingLogin,
  type SetupRequest,
  type TotpEnrolment,
  type User,
} from './api/client';

export type AuthStatus = 'loading' | 'setup' | 'anonymous' | 'authenticated' | 'unreachable';

class AuthState {
  status = $state<AuthStatus>('loading');
  user = $state<User | null>(null);
  /** Why the server could not be reached or answered unexpectedly. */
  failure = $state<ApiError | null>(null);

  /** Works out who is signed in, or whether this server still needs first-run setup. */
  async init(): Promise<void> {
    this.status = 'loading';
    this.failure = null;
    try {
      this.signIn((await api.me()).user);
      return;
    } catch (e) {
      if (!(e instanceof ApiRequestError) || e.error.status !== 401) return this.unreachable(e);
    }
    try {
      this.status = (await api.setupStatus()).setup_required ? 'setup' : 'anonymous';
    } catch (e) {
      this.unreachable(e);
    }
  }

  /** Set between a correct password and the second sign-in step. */
  pending = $state<PendingLogin | null>(null);
  /** Shown once after a required enrolment; the sign-in completes when the user has saved them. */
  recoveryCodes = $state<string[] | null>(null);
  private held: User | null = null;

  async login(email: string, password: string): Promise<void> {
    const result = await api.login(email, password);
    if ('pending' in result) {
      this.pending = result.pending;
      return;
    }
    this.signIn(result.user);
  }

  async verifyTotp(code: string): Promise<void> {
    if (!this.pending) return;
    const session = await api.verifyTotp(this.pending.ticket, code);
    this.pending = null;
    if (session.recovery_codes?.length) {
      this.held = session.user;
      this.recoveryCodes = session.recovery_codes;
      return;
    }
    this.signIn(session.user);
  }

  /** Starts the enrolment a server-wide two-factor requirement asks for. */
  pendingEnrol(): Promise<TotpEnrolment> {
    if (!this.pending) throw new Error('no pending sign-in');
    return api.pendingEnrol(this.pending.ticket);
  }

  cancelPending(): void {
    this.pending = null;
  }

  finishRecovery(): void {
    this.recoveryCodes = null;
    if (this.held) this.signIn(this.held);
    this.held = null;
  }

  /** The wizard continues where step 1 stopped, so the administrator lands on step 2 (INS-3). */
  async completeSetup(request: SetupRequest): Promise<void> {
    const session = await api.completeSetup(request);
    router.navigate(SETUP_PATH);
    this.signIn(session.user);
  }

  async logout(): Promise<void> {
    try {
      await api.logout();
    } catch (e) {
      // The server may be down or the session already gone; this browser signs out either way.
      console.warn(
        'sign-out request failed',
        e instanceof ApiRequestError ? e.error.code : 'unknown',
      );
    }
    this.user = null;
    this.status = 'anonymous';
  }

  private signIn(user: User): void {
    this.user = user;
    this.status = 'authenticated';
  }

  private unreachable(e: unknown): void {
    this.failure = e instanceof ApiRequestError ? e.error : null;
    this.status = 'unreachable';
  }
}

export const auth = new AuthState();
