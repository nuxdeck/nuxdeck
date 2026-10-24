// SPDX-License-Identifier: AGPL-3.0-only

import { api, ApiRequestError, type ApiError, type SetupRequest, type User } from './api/client';

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

  async login(email: string, password: string): Promise<void> {
    this.signIn((await api.login(email, password)).user);
  }

  async completeSetup(request: SetupRequest): Promise<void> {
    this.signIn((await api.completeSetup(request)).user);
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
