// @vitest-environment jsdom
import React from 'react';
import { act } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createRoot } from 'react-dom/client';
import { RolesSection } from './App';
import { api, type Host, type RoleRecord, type User } from './api';

const admin: User = { id: 1, email: 'admin@example.com', role: 'admin', disabled: false };
const hosts: Host[] = [
  { id: 10, name: 'App', domain: 'app.example.com', upstream_host: '127.0.0.1', upstream_port: 3000, tls_mode: 'disabled', certificate_id: null, enabled: true },
  { id: 11, name: 'Blog', domain: 'blog.example.com', upstream_host: '127.0.0.1', upstream_port: 3001, tls_mode: 'disabled', certificate_id: null, enabled: true },
];
const role: RoleRecord = { id: 4, slug: 'deploy', name: 'Deploy', description: '', system_managed: false, permissions: ['proxy_hosts.read'], scopes: [{ permission: 'proxy_hosts.read', proxy_host_ids: [10] }] };
const builtin: RoleRecord = { id: 1, slug: 'admin', name: 'Administrator', description: '', system_managed: true, permissions: ['proxy_hosts.read', 'proxy_hosts.write'], scopes: [] };

function render(roles = [role], width = 390) {
  Object.defineProperty(window, 'innerWidth', { configurable: true, value: width });
  const element = document.createElement('div');
  document.body.append(element);
  const root = createRoot(element);
  act(() => root.render(<RolesSection user={admin} roles={roles} hosts={hosts} onChanged={vi.fn()} />));
  return { element, root };
}

afterEach(() => { vi.restoreAllMocks(); document.body.innerHTML = ''; });

describe('role scope editor', () => {
  it('renders per-permission host controls and selected hosts', () => {
    const view = render();
    expect(view.element.querySelector('[data-testid="role-scope-editor-4"]')).toBeTruthy();
    expect(view.element.textContent).toContain('Proxy host read access');
    expect(view.element.textContent).toContain('app.example.com');
    expect((view.element.querySelector('[data-testid="scope-read-host-10"]') as HTMLInputElement).checked).toBe(true);
    expect((view.element.querySelector('[data-testid="scope-read-host-11"]') as HTMLInputElement).checked).toBe(false);
    view.root.unmount();
  });

  it('submits normalized read and write scope assignments and can clear them', async () => {
    const update = vi.spyOn(api, 'updateRole').mockResolvedValue(role);
    const view = render();
    const write = view.element.querySelector('[data-testid="scope-write-host-11"]') as HTMLInputElement;
    await act(async () => { write.click(); });
    await act(async () => { (view.element.querySelector('[data-testid="role-scope-save-4"]') as HTMLButtonElement).click(); });
    expect(update).toHaveBeenCalledWith(4, expect.objectContaining({ scopes: [
      { permission: 'proxy_hosts.read', proxy_host_ids: [10] },
      { permission: 'proxy_hosts.write', proxy_host_ids: [11] },
    ] }));
    await act(async () => { (view.element.querySelector('[data-testid="role-scope-clear-4"]') as HTMLButtonElement).click(); });
    expect((view.element.querySelector('[data-testid="scope-read-host-10"]') as HTMLInputElement).checked).toBe(false);
    expect((view.element.querySelector('[data-testid="scope-write-host-11"]') as HTMLInputElement).checked).toBe(false);
    view.root.unmount();
  });

  it('keeps built-in roles read-only and preserves unsaved selections after validation errors', async () => {
    const update = vi.spyOn(api, 'updateRole').mockRejectedValue(Object.assign(new Error('invalid scope'), { status: 422 }));
    const view = render([builtin, role]);
    const builtinInputs = view.element.querySelectorAll('[data-testid="role-scope-editor-1"] input') as NodeListOf<HTMLInputElement>;
    expect([...builtinInputs].every((input) => input.disabled)).toBe(true);
    const selectable = [...view.element.querySelectorAll('[data-testid="scope-read-host-11"]')].at(-1) as HTMLInputElement;
    await act(async () => { selectable.click(); });
    await act(async () => { (view.element.querySelector('[data-testid="role-scope-save-4"]') as HTMLButtonElement).click(); });
    expect(update).toHaveBeenCalled();
    expect(view.element.textContent).toContain('Please check the submitted role details.');
    expect((view.element.querySelectorAll('[data-testid="scope-read-host-11"]')[1] as HTMLInputElement).checked).toBe(true);
    expect(view.element.querySelector('[data-testid="role-scope-editor-4"]')?.className).toContain('grid');
    view.root.unmount();
  });
});
